//! Bluetooth LE scan. Sends the latest advertisement data of each device.
//!
//! The scan loop works on any [`Radio`]. `hardware` has the real adapter.

use anyhow::Result;
use btleplug::api::PeripheralProperties;
use futures::StreamExt;
use futures::stream::BoxStream;

use crate::model::Advert;

#[derive(Debug)]
pub enum BleEvent {
    /// The adapter is ready and the scan runs.
    Started(String),
    /// The adapter changed its power state. `true` means powered on.
    Power(bool),
    Advert(Advert),
    /// The scan stopped with an error.
    Failed(String),
}

/// One adapter event, as the scan loop needs it.
#[derive(Debug, Clone)]
pub(crate) enum Signal<Id> {
    /// The adapter changed its power state. `true` means powered on.
    Power(bool),
    /// The device with this ID sent or changed its advertisement data.
    Device(Id),
    /// An event that the scan does not use.
    Other,
}

/// A Bluetooth adapter.
pub(crate) trait Radio {
    type Id: Send;
    /// A name for the adapter.
    async fn info(&self) -> String;
    /// Start the scan and return the adapter events.
    async fn start(&self) -> Result<BoxStream<'static, Signal<Self::Id>>>;
    async fn stop(&self);
    /// The latest advertisement data of a device.
    async fn snapshot(&self, id: &Self::Id) -> Option<Advert>;
}

/// Open a radio with `open`, scan, and give each event to `emit`. The scan
/// stops when `emit` returns `false`. An error arrives as a `Failed` event.
pub(crate) async fn run<R: Radio>(
    open: impl Future<Output = Result<R>>,
    emit: impl Fn(BleEvent) -> bool + Send + Sync,
) {
    if let Err(error) = scan(open, &emit).await {
        emit(BleEvent::Failed(format!("{error:#}")));
    }
}

async fn scan<R: Radio>(
    open: impl Future<Output = Result<R>>,
    emit: &(impl Fn(BleEvent) -> bool + Send + Sync),
) -> Result<()> {
    let radio = open.await?;
    let info = radio.info().await;
    let mut events = radio.start().await?;
    let mut go_on = emit(BleEvent::Started(info));
    while go_on && let Some(signal) = events.next().await {
        go_on = match signal {
            Signal::Power(on) => emit(BleEvent::Power(on)),
            Signal::Device(id) => match radio.snapshot(&id).await {
                Some(advert) => emit(BleEvent::Advert(advert)),
                None => true,
            },
            Signal::Other => true,
        };
    }
    radio.stop().await;
    Ok(())
}

/// Make an [`Advert`] from the properties of a peripheral.
pub(crate) fn advert(id: String, props: PeripheralProperties) -> Advert {
    // macOS and iOS hide the address and report all zeros.
    let address = (props.address != Default::default()).then(|| props.address.to_string());
    Advert {
        id,
        address,
        name: [props.local_name, props.advertisement_name].into_iter().flatten().find(|n| !n.is_empty()),
        rssi: props.rssi,
        tx_power: props.tx_power_level,
        manufacturer_data: props.manufacturer_data.into_iter().collect(),
        service_data: props.service_data.into_iter().collect(),
        services: props.services,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use anyhow::bail;
    use btleplug::api::BDAddr;
    use uuid::Uuid;

    use super::*;

    #[derive(Default)]
    struct FakeRadio {
        signals: Vec<Signal<u32>>,
        cannot_start: bool,
        stopped: Arc<AtomicBool>,
    }

    impl Radio for FakeRadio {
        type Id = u32;

        async fn info(&self) -> String {
            "fake adapter".into()
        }

        async fn start(&self) -> Result<BoxStream<'static, Signal<u32>>> {
            if self.cannot_start {
                bail!("no Bluetooth permission");
            }
            Ok(futures::stream::iter(self.signals.clone()).boxed())
        }

        async fn stop(&self) {
            self.stopped.store(true, Ordering::SeqCst);
        }

        /// Device 0 has no data.
        async fn snapshot(&self, id: &u32) -> Option<Advert> {
            (*id != 0).then(|| Advert { id: id.to_string(), ..Advert::default() })
        }
    }

    /// Run a scan. `keep` decides which events let the scan go on. Returns
    /// the events and whether the scan stopped the radio.
    async fn record(radio: Result<FakeRadio>, keep: fn(&BleEvent) -> bool) -> (Vec<String>, bool) {
        let stopped = radio.as_ref().map(|radio| radio.stopped.clone()).unwrap_or_default();
        let seen = Mutex::new(Vec::new());
        run(async { radio }, |event| {
            let go_on = keep(&event);
            seen.lock().unwrap().push(match event {
                BleEvent::Started(info) => format!("started {info}"),
                BleEvent::Power(on) => format!("power {on}"),
                BleEvent::Advert(advert) => format!("advert {}", advert.id),
                BleEvent::Failed(error) => format!("failed {error}"),
            });
            go_on
        })
        .await;
        (seen.into_inner().unwrap(), stopped.load(Ordering::SeqCst))
    }

    fn radio(signals: Vec<Signal<u32>>) -> Result<FakeRadio> {
        Ok(FakeRadio { signals, ..FakeRadio::default() })
    }

    #[tokio::test]
    async fn scan_sends_each_event() {
        let signals = vec![
            Signal::Power(true),
            Signal::Device(7),
            Signal::Device(0),
            Signal::Other,
            Signal::Power(false),
        ];
        let (seen, stopped) = record(radio(signals), |_| true).await;
        assert_eq!(seen, ["started fake adapter", "power true", "advert 7", "power false"]);
        assert!(stopped);
    }

    #[tokio::test]
    async fn scan_stops_when_the_receiver_stops() {
        let signals = || vec![Signal::Power(true), Signal::Device(7), Signal::Device(8)];
        let (seen, stopped) = record(radio(signals()), |_| false).await;
        assert_eq!(seen, ["started fake adapter"]);
        assert!(stopped);

        let (seen, _) = record(radio(signals()), |event| !matches!(event, BleEvent::Power(_))).await;
        assert_eq!(seen, ["started fake adapter", "power true"]);

        let (seen, _) = record(radio(signals()), |event| !matches!(event, BleEvent::Advert(_))).await;
        assert_eq!(seen, ["started fake adapter", "power true", "advert 7"]);
    }

    #[tokio::test]
    async fn errors_arrive_as_failed_events() {
        let (seen, _) = record(Err(anyhow::anyhow!("no Bluetooth adapter found")), |_| true).await;
        assert_eq!(seen, ["failed no Bluetooth adapter found"]);

        let cannot_start = FakeRadio { cannot_start: true, ..FakeRadio::default() };
        let (seen, stopped) = record(Ok(cannot_start), |_| true).await;
        assert_eq!(seen, ["failed no Bluetooth permission"]);
        assert!(!stopped);
    }

    #[test]
    fn advert_from_properties() {
        let service = Uuid::from_u128(0xfd5a);
        let props = PeripheralProperties {
            address: BDAddr::from([0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22]),
            local_name: Some(String::new()),
            advertisement_name: Some("Tag".into()),
            rssi: Some(-60),
            tx_power_level: Some(-8),
            manufacturer_data: [(0x004c, vec![0x12, 0x19])].into(),
            service_data: [(service, vec![1])].into(),
            services: vec![service],
            ..PeripheralProperties::default()
        };
        let tag = advert("id-1".into(), props);
        assert_eq!(tag.id, "id-1");
        assert_eq!(tag.address.as_deref(), Some("AA:BB:CC:00:11:22"));
        // An empty local name does not hide the advertisement name.
        assert_eq!(tag.name.as_deref(), Some("Tag"));
        assert_eq!((tag.rssi, tag.tx_power), (Some(-60), Some(-8)));
        assert_eq!(tag.manufacturer_data[&0x004c], [0x12, 0x19]);
        assert_eq!(tag.service_data[&service], [1]);
        assert_eq!(tag.services, [service]);

        // macOS hides the address. The local name comes first.
        let hidden = advert(
            "id-2".into(),
            PeripheralProperties {
                local_name: Some("Local".into()),
                advertisement_name: Some("Tag".into()),
                ..PeripheralProperties::default()
            },
        );
        assert_eq!(hidden.address, None);
        assert_eq!(hidden.name.as_deref(), Some("Local"));
        assert_eq!(advert("id-3".into(), PeripheralProperties::default()).name, None);
    }
}

//! Bluetooth LE scan. Sends the latest advertisement data of each device.

use anyhow::{Context, Result, bail};
use btleplug::api::{Central, CentralEvent, CentralState, Manager as _, Peripheral as _, ScanFilter};
use btleplug::platform::{Adapter, Manager, PeripheralId};
use futures::StreamExt;

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

/// Scan and give each event to `emit`. The scan stops when `emit` returns
/// `false`. An error arrives as a `Failed` event.
pub async fn run(emit: impl Fn(BleEvent) -> bool + Send + Sync) {
    if let Err(error) = scan(&emit).await {
        emit(BleEvent::Failed(format!("{error:#}")));
    }
}

async fn scan(emit: &(impl Fn(BleEvent) -> bool + Send + Sync)) -> Result<()> {
    let manager = Manager::new().await.context("cannot start Bluetooth")?;
    let adapters = manager.adapters().await.context("cannot list Bluetooth adapters")?;
    let Some(central) = adapters.into_iter().next() else {
        bail!("no Bluetooth adapter found");
    };
    let info = central.adapter_info().await.unwrap_or_else(|_| "adapter".into());

    let mut events = central.events().await.context("cannot read Bluetooth events")?;
    central
        .start_scan(ScanFilter::default())
        .await
        .context("cannot start the scan (check the Bluetooth permission)")?;
    if !emit(BleEvent::Started(info)) {
        return Ok(());
    }

    while let Some(event) = events.next().await {
        let id = match event {
            CentralEvent::StateUpdate(state) => {
                if !emit(BleEvent::Power(state == CentralState::PoweredOn)) {
                    break;
                }
                continue;
            }
            CentralEvent::DeviceDiscovered(id)
            | CentralEvent::DeviceUpdated(id)
            | CentralEvent::ManufacturerDataAdvertisement { id, .. }
            | CentralEvent::ServiceDataAdvertisement { id, .. }
            | CentralEvent::ServicesAdvertisement { id, .. }
            | CentralEvent::RssiUpdate { id, .. } => id,
            _ => continue,
        };
        if let Some(advert) = snapshot(&central, &id).await
            && !emit(BleEvent::Advert(advert))
        {
            break;
        }
    }
    let _ = central.stop_scan().await;
    Ok(())
}

async fn snapshot(central: &Adapter, id: &PeripheralId) -> Option<Advert> {
    let peripheral = central.peripheral(id).await.ok()?;
    let props = peripheral.properties().await.ok()??;
    // macOS and iOS hide the address and report all zeros.
    let address = (props.address != Default::default()).then(|| props.address.to_string());
    Some(Advert {
        id: id.to_string(),
        address,
        name: props.local_name.or(props.advertisement_name).filter(|n| !n.is_empty()),
        rssi: props.rssi,
        tx_power: props.tx_power_level,
        manufacturer_data: props.manufacturer_data.into_iter().collect(),
        service_data: props.service_data.into_iter().collect(),
        services: props.services,
    })
}

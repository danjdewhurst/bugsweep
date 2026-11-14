//! The real Bluetooth adapter, network and terminal.
//!
//! This is the only code that needs a Bluetooth adapter, a network to sweep
//! or an interactive terminal, so the tests cannot run it and the coverage
//! check skips this file. Keep each function here short, and put all logic
//! in the other modules, where tests reach it through fakes.

use std::sync::mpsc::Receiver;

use anyhow::{Context, Result, bail};
use btleplug::api::{Central, CentralEvent, CentralState, Manager as _, Peripheral as _, ScanFilter};
use btleplug::platform::{Adapter, Manager, PeripheralId};
use futures::future::BoxFuture;
use futures::stream::BoxStream;
use futures::{FutureExt, StreamExt};

use crate::ble::{self, BleEvent, Radio, Signal};
use crate::cli::Hardware;
use crate::lan::{self, LanReport};
use crate::model::Advert;
use crate::session::Session;
use crate::tui::{self, AppEvent};

/// This machine.
pub struct Machine;

impl Hardware for Machine {
    fn ble(&self, emit: Box<dyn Fn(BleEvent) -> bool + Send + Sync>) -> BoxFuture<'static, ()> {
        ble::run(Bluetooth::open(), emit).boxed()
    }

    fn lan(&self) -> BoxFuture<'static, Result<LanReport>> {
        lan::sweep_with(&lan::System).boxed()
    }

    fn terminal(&self, session: Session, events: Receiver<AppEvent>, start_lan: &dyn Fn()) -> Result<()> {
        tui::run(session, events, start_lan)
    }
}

/// The first Bluetooth adapter of this machine.
struct Bluetooth {
    // The adapter needs its manager.
    _manager: Manager,
    adapter: Adapter,
}

impl Bluetooth {
    async fn open() -> Result<Self> {
        let manager = Manager::new().await.context("cannot start Bluetooth")?;
        let adapters = manager.adapters().await.context("cannot list Bluetooth adapters")?;
        let Some(adapter) = adapters.into_iter().next() else {
            bail!("no Bluetooth adapter found");
        };
        Ok(Bluetooth { _manager: manager, adapter })
    }
}

fn signal(event: CentralEvent) -> Signal<PeripheralId> {
    match event {
        CentralEvent::StateUpdate(state) => Signal::Power(state == CentralState::PoweredOn),
        CentralEvent::DeviceDiscovered(id)
        | CentralEvent::DeviceUpdated(id)
        | CentralEvent::ManufacturerDataAdvertisement { id, .. }
        | CentralEvent::ServiceDataAdvertisement { id, .. }
        | CentralEvent::ServicesAdvertisement { id, .. }
        | CentralEvent::RssiUpdate { id, .. } => Signal::Device(id),
        _ => Signal::Other,
    }
}

impl Radio for Bluetooth {
    type Id = PeripheralId;

    async fn info(&self) -> String {
        self.adapter.adapter_info().await.unwrap_or_else(|_| "adapter".into())
    }

    async fn start(&self) -> Result<BoxStream<'static, Signal<PeripheralId>>> {
        let events = self.adapter.events().await.context("cannot read Bluetooth events")?;
        self.adapter
            .start_scan(ScanFilter::default())
            .await
            .context("cannot start the scan (check the Bluetooth permission)")?;
        Ok(events.map(signal).boxed())
    }

    async fn stop(&self) {
        let _ = self.adapter.stop_scan().await;
    }

    async fn snapshot(&self, id: &PeripheralId) -> Option<Advert> {
        let peripheral = self.adapter.peripheral(id).await.ok()?;
        let props = peripheral.properties().await.ok()??;
        Some(ble::advert(id.to_string(), props))
    }
}

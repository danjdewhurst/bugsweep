//! Desktop window. It shows the same views as the terminal interface.
//!
//! A separate thread runs [`pump`], which gives each Bluetooth and sweep
//! event to the shared [`Live`] state. So the session and the log stay
//! current also while the system does not draw the window, for example when
//! the window is hidden.

use std::collections::VecDeque;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eframe::egui::{
    self, Align, Button, CentralPanel, Color32, Context, Grid, Label, Layout, ProgressBar, RichText,
    ScrollArea, Sense, Shape, SidePanel, Stroke, TopBottomPanel, Ui, Visuals, pos2, vec2,
};
use egui_extras::{Column, TableBuilder, TableRow};

use crate::ble::BleEvent;
use crate::lan::{LanReport, Verdict};
use crate::session::{Device, Session};
use crate::signatures::Level;
use crate::store::Follower;
use crate::tui::{
    AppEvent, FINDER_SAMPLES, FinderReading, STALE_AFTER, TICK, detail_fields, finding_text, follow_warning,
    format_age, format_distance, lan_evidence, level_tag, neighbour_detail, signal_percent,
};

const GREEN: Color32 = Color32::from_rgb(40, 170, 90);
const BLUE: Color32 = Color32::from_rgb(60, 140, 230);
const CYAN: Color32 = Color32::from_rgb(0, 160, 200);
/// Time between two redraws outside the finder. The ages in the list
/// change once a second.
const IDLE_REPAINT: Duration = Duration::from_secs(1);
/// Height of one row in the device list.
const ROW_HEIGHT: f32 = 22.0;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum View {
    Devices,
    Network,
    Followers,
}

enum LanState {
    Idle,
    Running(Instant),
    Done(LanReport),
    Failed(String),
}

/// The state that the events change. The window and the event thread
/// share it.
pub struct Live {
    session: Session,
    ble_status: String,
    ble_ok: bool,
    lan: LanState,
}

impl Live {
    pub fn new(session: Session) -> Self {
        Live { session, ble_status: "starting".into(), ble_ok: false, lan: LanState::Idle }
    }

    fn on_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::Ble(BleEvent::Started(adapter)) => {
                self.ble_status = format!("scanning ({adapter})");
                self.ble_ok = true;
            }
            AppEvent::Ble(BleEvent::Power(on)) => {
                self.ble_ok = on;
                self.ble_status = if on { "scanning".into() } else { "Bluetooth is off".into() };
            }
            AppEvent::Ble(BleEvent::Advert(advert)) => self.session.ingest(advert),
            AppEvent::Ble(BleEvent::Failed(error)) => {
                self.ble_ok = false;
                self.ble_status = format!("failed: {error}");
            }
            AppEvent::Lan(Ok(report)) => self.lan = LanState::Done(report),
            AppEvent::Lan(Err(error)) => self.lan = LanState::Failed(error),
        }
    }
}

/// Give each event to `live`, until all senders are gone.
pub fn pump(events: Receiver<AppEvent>, live: &Mutex<Live>) {
    for event in events {
        lock(live).on_event(event);
    }
}

/// Show in the header that the events stopped, for example because the
/// event thread panicked.
pub fn fail(live: &Mutex<Live>, reason: &str) {
    lock(live).on_event(AppEvent::Ble(BleEvent::Failed(reason.into())));
}

/// A panic while the lock was held does not make the state unusable, so
/// use it also when the lock is poisoned.
fn lock(live: &Mutex<Live>) -> MutexGuard<'_, Live> {
    live.lock().unwrap_or_else(PoisonError::into_inner)
}

pub struct Gui<'a> {
    live: Arc<Mutex<Live>>,
    start_lan: &'a dyn Fn(),
    view: View,
    /// Show the devices without a finding too.
    show_all: bool,
    selected: Option<String>,
    /// Device ID that the finder follows, and its signal history.
    finder: Option<String>,
    finder_history: VecDeque<u16>,
    last_sample: Instant,
    /// Show the hosts without camera evidence too.
    lan_show_all: bool,
    followers: Vec<Follower>,
}

impl<'a> Gui<'a> {
    /// `start_lan` starts one network sweep, whose result must reach `live`
    /// as `AppEvent::Lan`.
    pub fn new(live: Arc<Mutex<Live>>, start_lan: &'a dyn Fn()) -> Self {
        Gui {
            live,
            start_lan,
            view: View::Devices,
            show_all: true,
            selected: None,
            finder: None,
            finder_history: VecDeque::new(),
            last_sample: Instant::now(),
            lan_show_all: false,
            followers: Vec::new(),
        }
    }

    /// Draw one frame.
    pub fn show(&mut self, ctx: &Context) {
        let shared = Arc::clone(&self.live);
        let mut live = lock(&shared);
        if self.last_sample.elapsed() >= TICK {
            self.last_sample = Instant::now();
            self.sample_finder(&live.session);
        }
        // The finder follows the signal closely. The other views change at
        // most once a second.
        ctx.request_repaint_after(if self.finder.is_some() { TICK } else { IDLE_REPAINT });

        TopBottomPanel::top("header").show(ctx, |ui| self.header(ui, &live));
        TopBottomPanel::bottom("footer").show(ctx, |ui| {
            ui.weak("Radio check only. A device that sends no radio signal stays hidden.");
        });
        CentralPanel::default().show(ctx, |ui| match (&self.finder, self.view) {
            (Some(_), _) => self.finder_view(ui, &live.session),
            (None, View::Devices) => self.devices_view(ui, &mut live.session),
            (None, View::Network) => self.network_view(ui, &mut live.lan),
            (None, View::Followers) => self.followers_view(ui, &live.session),
        });
    }

    fn sample_finder(&mut self, session: &Session) {
        let Some(device) = self.finder.as_deref().and_then(|id| session.get(id)) else {
            return;
        };
        while self.finder_history.len() >= FINDER_SAMPLES {
            self.finder_history.pop_front();
        }
        self.finder_history.push_back(device.rssi_avg.map(signal_percent).unwrap_or(0));
    }

    fn open_finder(&mut self, id: Option<String>) {
        self.finder = id;
        self.finder_history.clear();
    }

    // ------------------------------------------------------------ panels

    fn header(&mut self, ui: &mut Ui, live: &Live) {
        let session = &live.session;
        let flagged = session.flagged_count();
        ui.horizontal_wrapped(|ui| {
            ui.heading("bugsweep");
            ui.separator();
            ui.label("Bluetooth:");
            let colour = if live.ble_ok { GREEN } else { ui.visuals().error_fg_color };
            ui.colored_label(colour, &live.ble_status);
            ui.separator();
            ui.label(format!("Place: {}", session.place));
            ui.separator();
            ui.label(format!("Devices: {}", session.len()));
            ui.separator();
            let flagged_text = RichText::new(format!("Flagged: {flagged}"));
            ui.label(if flagged > 0 {
                flagged_text.strong().color(ui.visuals().warn_fg_color)
            } else {
                flagged_text
            });
            if let Some(error) = &session.store_error {
                ui.separator();
                ui.colored_label(ui.visuals().error_fg_color, format!("Log error: {error}"));
            }
        });
        ui.horizontal(|ui| {
            let tabs = [
                (View::Devices, "Bluetooth"),
                (View::Network, "Network cameras"),
                (View::Followers, "Followers"),
            ];
            for (view, title) in tabs {
                // A click on a tab also leaves the finder, which shows under the Bluetooth tab.
                if ui.selectable_label(self.view == view, title).clicked() {
                    self.view = view;
                    self.open_finder(None);
                    if view == View::Followers {
                        self.followers = session.followers();
                    }
                }
            }
        });
        ui.add_space(2.0);
    }

    fn devices_view(&mut self, ui: &mut Ui, session: &mut Session) {
        let devices = session.sorted(self.show_all);
        // Keep the selection on the same device when the order changes.
        let selected = self
            .selected
            .as_ref()
            .and_then(|id| devices.iter().find(|d| &d.advert.id == id))
            .or(devices.first())
            .map(|d| d.advert.id.clone());

        let mut show_all = self.show_all;
        let mut clicked = None;
        let mut action = None;
        // A fixed width range, so that long data wraps and does not push the list away.
        let details =
            SidePanel::right("details").resizable(true).default_width(380.0).width_range(260.0..=560.0);
        details.show_inside(ui, |ui| {
            ui.heading("Details");
            ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                match selected.as_deref().and_then(|id| session.get(id)) {
                    Some(device) => action = details_pane(ui, session, device),
                    None if self.show_all => _ = ui.label("No devices yet."),
                    None => _ = ui.label("No flagged devices."),
                }
            });
        });
        CentralPanel::default().show_inside(ui, |ui| {
            ui.checkbox(&mut show_all, "Show devices without a finding");
            ui.add_space(4.0);
            // The table scrolls only up and down, so a narrow window scrolls it sideways.
            ScrollArea::horizontal().show(ui, |ui| {
                clicked = device_table(ui, session, &devices, selected.as_deref());
            });
        });

        self.show_all = show_all;
        // The buttons act on the device that the details pane showed.
        match (action, &selected) {
            (Some(DeviceAction::Find), Some(_)) => self.open_finder(selected.clone()),
            (Some(DeviceAction::ToggleKnown), Some(id)) => _ = session.toggle_known(id),
            _ => {}
        }
        self.selected = clicked.or(selected);
    }

    fn finder_view(&mut self, ui: &mut Ui, session: &Session) {
        if ui.button("Back to the list").clicked() {
            self.open_finder(None);
            return;
        }
        ui.add_space(8.0);
        let Some(device) = self.finder.as_deref().and_then(|id| session.get(id)) else {
            ui.label("The device is gone.");
            return;
        };
        ui.heading(device.title().unwrap_or_else(|| "(no name)".into()));
        if let Some(sig) = session.top_signature(device) {
            ui.label(&sig.name);
        }
        ui.add_space(8.0);

        let reading = FinderReading::of(device);
        let colour = strength_colour(ui.visuals(), &reading);
        let bar = ProgressBar::new(reading.percent as f32 / 100.0).desired_height(36.0).fill(colour);
        ui.add(bar.text(reading.label));
        ui.add_space(8.0);
        self.history(ui, colour);
        ui.add_space(8.0);
        ui.label("Move the laptop slowly. The bar grows when you get nearer to the device.");
        ui.weak("The distance is a rough estimate. Walls and bodies weaken the signal.");
    }

    /// The signal history of the finder, as a line from left (old) to right (new).
    fn history(&self, ui: &mut Ui, colour: Color32) {
        let (response, painter) = ui.allocate_painter(vec2(ui.available_width(), 160.0), Sense::hover());
        let rect = response.rect;
        painter.rect_stroke(
            rect,
            4.0,
            ui.visuals().widgets.noninteractive.bg_stroke,
            egui::StrokeKind::Inside,
        );
        let step = rect.width() / (FINDER_SAMPLES - 1) as f32;
        let start = FINDER_SAMPLES.saturating_sub(self.finder_history.len());
        let points = self
            .finder_history
            .iter()
            .enumerate()
            .map(|(i, &value)| {
                pos2(
                    rect.left() + (start + i) as f32 * step,
                    rect.bottom() - rect.height() * value as f32 / 100.0,
                )
            })
            .collect();
        painter.add(Shape::line(points, Stroke::new(2.0_f32, colour)));
    }

    fn network_view(&mut self, ui: &mut Ui, lan: &mut LanState) {
        ui.label("The sweep looks for IP cameras and video recorders on the local network.");
        ui.label("It sends connection attempts to each address. Use it only where you are allowed to.");
        ui.add_space(8.0);
        let mut start = false;
        match &*lan {
            LanState::Idle => start = ui.button("Start the sweep").clicked(),
            LanState::Running(since) => {
                ui.add_enabled(false, Button::new("Start the sweep"));
                ui.colored_label(
                    ui.visuals().warn_fg_color,
                    format!("The sweep runs… {} s", since.elapsed().as_secs()),
                );
            }
            LanState::Failed(error) => {
                ui.colored_label(ui.visuals().error_fg_color, format!("The sweep failed: {error}"));
                start = ui.button("Try again").clicked();
            }
            LanState::Done(report) => {
                ui.horizontal(|ui| {
                    start = ui.button("Sweep again").clicked();
                    ui.checkbox(&mut self.lan_show_all, "Show hosts without camera evidence");
                });
                ui.add_space(8.0);
                lan_report(ui, report, self.lan_show_all);
            }
        }
        if start {
            *lan = LanState::Running(Instant::now());
            (self.start_lan)();
        }
    }

    fn followers_view(&mut self, ui: &mut Ui, session: &Session) {
        ui.horizontal(|ui| {
            ui.heading("Devices seen at two or more places");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("Refresh").clicked() {
                    self.followers = session.followers();
                }
            });
        });
        ui.add_space(8.0);
        if !session.has_log() {
            ui.label("The log is off, so there is no history.");
            return;
        }
        if self.followers.is_empty() {
            ui.label("No device was seen at two or more places.");
            ui.weak("Run bugsweep at different places. Mark your own devices in the Bluetooth view.");
            ui.weak(
                "Many devices change their address often and send no name, so this check can miss a tracker.",
            );
            return;
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        let ago = |then: i64| format_age(Duration::from_secs((now - then).max(0) as u64));
        ScrollArea::both().show(ui, |ui| {
            Grid::new("followers").striped(true).num_columns(7).spacing([12.0, 6.0]).show(ui, |ui| {
                for title in ["Device", "Signature", "Match", "Places", "First seen", "Last seen", "Key"] {
                    ui.strong(title);
                }
                ui.end_row();
                for f in &self.followers {
                    ui.label(f.title.as_deref().unwrap_or("(no name)"));
                    ui.label(f.signature.as_deref().unwrap_or(""));
                    ui.label(format!("same {}", f.basis.label()));
                    ui.label(f.places.join(", "));
                    ui.label(ago(f.first_seen));
                    ui.label(ago(f.last_seen));
                    ui.monospace(&f.key);
                    ui.end_row();
                }
            });
        });
    }
}

enum DeviceAction {
    Find,
    ToggleKnown,
}

/// Draw the device list. Only the visible rows are laid out, so a long
/// list in a busy place stays fast. Returns the device that the user
/// clicked.
fn device_table(
    ui: &mut Ui,
    session: &Session,
    devices: &[&Device],
    selected: Option<&str>,
) -> Option<String> {
    // Labels that take no clicks, so that a click anywhere in a row selects it.
    ui.style_mut().interaction.selectable_labels = false;
    let mut clicked = None;
    TableBuilder::new(ui)
        .striped(true)
        .sense(Sense::click())
        .cell_layout(Layout::left_to_right(Align::Center))
        .column(Column::exact(44.0))
        .column(Column::exact(72.0))
        .column(Column::initial(220.0).at_least(100.0).clip(true).resizable(true))
        .column(Column::remainder().at_least(120.0).clip(true))
        .column(Column::exact(120.0))
        .column(Column::exact(64.0))
        .column(Column::exact(40.0))
        .header(ROW_HEIGHT, |mut header| {
            for title in ["Level", "Type", "Device", "Finding", "Signal", "Distance", "Seen"] {
                header.col(|ui| _ = ui.strong(title));
            }
        })
        .body(|body| {
            body.rows(ROW_HEIGHT, devices.len(), |mut row| {
                let device = devices[row.index()];
                row.set_selected(selected == Some(device.advert.id.as_str()));
                device_row(&mut row, session, device);
                if row.response().clicked() {
                    clicked = Some(device.advert.id.clone());
                }
            });
        });
    clicked
}

fn device_row(row: &mut TableRow, session: &Session, device: &Device) {
    let level = session.level(device);
    let signature = session.top_signature(device);
    let dim = device.known || device.age() > STALE_AFTER;
    let text = |text: String| {
        let text = RichText::new(text);
        if dim { text.weak() } else { text }
    };

    let tag = level.map(level_tag).unwrap_or("");
    row.col(|ui| {
        ui.label(match level {
            Some(level) if !dim => RichText::new(tag).strong().color(level_colour(ui.visuals(), level)),
            _ => text(tag.into()),
        });
    });
    row.col(|ui| _ = ui.label(text(signature.map(|sig| sig.category.label()).unwrap_or("").into())));
    row.col(|ui| _ = ui.label(text(device.title().unwrap_or_else(|| "(no name)".into()))));
    row.col(|ui| _ = ui.label(text(finding_text(session, device))));
    row.col(|ui| {
        if let Some(rssi) = device.rssi_avg {
            let bar = ProgressBar::new(signal_percent(rssi) as f32 / 100.0).desired_width(110.0);
            ui.add(bar.text(format!("{rssi:.0} dBm")));
        }
    });
    row.col(|ui| _ = ui.label(text(device.distance_m().map(format_distance).unwrap_or_default())));
    row.col(|ui| _ = ui.label(text(format_age(device.age()))));
}

fn details_pane(ui: &mut Ui, session: &Session, device: &Device) -> Option<DeviceAction> {
    let mut action = None;
    ui.horizontal(|ui| {
        if ui.button("Find this device").clicked() {
            action = Some(DeviceAction::Find);
        }
        let mark = if device.known { "Not my device" } else { "Mark as my device" };
        if ui.button(mark).clicked() {
            action = Some(DeviceAction::ToggleKnown);
        }
    });
    ui.add_space(6.0);

    for &index in &device.hits {
        let sig = session.db().get(index);
        ui.horizontal_wrapped(|ui| {
            let colour = level_colour(ui.visuals(), sig.severity);
            ui.label(RichText::new(level_tag(sig.severity)).strong().color(colour));
            ui.strong(&sig.name);
        });
        ui.weak(format!("Confidence {}; {}", sig.confidence.label(), sig.evidence.describe()));
        if let Some(notes) = &sig.notes {
            ui.label(notes);
        }
        ui.weak(format!("Source: {}", sig.source));
        ui.add_space(6.0);
    }
    if let Some(follow) = device.follow() {
        let warning = format!("{} Mark it as your device if it is yours.", follow_warning(follow));
        ui.colored_label(ui.visuals().warn_fg_color, warning);
        ui.add_space(6.0);
    }
    if device.hits.is_empty() && device.follow().is_none() {
        ui.weak("No finding for this device.");
        ui.add_space(6.0);
    }

    // The value column takes the rest of the panel, and long hex data wraps.
    let value_width = (ui.available_width() - 100.0).max(120.0);
    Grid::new("fields").num_columns(2).spacing([12.0, 4.0]).max_col_width(value_width).show(ui, |ui| {
        for (label, value) in detail_fields(device) {
            ui.weak(label);
            ui.add(Label::new(value).wrap());
            ui.end_row();
        }
    });
    action
}

fn level_colour(visuals: &Visuals, level: Level) -> Color32 {
    match level {
        Level::High => visuals.error_fg_color,
        Level::Medium => visuals.warn_fg_color,
        Level::Low => CYAN,
        Level::Info => visuals.text_color(),
    }
}

/// Colour of the finder bar: red when near, yellow, then blue when far,
/// and grey when the device is silent.
fn strength_colour(visuals: &Visuals, reading: &FinderReading) -> Color32 {
    match reading.percent {
        _ if reading.stale => visuals.weak_text_color(),
        70.. => visuals.error_fg_color,
        40.. => visuals.warn_fg_color,
        _ => BLUE,
    }
}

fn lan_report(ui: &mut Ui, report: &LanReport, show_all: bool) {
    ui.label(format!(
        "{} addresses checked in {:.1} s on {}.",
        report.addresses_probed,
        report.seconds,
        report.networks.join(", ")
    ));
    let others = report.others.len();
    if report.hosts.is_empty() {
        ui.colored_label(GREEN, format!("No camera evidence found. {others} other host(s) answered."));
    } else {
        ui.colored_label(
            ui.visuals().warn_fg_color,
            format!("{} host(s) with camera evidence. {others} other host(s) answered.", report.hosts.len()),
        );
    }
    ui.add_space(8.0);
    ScrollArea::both().show(ui, |ui| {
        Grid::new("hosts").striped(true).num_columns(4).spacing([12.0, 6.0]).show(ui, |ui| {
            for title in ["Camera", "IP address", "MAC address", "Evidence or vendor"] {
                ui.strong(title);
            }
            ui.end_row();
            for host in &report.hosts {
                let (verdict, colour) = match host.verdict {
                    Verdict::Likely => ("LIKELY", ui.visuals().error_fg_color),
                    Verdict::Possible => ("maybe", ui.visuals().warn_fg_color),
                };
                ui.label(RichText::new(verdict).strong().color(colour));
                ui.label(host.ip.to_string());
                ui.monospace(host.mac.clone().unwrap_or_default());
                ui.label(lan_evidence(host));
                ui.end_row();
            }
            for other in report.others.iter().filter(|_| show_all) {
                ui.label("");
                ui.label(other.ip.to_string());
                ui.monospace(&other.mac);
                ui.label(neighbour_detail(other));
                ui.end_row();
            }
        });
    });
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::net::Ipv4Addr;
    use std::sync::mpsc;

    use egui_kittest::Harness;
    use egui_kittest::kittest::{NodeT, Queryable};

    use super::*;
    use crate::lan::{LanHost, Neighbour, OpenPort};
    use crate::model::{Advert, parse_uuid};
    use crate::signatures::SignatureDb;
    use crate::store::Store;

    /// A room with glasses (high), a Tile (medium), a phone that the log has
    /// at home, and a lamp without a finding.
    fn session() -> Session {
        let db = Arc::new(SignatureDb::embedded().unwrap());
        let store = Store::in_memory().unwrap();
        store.record("id:phone", "home", Some(-50), Some("My phone"), None).unwrap();
        let mut session = Session::new(db, Some(store), "office".into());

        let mut tile = Advert { id: "tile".into(), rssi: Some(-48), ..Default::default() };
        tile.services.push(parse_uuid("feed").unwrap());
        session.ingest(tile);
        let mut glasses = Advert { id: "glasses".into(), rssi: Some(-70), ..Default::default() };
        glasses.manufacturer_data.insert(0x01AB, vec![1, 2, 3]);
        session.ingest(glasses);
        session.ingest(Advert {
            id: "phone".into(),
            name: Some("My phone".into()),
            rssi: Some(-40),
            ..Default::default()
        });
        session.ingest(Advert {
            id: "lamp".into(),
            name: Some("Desk lamp".into()),
            rssi: Some(-60),
            ..Default::default()
        });
        session
    }

    fn noop() {}

    /// A window of 1400 × 900 points.
    fn harness<'a>(session: Session, start_lan: &'a dyn Fn()) -> Harness<'a, Gui<'a>> {
        let gui = Gui::new(Arc::new(Mutex::new(Live::new(session))), start_lan);
        // A frame time below the tick, so that the harness does not take the
        // repaint request of each tick as an endless animation.
        let mut harness = Harness::builder()
            .with_size(vec2(1400.0, 900.0))
            .with_step_dt(0.05)
            .build_state(|ctx, gui: &mut Gui| gui.show(ctx), gui);
        harness.run();
        harness
    }

    /// Give one event to the shared state, as the event thread does, and draw.
    fn deliver(harness: &mut Harness<Gui>, event: AppEvent) {
        lock(&harness.state().live).on_event(event);
        harness.run();
    }

    fn has(harness: &Harness<Gui>, text: &str) -> bool {
        harness.query_all_by_label_contains(text).next().is_some()
    }

    fn click(harness: &mut Harness<Gui>, label: &str) {
        harness.get_by_label(label).click();
        harness.run();
    }

    #[test]
    fn device_view_lists_findings_and_details() {
        let mut harness = harness(session(), &noop);
        assert!(has(&harness, "Devices: 4"));
        assert!(has(&harness, "Flagged: 3"));
        assert!(has(&harness, "Place: office"));
        assert!(has(&harness, "seen at 1 other place(s), same ID"));
        // The first device is selected, so the details show its evidence.
        assert_eq!(harness.state().selected.as_deref(), Some("glasses"));
        assert!(has(&harness, "from a paper or a published capture"));
        assert!(has(&harness, "Source: "));
        assert!(has(&harness, "0x01ab"));

        // A click anywhere in a row selects the device.
        click(&mut harness, "Desk lamp");
        assert_eq!(harness.state().selected.as_deref(), Some("lamp"));
        assert!(has(&harness, "No finding for this device."));

        // Only the flagged devices. The lamp is gone, so the selection
        // moves to the first flagged device.
        click(&mut harness, "Show devices without a finding");
        assert!(!harness.state().show_all);
        assert!(!has(&harness, "Desk lamp"));
        assert_eq!(harness.state().selected.as_deref(), Some("glasses"));

        // The phone has no signature, so its details show only the warning.
        click(&mut harness, "My phone");
        assert_eq!(harness.state().selected.as_deref(), Some("phone"));
        assert!(has(&harness, "This device was seen at 1 other place(s), same ID."));
    }

    #[test]
    fn mark_as_my_device_removes_the_flag() {
        let mut harness = harness(session(), &noop);
        click(&mut harness, "Mark as my device");
        assert!(has(&harness, "Flagged: 2"));
        assert!(has(&harness, "known · Meta smart glasses"));
        // The selection stays on the same device after the order changes.
        assert_eq!(harness.state().selected.as_deref(), Some("glasses"));
        click(&mut harness, "Not my device");
        assert!(has(&harness, "Flagged: 3"));
    }

    #[test]
    fn empty_lists_explain_themselves() {
        let db = Arc::new(SignatureDb::embedded().unwrap());
        let mut harness = harness(Session::new(db, None, "car".into()), &noop);
        assert!(has(&harness, "No devices yet."));
        click(&mut harness, "Show devices without a finding");
        assert!(has(&harness, "No flagged devices."));
        click(&mut harness, "Network cameras");
        click(&mut harness, "Start the sweep");
        assert!(has(&harness, "The sweep runs"));
    }

    #[test]
    fn finder_follows_the_signal() {
        let mut harness = harness(session(), &noop);
        click(&mut harness, "My phone");
        click(&mut harness, "Find this device");
        assert_eq!(harness.state().finder.as_deref(), Some("phone"));
        assert!(has(&harness, "Move the laptop slowly."));

        // Each tick adds one sample, and the history keeps the latest ones.
        harness.state_mut().finder_history = (1..=FINDER_SAMPLES as u16).collect();
        harness.state_mut().last_sample = Instant::now() - TICK;
        harness.run();
        let history = &harness.state().finder_history;
        assert_eq!(history.len(), FINDER_SAMPLES);
        assert_eq!(history.front(), Some(&2));
        // -40 dBm is 92 percent.
        assert_eq!(history.back(), Some(&92));

        click(&mut harness, "Back to the list");
        assert!(harness.state().finder.is_none());
        // Without the finder, a tick adds no sample.
        harness.state_mut().last_sample = Instant::now() - TICK;
        harness.run();
        assert!(harness.state().finder_history.is_empty());
    }

    #[test]
    fn a_tab_click_leaves_the_finder() {
        let mut harness = harness(session(), &noop);
        click(&mut harness, "Find this device");
        assert_eq!(harness.state().finder.as_deref(), Some("glasses"));
        // The Bluetooth tab is already selected, and a click still leaves the finder.
        click(&mut harness, "Bluetooth");
        assert!(harness.state().finder.is_none());
        assert!(has(&harness, "Show devices without a finding"));
    }

    #[test]
    fn finder_shows_each_strength() {
        let mut session = session();
        // Silent for 10 minutes: stale in the finder.
        let old =
            Advert { id: "old".into(), name: Some("Old tag".into()), rssi: Some(-90), ..Default::default() };
        session.ingest_at(old, Instant::now() - Duration::from_secs(600));
        session.ingest(Advert { id: "far".into(), rssi: Some(-85), ..Default::default() });
        let mut harness = harness(session, &noop);
        for id in ["phone", "glasses", "far", "old"] {
            harness.state_mut().finder = Some(id.into());
            harness.run();
        }
        assert!(has(&harness, "no signal for 10m"));

        // A device that is gone.
        harness.state_mut().finder = Some("gone".into());
        harness.run();
        assert!(has(&harness, "The device is gone."));
    }

    #[test]
    fn strength_colour_follows_the_bands() {
        let visuals = Visuals::dark();
        let colour = |percent, stale| {
            strength_colour(&visuals, &FinderReading { stale, percent, label: String::new() })
        };
        assert_eq!(colour(70, false), visuals.error_fg_color);
        assert_eq!(colour(69, false), visuals.warn_fg_color);
        assert_eq!(colour(40, false), visuals.warn_fg_color);
        assert_eq!(colour(39, false), BLUE);
        assert_eq!(colour(90, true), visuals.weak_text_color());
    }

    #[test]
    fn history_line_survives_a_long_history() {
        let mut harness = harness(session(), &noop);
        harness.state_mut().finder = Some("phone".into());
        // More samples than the history holds must not break the drawing.
        harness.state_mut().finder_history = vec![50; FINDER_SAMPLES + 2].into();
        harness.run();
        assert!(has(&harness, "Move the laptop slowly."));
    }

    #[test]
    fn all_levels_and_rows_without_a_signal_show() {
        let db = SignatureDb::parse(
            r#"
[[signature]]
id = "low-tag"
name = "Low tag"
category = "tracker"
severity = "low"
confidence = "low"
evidence = "guess"
source = "test"
notes = "A note about the low tag."
[[signature.match]]
name_regex = "^LowTag"

[[signature]]
id = "info-tag"
name = "Info tag"
category = "tracker"
severity = "info"
confidence = "low"
evidence = "guess"
source = "test"
[[signature.match]]
name_regex = "^InfoTag"
"#,
        )
        .unwrap();
        let mut session = Session::new(Arc::new(db), None, "lab".into());
        session.ingest(Advert {
            id: "low".into(),
            name: Some("LowTag".into()),
            rssi: Some(-50),
            ..Default::default()
        });
        session.ingest(Advert { id: "info".into(), name: Some("InfoTag".into()), ..Default::default() });
        let mut harness = harness(session, &noop);
        assert!(has(&harness, "Low tag"));
        assert!(has(&harness, "Info tag"));
        assert!(has(&harness, "A note about the low tag."));
        // The level tags: in the list for both, and in the details for the low tag.
        assert!(harness.query_all_by_label("low").count() >= 2);
        assert!(harness.query_all_by_label("info").next().is_some());
        // The info tag has no signal, so it has no distance either.
        let distances = harness
            .query_all_by_label_contains(" m")
            .filter(|node| node.accesskit_node().value().is_some_and(|text| text.ends_with(" m")));
        assert_eq!(distances.count(), 1);

        // The details of a signature without notes.
        click(&mut harness, "InfoTag");
        assert_eq!(harness.state().selected.as_deref(), Some("info"));
        assert!(!has(&harness, "A note about the low tag."));
        assert!(has(&harness, "Source: test"));
    }

    #[test]
    fn bluetooth_events_change_the_header() {
        let mut harness = harness(session(), &noop);
        assert!(has(&harness, "starting"));
        let mut check = |event: BleEvent, expect: &str, ok: bool| {
            deliver(&mut harness, AppEvent::Ble(event));
            assert!(has(&harness, expect), "{expect}");
            assert_eq!(lock(&harness.state().live).ble_ok, ok, "{expect}");
        };
        check(BleEvent::Started("hci0".into()), "scanning (hci0)", true);
        check(BleEvent::Power(false), "Bluetooth is off", false);
        check(BleEvent::Power(true), "scanning", true);
        let advert = Advert { id: "new".into(), name: Some("New one".into()), ..Default::default() };
        check(BleEvent::Advert(advert), "New one", true);
        check(BleEvent::Failed("no adapter".into()), "failed: no adapter", false);

        lock(&harness.state().live).session.store_error = Some("disk full".into());
        harness.run();
        assert!(has(&harness, "Log error: disk full"));
    }

    #[test]
    fn pump_gives_each_event_to_the_state_until_the_senders_are_gone() {
        let db = Arc::new(SignatureDb::embedded().unwrap());
        let live = Mutex::new(Live::new(Session::new(db, None, "car".into())));
        let (tx, rx) = mpsc::channel();
        tx.send(AppEvent::Ble(BleEvent::Started("hci0".into()))).unwrap();
        tx.send(AppEvent::Ble(BleEvent::Advert(Advert { id: "tag".into(), ..Default::default() }))).unwrap();
        tx.send(AppEvent::Lan(Err("no network".into()))).unwrap();
        drop(tx);
        pump(rx, &live);
        let live = lock(&live);
        assert!(live.ble_ok);
        assert!(live.session.get("tag").is_some());
        assert!(matches!(&live.lan, LanState::Failed(error) if error == "no network"));
        drop(live);

        // A stopped event thread shows as a failure.
        let live = Mutex::new(Live::new(session()));
        fail(&live, "the event thread stopped");
        assert!(!lock(&live).ble_ok);
        assert_eq!(lock(&live).ble_status, "failed: the event thread stopped");
    }

    fn report(hosts: Vec<LanHost>) -> LanReport {
        LanReport {
            networks: vec!["192.168.1.0/24 (en0)".into()],
            addresses_probed: 253,
            seconds: 5.5,
            hosts,
            others: vec![Neighbour {
                ip: Ipv4Addr::new(192, 168, 1, 1),
                mac: "00:11:22:33:44:55".into(),
                vendor: Some("Router Maker".into()),
                note: None,
            }],
        }
    }

    fn host(last: u8, verdict: Verdict) -> LanHost {
        LanHost {
            ip: Ipv4Addr::new(192, 168, 1, last),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            vendor: Some("Some Maker".into()),
            camera_vendor: false,
            verdict,
            open_ports: vec![OpenPort { port: 554, meaning: "RTSP video stream" }],
            rtsp: Some("Hipcam".into()),
            onvif: None,
        }
    }

    #[test]
    fn network_view_runs_the_sweep_and_shows_the_result() {
        let starts = Cell::new(0);
        let start = || starts.set(starts.get() + 1);
        let mut harness = harness(session(), &start);
        click(&mut harness, "Network cameras");
        click(&mut harness, "Start the sweep");
        assert_eq!(starts.get(), 1);
        assert!(has(&harness, "The sweep runs… 0 s"));
        // The button is off while the sweep runs.
        assert!(harness.get_by_label("Start the sweep").accesskit_node().is_disabled());
        click(&mut harness, "Start the sweep");
        assert_eq!(starts.get(), 1);

        deliver(
            &mut harness,
            AppEvent::Lan(Ok(report(vec![host(64, Verdict::Likely), host(65, Verdict::Possible)]))),
        );
        assert!(has(&harness, "253 addresses checked in 5.5 s on 192.168.1.0/24 (en0)."));
        assert!(has(&harness, "2 host(s) with camera evidence. 1 other host(s) answered."));
        assert!(has(&harness, "LIKELY"));
        assert!(has(&harness, "maybe"));
        assert!(has(&harness, "RTSP server: Hipcam; port 554"));
        // Other hosts show only after the user asks for them.
        assert!(!has(&harness, "Router Maker"));
        click(&mut harness, "Show hosts without camera evidence");
        assert!(has(&harness, "Router Maker"));

        click(&mut harness, "Sweep again");
        assert_eq!(starts.get(), 2);
        deliver(&mut harness, AppEvent::Lan(Err("no private IPv4 network found".into())));
        assert!(has(&harness, "The sweep failed: no private IPv4 network found"));
        click(&mut harness, "Try again");
        assert_eq!(starts.get(), 3);

        deliver(&mut harness, AppEvent::Lan(Ok(report(Vec::new()))));
        assert!(has(&harness, "No camera evidence found. 1 other host(s) answered."));
    }

    #[test]
    fn followers_view_reads_the_log() {
        let mut harness = harness(session(), &noop);
        click(&mut harness, "Followers");
        assert!(has(&harness, "same ID"));
        assert!(has(&harness, "home, office"));
        assert!(has(&harness, "id:phone"));
        assert!(!has(&harness, "Desk lamp"));
        // Refresh reads the log again.
        harness.state_mut().followers.clear();
        click(&mut harness, "Refresh");
        assert_eq!(harness.state().followers.len(), 1);
    }

    #[test]
    fn followers_view_without_history() {
        let db = Arc::new(SignatureDb::embedded().unwrap());
        let mut without_log = harness(Session::new(db.clone(), None, "car".into()), &noop);
        click(&mut without_log, "Followers");
        assert!(has(&without_log, "The log is off, so there is no history."));

        let session = Session::new(db, Some(Store::in_memory().unwrap()), "car".into());
        let mut with_log = harness(session, &noop);
        click(&mut with_log, "Followers");
        assert!(has(&with_log, "No device was seen at two or more places."));
    }
}

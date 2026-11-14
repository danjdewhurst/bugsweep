//! Desktop window. It shows the same views as the terminal interface.

use std::collections::VecDeque;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eframe::egui::{
    self, Align, Button, CentralPanel, Color32, Context, Grid, Label, Layout, ProgressBar, RichText,
    ScrollArea, Sense, Shape, SidePanel, Stroke, TopBottomPanel, Ui, pos2, vec2,
};

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

pub struct Gui<'a> {
    session: Session,
    events: Receiver<AppEvent>,
    start_lan: &'a dyn Fn(),
    view: View,
    /// Show the devices without a finding too.
    show_all: bool,
    selected: Option<String>,
    /// Device ID that the finder follows, and its signal history.
    finder: Option<String>,
    finder_history: VecDeque<u16>,
    last_sample: Instant,
    ble_status: String,
    ble_ok: bool,
    lan: LanState,
    /// Show the hosts without camera evidence too.
    lan_show_all: bool,
    followers: Vec<Follower>,
}

impl<'a> Gui<'a> {
    /// `start_lan` starts one network sweep, whose result must arrive on
    /// `events` as `AppEvent::Lan`.
    pub fn new(session: Session, events: Receiver<AppEvent>, start_lan: &'a dyn Fn()) -> Self {
        Gui {
            session,
            events,
            start_lan,
            view: View::Devices,
            show_all: true,
            selected: None,
            finder: None,
            finder_history: VecDeque::new(),
            last_sample: Instant::now(),
            ble_status: "starting".into(),
            ble_ok: false,
            lan: LanState::Idle,
            lan_show_all: false,
            followers: Vec::new(),
        }
    }

    /// Handle the new events and draw one frame.
    pub fn show(&mut self, ctx: &Context) {
        while let Ok(event) = self.events.try_recv() {
            self.on_event(event);
        }
        if self.last_sample.elapsed() >= TICK {
            self.last_sample = Instant::now();
            self.sample_finder();
        }
        // New adverts arrive all the time, so draw again soon.
        ctx.request_repaint_after(TICK);

        TopBottomPanel::top("header").show(ctx, |ui| self.header(ui));
        TopBottomPanel::bottom("footer").show(ctx, |ui| {
            ui.weak("Radio check only. A device that sends no radio signal stays hidden.");
        });
        CentralPanel::default().show(ctx, |ui| match (&self.finder, self.view) {
            (Some(_), _) => self.finder_view(ui),
            (None, View::Devices) => self.devices_view(ui),
            (None, View::Network) => self.network_view(ui),
            (None, View::Followers) => self.followers_view(ui),
        });
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

    fn sample_finder(&mut self) {
        let Some(device) = self.finder.as_deref().and_then(|id| self.session.get(id)) else {
            return;
        };
        if self.finder_history.len() == FINDER_SAMPLES {
            self.finder_history.pop_front();
        }
        self.finder_history.push_back(device.rssi_avg.map(signal_percent).unwrap_or(0));
    }

    fn open_finder(&mut self, id: Option<String>) {
        self.finder = id;
        self.finder_history.clear();
    }

    fn start_sweep(&mut self) {
        self.lan = LanState::Running(Instant::now());
        (self.start_lan)();
    }

    // ------------------------------------------------------------ panels

    fn header(&mut self, ui: &mut Ui) {
        let all = self.session.sorted(true);
        let flagged = all.iter().filter(|d| self.session.is_flagged(d)).count();
        let devices = all.len();
        ui.horizontal_wrapped(|ui| {
            ui.heading("bugsweep");
            ui.separator();
            ui.label("Bluetooth:");
            let colour = if self.ble_ok { GREEN } else { ui.visuals().error_fg_color };
            ui.colored_label(colour, &self.ble_status);
            ui.separator();
            ui.label(format!("Place: {}", self.session.place));
            ui.separator();
            ui.label(format!("Devices: {devices}"));
            ui.separator();
            let flagged_text = RichText::new(format!("Flagged: {flagged}"));
            ui.label(if flagged > 0 {
                flagged_text.strong().color(ui.visuals().warn_fg_color)
            } else {
                flagged_text
            });
            if let Some(error) = &self.session.store_error {
                ui.separator();
                ui.colored_label(ui.visuals().error_fg_color, format!("Log error: {error}"));
            }
        });
        ui.horizontal(|ui| {
            let before = self.view;
            ui.selectable_value(&mut self.view, View::Devices, "Bluetooth");
            ui.selectable_value(&mut self.view, View::Network, "Network cameras");
            ui.selectable_value(&mut self.view, View::Followers, "Followers");
            if self.view != before {
                self.open_finder(None);
                if self.view == View::Followers {
                    self.followers = self.session.followers();
                }
            }
        });
        ui.add_space(2.0);
    }

    fn devices_view(&mut self, ui: &mut Ui) {
        let devices = self.session.sorted(self.show_all);
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
                match selected.as_deref().and_then(|id| self.session.get(id)) {
                    Some(device) => action = self.details(ui, device),
                    None if self.show_all => _ = ui.label("No devices yet."),
                    None => _ = ui.label("No flagged devices."),
                }
            });
        });
        CentralPanel::default().show_inside(ui, |ui| {
            ui.checkbox(&mut show_all, "Show devices without a finding");
            ui.add_space(4.0);
            ScrollArea::both().show(ui, |ui| {
                Grid::new("devices").striped(true).num_columns(7).spacing([12.0, 6.0]).show(ui, |ui| {
                    for title in ["Level", "Type", "Device", "Finding", "Signal", "Distance", "Seen"] {
                        ui.strong(title);
                    }
                    ui.end_row();
                    for device in &devices {
                        if self.device_row(ui, device, selected.as_deref() == Some(&device.advert.id)) {
                            clicked = Some(device.advert.id.clone());
                        }
                        ui.end_row();
                    }
                });
            });
        });

        self.show_all = show_all;
        self.selected = clicked.or(selected);
        match action {
            Some(DeviceAction::Find) => self.open_finder(self.selected.clone()),
            Some(DeviceAction::ToggleKnown) => {
                if let Some(id) = &self.selected {
                    self.session.toggle_known(id);
                }
            }
            None => {}
        }
    }

    /// Draw one row of the device list. Returns `true` when the user
    /// clicked the device.
    fn device_row(&self, ui: &mut Ui, device: &Device, selected: bool) -> bool {
        let level = self.session.level(device);
        let signature = self.session.top_signature(device);
        let dim = device.known || device.age() > STALE_AFTER;
        let text = |text: String| {
            let text = RichText::new(text);
            if dim { text.weak() } else { text }
        };

        let tag = level.map(level_tag).unwrap_or("");
        ui.label(match level {
            Some(level) if !dim => RichText::new(tag).strong().color(level_colour(ui, level)),
            _ => text(tag.into()),
        });
        ui.label(text(signature.map(|sig| sig.category.label()).unwrap_or("").into()));
        let title = device.title().unwrap_or_else(|| "(no name)".into());
        let clicked = ui.selectable_label(selected, text(title)).clicked();
        ui.label(text(finding_text(&self.session, device)));
        match device.rssi_avg {
            Some(rssi) => {
                _ = ui.add(
                    ProgressBar::new(signal_percent(rssi) as f32 / 100.0)
                        .desired_width(110.0)
                        .text(format!("{rssi:.0} dBm")),
                )
            }
            None => _ = ui.label(""),
        }
        ui.label(text(device.distance_m().map(format_distance).unwrap_or_default()));
        ui.label(text(format_age(device.age())));
        clicked
    }

    fn details(&self, ui: &mut Ui, device: &Device) -> Option<DeviceAction> {
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
            let sig = self.session.db().get(index);
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(level_tag(sig.severity)).strong().color(level_colour(ui, sig.severity)),
                );
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

    fn finder_view(&mut self, ui: &mut Ui) {
        if ui.button("Back to the list").clicked() {
            self.open_finder(None);
            return;
        }
        ui.add_space(8.0);
        let Some(device) = self.finder.as_deref().and_then(|id| self.session.get(id)) else {
            ui.label("The device is gone.");
            return;
        };
        ui.heading(device.title().unwrap_or_else(|| "(no name)".into()));
        if let Some(sig) = self.session.top_signature(device) {
            ui.label(&sig.name);
        }
        ui.add_space(8.0);

        let FinderReading { stale, percent, label } = FinderReading::of(device);
        let colour = match percent {
            _ if stale => ui.visuals().weak_text_color(),
            70.. => ui.visuals().error_fg_color,
            40.. => ui.visuals().warn_fg_color,
            _ => BLUE,
        };
        ui.add(ProgressBar::new(percent as f32 / 100.0).desired_height(36.0).fill(colour).text(label));
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
        let start = FINDER_SAMPLES - self.finder_history.len();
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
        painter.add(Shape::line(points, Stroke::new(2.0, colour)));
    }

    fn network_view(&mut self, ui: &mut Ui) {
        ui.label("The sweep looks for IP cameras and video recorders on the local network.");
        ui.label("It sends connection attempts to each address. Use it only where you are allowed to.");
        ui.add_space(8.0);
        let mut start = false;
        match &self.lan {
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
            self.start_sweep();
        }
    }

    fn followers_view(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.heading("Devices seen at two or more places");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("Refresh").clicked() {
                    self.followers = self.session.followers();
                }
            });
        });
        ui.add_space(8.0);
        if !self.session.has_log() {
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

fn level_colour(ui: &Ui, level: Level) -> Color32 {
    match level {
        Level::High => ui.visuals().error_fg_color,
        Level::Medium => ui.visuals().warn_fg_color,
        Level::Low => CYAN,
        Level::Info => ui.visuals().text_color(),
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
    use std::sync::Arc;
    use std::sync::mpsc::{self, Sender};

    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable;

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

    /// A window of 1400 × 900 points, with the channel that feeds it.
    fn harness<'a>(session: Session, start_lan: &'a dyn Fn()) -> (Harness<'a, Gui<'a>>, Sender<AppEvent>) {
        let (tx, rx) = mpsc::channel();
        let gui = Gui::new(session, rx, start_lan);
        // A frame time below the tick, so that the harness does not take the
        // repaint request of each tick as an endless animation.
        let mut harness = Harness::builder()
            .with_size(vec2(1400.0, 900.0))
            .with_step_dt(0.05)
            .build_state(|ctx, gui: &mut Gui| gui.show(ctx), gui);
        harness.run();
        (harness, tx)
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
        let (mut harness, _tx) = harness(session(), &noop);
        assert!(has(&harness, "Devices: 4"));
        assert!(has(&harness, "Flagged: 3"));
        assert!(has(&harness, "Place: office"));
        assert!(has(&harness, "seen at 1 other place(s), same ID"));
        // The first device is selected, so the details show its evidence.
        assert_eq!(harness.state().selected.as_deref(), Some("glasses"));
        assert!(has(&harness, "from a paper or a published capture"));
        assert!(has(&harness, "Source: "));
        assert!(has(&harness, "0x01ab"));

        click(&mut harness, "Desk lamp");
        assert!(has(&harness, "No finding for this device."));

        // Only the flagged devices.
        click(&mut harness, "Show devices without a finding");
        assert!(!harness.state().show_all);
        assert!(!has(&harness, "Desk lamp"));

        // The phone has no signature, so its details show only the warning.
        click(&mut harness, "My phone");
        assert_eq!(harness.state().selected.as_deref(), Some("phone"));
        assert!(has(&harness, "This device was seen at 1 other place(s), same ID."));
    }

    #[test]
    fn mark_as_my_device_removes_the_flag() {
        let (mut harness, _tx) = harness(session(), &noop);
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
        let (mut harness, _tx) = harness(Session::new(db, None, "car".into()), &noop);
        assert!(has(&harness, "No devices yet."));
        click(&mut harness, "Show devices without a finding");
        assert!(has(&harness, "No flagged devices."));
        click(&mut harness, "Network cameras");
        click(&mut harness, "Start the sweep");
        assert!(has(&harness, "The sweep runs"));
    }

    #[test]
    fn finder_follows_the_signal() {
        let (mut harness, _tx) = harness(session(), &noop);
        click(&mut harness, "My phone");
        click(&mut harness, "Find this device");
        assert_eq!(harness.state().finder.as_deref(), Some("phone"));
        assert!(has(&harness, "Move the laptop slowly."));

        // Each tick adds one sample, and the history keeps the latest ones.
        harness.state_mut().finder_history.extend([0; FINDER_SAMPLES]);
        harness.state_mut().last_sample = Instant::now() - TICK;
        harness.run();
        assert_eq!(harness.state().finder_history.len(), FINDER_SAMPLES);
        // -40 dBm is 92 percent.
        assert_eq!(harness.state().finder_history.back(), Some(&92));

        click(&mut harness, "Back to the list");
        assert!(harness.state().finder.is_none());
        // Without the finder, a tick adds no sample.
        harness.state_mut().last_sample = Instant::now() - TICK;
        harness.run();
        assert!(harness.state().finder_history.is_empty());
    }

    #[test]
    fn finder_colours_follow_the_strength() {
        let mut session = session();
        // Silent for 40 s: stale in the finder and dim in the list.
        let old =
            Advert { id: "old".into(), name: Some("Old tag".into()), rssi: Some(-90), ..Default::default() };
        session.ingest_at(old, Instant::now() - Duration::from_secs(40));
        session.ingest(Advert { id: "far".into(), rssi: Some(-85), ..Default::default() });
        let (mut harness, _tx) = harness(session, &noop);
        for id in ["phone", "glasses", "far", "old"] {
            harness.state_mut().finder = Some(id.into());
            harness.run();
        }
        assert!(has(&harness, "no signal for 40s"));

        // A device that is gone, and a tab change, which closes the finder.
        harness.state_mut().finder = Some("gone".into());
        harness.run();
        assert!(has(&harness, "The device is gone."));
        click(&mut harness, "Followers");
        assert!(harness.state().finder.is_none());
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
        let (harness, _tx) = harness(session, &noop);
        assert!(has(&harness, "Low tag"));
        assert!(has(&harness, "Info tag"));
        assert!(has(&harness, "A note about the low tag."));
    }

    #[test]
    fn bluetooth_events_change_the_header() {
        let (mut harness, tx) = harness(session(), &noop);
        assert!(has(&harness, "starting"));
        let mut send = |event: BleEvent, expect: &str| {
            tx.send(AppEvent::Ble(event)).unwrap();
            harness.run();
            assert!(has(&harness, expect), "{expect}");
        };
        send(BleEvent::Started("hci0".into()), "scanning (hci0)");
        send(BleEvent::Power(false), "Bluetooth is off");
        send(BleEvent::Power(true), "scanning");
        send(
            BleEvent::Advert(Advert { id: "new".into(), name: Some("New one".into()), ..Default::default() }),
            "New one",
        );
        send(BleEvent::Failed("no adapter".into()), "failed: no adapter");

        harness.state_mut().session.store_error = Some("disk full".into());
        harness.run();
        assert!(has(&harness, "Log error: disk full"));
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
        let (mut harness, tx) = harness(session(), &start);
        click(&mut harness, "Network cameras");
        click(&mut harness, "Start the sweep");
        assert_eq!(starts.get(), 1);
        assert!(has(&harness, "The sweep runs… 0 s"));
        // The button is off while the sweep runs.
        click(&mut harness, "Start the sweep");
        assert_eq!(starts.get(), 1);

        tx.send(AppEvent::Lan(Ok(report(vec![host(64, Verdict::Likely), host(65, Verdict::Possible)]))))
            .unwrap();
        harness.run();
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
        tx.send(AppEvent::Lan(Err("no private IPv4 network found".into()))).unwrap();
        harness.run();
        assert!(has(&harness, "The sweep failed: no private IPv4 network found"));
        click(&mut harness, "Try again");
        assert_eq!(starts.get(), 3);

        tx.send(AppEvent::Lan(Ok(report(Vec::new())))).unwrap();
        harness.run();
        assert!(has(&harness, "No camera evidence found. 1 other host(s) answered."));
    }

    #[test]
    fn followers_view_reads_the_log() {
        let (mut harness, _tx) = harness(session(), &noop);
        click(&mut harness, "Followers");
        assert!(has(&harness, "same ID"));
        assert!(has(&harness, "home, office"));
        assert!(has(&harness, "id:phone"));
        assert!(!has(&harness, "Desk lamp"));
        click(&mut harness, "Refresh");
        assert_eq!(harness.state().followers.len(), 1);
    }

    #[test]
    fn followers_view_without_history() {
        let db = Arc::new(SignatureDb::embedded().unwrap());
        let (mut harness, _tx) = harness(Session::new(db.clone(), None, "car".into()), &noop);
        click(&mut harness, "Followers");
        assert!(has(&harness, "The log is off, so there is no history."));

        let session = Session::new(db, Some(Store::in_memory().unwrap()), "car".into());
        let (mut with_log, _tx) = self::harness(session, &noop);
        click(&mut with_log, "Followers");
        assert!(has(&with_log, "No device was seen at two or more places."));
    }
}

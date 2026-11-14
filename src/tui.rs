//! Terminal interface.

use std::collections::VecDeque;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Gauge, Paragraph, Row, Sparkline, Table, TableState, Tabs, Wrap};
use ratatui::{DefaultTerminal, Frame};

use crate::ble::BleEvent;
use crate::lan::{LanHost, LanReport, Verdict};
use crate::model::uuid_label;
use crate::session::follow_text;
use crate::session::{Device, Session};
use crate::signatures::Level;
use crate::store::Follower;
use crate::vendors;

pub enum AppEvent {
    Ble(BleEvent),
    Lan(Result<LanReport, String>),
}

/// A device that was silent for this time shows dim.
const STALE_AFTER: Duration = Duration::from_secs(30);
const TICK: Duration = Duration::from_millis(200);
const FINDER_SAMPLES: usize = 120;

#[derive(Clone, Copy, PartialEq, Eq)]
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

struct App<'a> {
    session: Session,
    start_lan: &'a dyn Fn(),
    view: View,
    show_all: bool,
    selected: Option<String>,
    table: TableState,
    /// Device ID that the finder follows, and its signal history.
    finder: Option<String>,
    finder_history: VecDeque<u64>,
    ble_status: String,
    ble_ok: bool,
    lan: LanState,
    /// Show the hosts without camera evidence too.
    lan_show_all: bool,
    followers: Vec<Follower>,
}

/// Run the interface until the user quits. `start_lan` starts one network
/// sweep, whose result must arrive as `AppEvent::Lan`.
pub fn run(session: Session, events: Receiver<AppEvent>, start_lan: &dyn Fn()) -> Result<()> {
    let mut app = App::new(session, start_lan);
    let mut terminal = ratatui::init();
    let result = app.event_loop(&mut terminal, events);
    ratatui::restore();
    result
}

impl<'a> App<'a> {
    fn new(session: Session, start_lan: &'a dyn Fn()) -> Self {
        App {
            session,
            start_lan,
            view: View::Devices,
            show_all: true,
            selected: None,
            table: TableState::default(),
            finder: None,
            finder_history: VecDeque::new(),
            ble_status: "starting".into(),
            ble_ok: false,
            lan: LanState::Idle,
            lan_show_all: false,
            followers: Vec::new(),
        }
    }

    fn event_loop(&mut self, terminal: &mut DefaultTerminal, events: Receiver<AppEvent>) -> Result<()> {
        let mut last_sample = Instant::now();
        loop {
            while let Ok(event) = events.try_recv() {
                self.on_app_event(event);
            }
            if last_sample.elapsed() >= TICK {
                last_sample = Instant::now();
                self.sample_finder();
            }
            terminal.draw(|frame| self.draw(frame))?;
            if event::poll(TICK)?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                let ctrl_c = key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
                if ctrl_c || !self.on_key(key.code) {
                    return Ok(());
                }
            }
        }
    }

    fn on_app_event(&mut self, event: AppEvent) {
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
        let strength = device.rssi_avg.map(signal_percent).unwrap_or(0);
        if self.finder_history.len() == FINDER_SAMPLES {
            self.finder_history.pop_front();
        }
        self.finder_history.push_back(strength as u64);
    }

    /// Returns `false` when the user quits.
    fn on_key(&mut self, key: KeyCode) -> bool {
        if self.finder.is_some() {
            if matches!(key, KeyCode::Esc | KeyCode::Char('f') | KeyCode::Char('q')) {
                self.finder = None;
                self.finder_history.clear();
            }
            return true;
        }
        match key {
            KeyCode::Char('q') | KeyCode::Esc => return false,
            KeyCode::Tab => self.set_view(match self.view {
                View::Devices => View::Network,
                View::Network => View::Followers,
                View::Followers => View::Devices,
            }),
            KeyCode::Char('1') => self.set_view(View::Devices),
            KeyCode::Char('2') => self.set_view(View::Network),
            KeyCode::Char('3') => self.set_view(View::Followers),
            KeyCode::Char('l') if self.view == View::Network => {
                if !matches!(self.lan, LanState::Running(_)) {
                    self.lan = LanState::Running(Instant::now());
                    (self.start_lan)();
                }
            }
            KeyCode::Char('a') if self.view == View::Network => self.lan_show_all = !self.lan_show_all,
            _ if self.view != View::Devices => {}
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Char('a') => self.show_all = !self.show_all,
            KeyCode::Char('m') => {
                if let Some(id) = self.selected.clone() {
                    self.session.toggle_known(&id);
                }
            }
            KeyCode::Char('f') | KeyCode::Enter => {
                self.finder = self.selected.clone();
                self.finder_history.clear();
            }
            _ => {}
        }
        true
    }

    fn set_view(&mut self, view: View) {
        self.view = view;
        if view == View::Followers {
            self.followers = self.session.followers();
        }
    }

    fn move_selection(&mut self, step: isize) {
        let ids: Vec<String> =
            self.session.sorted(self.show_all).iter().map(|d| d.advert.id.clone()).collect();
        if ids.is_empty() {
            self.selected = None;
            return;
        }
        let current = self.selected.as_ref().and_then(|id| ids.iter().position(|x| x == id));
        let next = match current {
            Some(index) => (index as isize + step).clamp(0, ids.len() as isize - 1) as usize,
            None => 0,
        };
        self.selected = Some(ids[next].clone());
    }

    // ------------------------------------------------------------ drawing

    fn draw(&mut self, frame: &mut Frame) {
        let [header, tabs, body, footer] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(2),
        ])
        .areas(frame.area());

        self.draw_header(frame, header);
        let selected_tab = match self.view {
            View::Devices => 0,
            View::Network => 1,
            View::Followers => 2,
        };
        frame.render_widget(
            Tabs::new(["1 Bluetooth", "2 Network cameras", "3 Followers"])
                .select(selected_tab)
                .highlight_style(Style::new().fg(Color::Black).bg(Color::Cyan)),
            tabs,
        );

        match (&self.finder, self.view) {
            (Some(_), _) => self.draw_finder(frame, body),
            (None, View::Devices) => self.draw_devices(frame, body),
            (None, View::Network) => self.draw_network(frame, body),
            (None, View::Followers) => self.draw_followers(frame, body),
        }
        self.draw_footer(frame, footer);
    }

    fn draw_header(&self, frame: &mut Frame, area: Rect) {
        let all = self.session.sorted(true);
        let flagged = all.iter().filter(|d| self.session.is_flagged(d)).count();
        let status_style = if self.ble_ok { Style::new().green() } else { Style::new().red().bold() };
        let mut spans = vec![
            Span::from(" bugsweep ").bold().reversed(),
            Span::from("  Bluetooth: "),
            Span::styled(self.ble_status.clone(), status_style),
            Span::from(format!("   place: {}", self.session.place)),
            Span::from(format!("   devices: {}", all.len())),
            Span::from("   flagged: "),
            Span::styled(
                flagged.to_string(),
                if flagged > 0 { Style::new().yellow().bold() } else { Style::new() },
            ),
        ];
        if let Some(error) = &self.session.store_error {
            spans.push(Span::from(format!("   log error: {error}")).red());
        }
        frame.render_widget(Line::from(spans), area);
    }

    fn draw_footer(&self, frame: &mut Frame, area: Rect) {
        let keys = if self.finder.is_some() {
            "f/Esc leave the finder"
        } else {
            match self.view {
                View::Devices => {
                    "↑↓ select   f finder   m mark as known   a all/flagged only   Tab view   q quit"
                }
                View::Network => "l start the sweep   a all hosts/camera evidence only   Tab view   q quit",
                View::Followers => "Tab view   q quit",
            }
        };
        let lines = vec![
            Line::from(keys).cyan(),
            Line::from("Radio check only. A device that sends no radio signal stays hidden.").dim(),
        ];
        frame.render_widget(Paragraph::new(lines), area);
    }

    fn draw_devices(&mut self, frame: &mut Frame, area: Rect) {
        let [list_area, detail_area] =
            Layout::vertical([Constraint::Min(6), Constraint::Length(12)]).areas(area);

        let devices = self.session.sorted(self.show_all);
        // Keep the selection on the same device when the order changes.
        let mut index = self.selected.as_ref().and_then(|id| devices.iter().position(|d| &d.advert.id == id));
        if index.is_none() && !devices.is_empty() {
            index = Some(0);
        }
        let selected_id = index.map(|i| devices[i].advert.id.clone());

        let rows: Vec<Row> = devices.iter().map(|device| self.device_row(device)).collect();
        let title = if self.show_all { " All devices " } else { " Flagged devices " };
        let table = Table::new(
            rows,
            [
                Constraint::Length(6),
                Constraint::Length(9),
                Constraint::Percentage(28),
                Constraint::Percentage(42),
                Constraint::Length(19),
                Constraint::Length(7),
                Constraint::Length(5),
            ],
        )
        .header(
            Row::new(["Level", "Type", "Device", "Finding", "Signal", "Dist.", "Seen"])
                .style(Style::new().add_modifier(Modifier::UNDERLINED)),
        )
        .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .block(Block::bordered().title(title));

        let detail = match index {
            Some(i) => self.detail_lines(devices[i]),
            None if self.show_all => vec![Line::from("No devices yet.")],
            None => vec![Line::from("No flagged devices. Press a to show all devices.")],
        };

        self.table.select(index);
        frame.render_stateful_widget(table, list_area, &mut self.table);
        frame.render_widget(
            Paragraph::new(detail).wrap(Wrap { trim: false }).block(Block::bordered().title(" Details ")),
            detail_area,
        );
        self.selected = selected_id;
    }

    fn device_row(&self, device: &Device) -> Row<'static> {
        let level = self.session.level(device);
        let signature = self.session.top_signature(device);
        let mut finding = signature.map(|sig| sig.name.clone()).unwrap_or_default();
        if let Some(follow) = device.follow() {
            let follow = follow_text(follow);
            finding = if finding.is_empty() { follow } else { format!("{finding}; {follow}") };
        }
        if device.known {
            finding = if finding.is_empty() { "known".into() } else { format!("known · {finding}") };
        }
        let signal = match device.rssi_avg {
            Some(rssi) => format!("{} {:>4.0} dBm", bar(signal_percent(rssi), 8), rssi),
            None => String::new(),
        };
        let distance = device.distance_m().map(format_distance).unwrap_or_default();

        let mut style = level_style(level);
        if device.known || device.age() > STALE_AFTER {
            style = Style::new().dim();
        }
        Row::new([
            Cell::from(level.map(level_tag).unwrap_or("")),
            Cell::from(signature.map(|sig| sig.category.label()).unwrap_or("")),
            Cell::from(device.title().unwrap_or_else(|| "(no name)".into())),
            Cell::from(finding),
            Cell::from(signal),
            Cell::from(distance),
            Cell::from(format_age(device.age())),
        ])
        .style(style)
    }

    fn detail_lines(&self, device: &Device) -> Vec<Line<'static>> {
        let advert = &device.advert;
        let mut lines = Vec::new();
        let field = |label: &str, value: String| {
            Line::from(vec![Span::from(format!("{label:<11}")).dim(), Span::from(value)])
        };

        for &index in &device.hits {
            let sig = self.session.db().get(index);
            lines.push(Line::from(vec![
                Span::styled(format!("{} ", level_tag(sig.severity)), level_style(Some(sig.severity))),
                Span::from(sig.name.clone()).bold(),
                Span::from(format!("  (confidence {}; {})", sig.confidence.label(), sig.evidence.describe()))
                    .dim(),
            ]));
            if let Some(notes) = &sig.notes {
                lines.push(Line::from(format!("     {notes}")));
            }
            lines.push(Line::from(format!("     Source: {}", sig.source)).dim());
        }
        if let Some(follow) = device.follow() {
            let caution = match follow.basis {
                crate::identity::Basis::Name => " A different device of the same model can have this name.",
                crate::identity::Basis::Data => " A different device of the same model can send this data.",
                _ => "",
            };
            lines.push(
                Line::from(format!(
                    "This device was {}.{caution} Press m if it is yours.",
                    follow_text(follow)
                ))
                .yellow(),
            );
        }
        if device.hits.is_empty() && device.follow().is_none() {
            lines.push(Line::from("No finding for this device.").dim());
        }

        let name = advert.name.clone().unwrap_or_else(|| "(no name)".into());
        lines.push(field("Name", name));
        let id = match &advert.address {
            Some(address) => format!("{address}  ({})", advert.id),
            None => format!("{}  (the system hides the address)", advert.id),
        };
        lines.push(field("ID", id));
        for (company, data) in &advert.manufacturer_data {
            let vendor = vendors::company(*company).unwrap_or("unknown company");
            lines.push(field("Maker data", format!("{company:#06x} {vendor}: {}", hex_short(data, 24))));
        }
        for uuid in &advert.services {
            lines.push(field("Service", with_owner(uuid)));
        }
        for (uuid, data) in &advert.service_data {
            lines.push(field("Svc data", format!("{}: {}", with_owner(uuid), hex_short(data, 24))));
        }
        lines.push(field(
            "Stats",
            format!(
                "{} updates, first seen {} ago{}",
                device.updates,
                format_age(device.first_seen.elapsed()),
                advert.tx_power.map(|p| format!(", TX power {p} dBm")).unwrap_or_default()
            ),
        ));
        lines
    }

    fn draw_finder(&self, frame: &mut Frame, area: Rect) {
        let block = Block::bordered().title(" Finder ");
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let Some(device) = self.finder.as_deref().and_then(|id| self.session.get(id)) else {
            frame.render_widget(Paragraph::new("The device is gone."), inner);
            return;
        };
        let [title, gauge_area, _, history, help] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(3),
        ])
        .areas(inner);

        let name = device.title().unwrap_or_else(|| "(no name)".into());
        let finding = self.session.top_signature(device).map(|sig| sig.name.clone()).unwrap_or_default();
        frame.render_widget(Paragraph::new(vec![Line::from(name).bold(), Line::from(finding)]), title);

        let stale = device.age() > Duration::from_secs(5);
        let percent = device.rssi_avg.map(signal_percent).unwrap_or(0);
        let label = match (device.rssi_avg, device.distance_m()) {
            _ if stale => format!("no signal for {}", format_age(device.age())),
            (Some(rssi), Some(distance)) => {
                format!("{rssi:.0} dBm   about {}", format_distance(distance))
            }
            _ => "no signal value".into(),
        };
        let colour = match percent {
            _ if stale => Color::DarkGray,
            70.. => Color::Red,
            40.. => Color::Yellow,
            _ => Color::Blue,
        };
        frame.render_widget(
            Gauge::default()
                .block(Block::bordered())
                .gauge_style(Style::new().fg(colour))
                .percent(percent)
                .label(label),
            gauge_area,
        );

        let width = history.width as usize;
        let samples: Vec<u64> = self.finder_history.iter().rev().take(width).rev().copied().collect();
        frame.render_widget(
            Sparkline::default().data(&samples).max(100).style(Style::new().fg(colour)),
            history,
        );
        frame.render_widget(
            Paragraph::new(vec![
                Line::from("Move the laptop slowly. The bar grows when you get nearer to the device."),
                Line::from("The distance is a rough estimate. Walls and bodies weaken the signal.").dim(),
            ])
            .wrap(Wrap { trim: true }),
            help,
        );
    }

    fn draw_network(&self, frame: &mut Frame, area: Rect) {
        let block = Block::bordered().title(" Cameras on the local network ");
        let intro = |extra: Vec<Line<'static>>| {
            let mut lines = vec![
                Line::from("The sweep looks for IP cameras and video recorders on the local network."),
                Line::from(
                    "It sends connection attempts to each address. Use it only where you are allowed to.",
                ),
                Line::from(""),
            ];
            lines.extend(extra);
            Paragraph::new(lines).wrap(Wrap { trim: false })
        };
        match &self.lan {
            LanState::Idle => {
                let text = intro(vec![Line::from("Press l to start the sweep.").cyan()]);
                frame.render_widget(text.block(block), area);
            }
            LanState::Running(since) => {
                let text = intro(vec![
                    Line::from(format!("The sweep runs… {} s", since.elapsed().as_secs())).yellow(),
                ]);
                frame.render_widget(text.block(block), area);
            }
            LanState::Failed(error) => {
                let text = intro(vec![
                    Line::from(format!("The sweep failed: {error}")).red(),
                    Line::from("Press l to try again."),
                ]);
                frame.render_widget(text.block(block), area);
            }
            LanState::Done(report) => {
                let [summary, table_area] =
                    Layout::vertical([Constraint::Length(2), Constraint::Min(3)]).areas(block.inner(area));
                frame.render_widget(block, area);
                frame.render_widget(
                    Paragraph::new(vec![
                        Line::from(format!(
                            "{} addresses checked in {:.1} s on {}.",
                            report.addresses_probed,
                            report.seconds,
                            report.networks.join(", ")
                        )),
                        if report.hosts.is_empty() {
                            Line::from(format!(
                                "No camera evidence found. {} other host(s) answered.",
                                report.others.len()
                            ))
                            .green()
                        } else {
                            Line::from(format!(
                                "{} host(s) with camera evidence. {} other host(s) answered.",
                                report.hosts.len(),
                                report.others.len()
                            ))
                            .yellow()
                        },
                    ]),
                    summary,
                );
                let other_rows = report.others.iter().filter(|_| self.lan_show_all).map(|other| {
                    let detail = match (&other.vendor, other.note) {
                        (Some(vendor), Some(note)) => format!("{vendor} ({note})"),
                        (Some(vendor), None) => vendor.clone(),
                        (None, Some(note)) => note.to_string(),
                        (None, None) => "unknown vendor".to_string(),
                    };
                    Row::new([
                        Cell::from(""),
                        Cell::from(other.ip.to_string()),
                        Cell::from(other.mac.clone()),
                        Cell::from(detail),
                    ])
                });
                let rows = report.hosts.iter().map(|host| {
                    let style = match host.verdict {
                        Verdict::Likely => Style::new().red().bold(),
                        Verdict::Possible => Style::new().yellow(),
                    };
                    Row::new([
                        Cell::from(match host.verdict {
                            Verdict::Likely => "LIKELY",
                            Verdict::Possible => "maybe",
                        }),
                        Cell::from(host.ip.to_string()),
                        Cell::from(host.mac.clone().unwrap_or_default()),
                        Cell::from(lan_evidence(host)),
                    ])
                    .style(style)
                });
                let table = Table::new(
                    rows.chain(other_rows),
                    [
                        Constraint::Length(7),
                        Constraint::Length(16),
                        Constraint::Length(18),
                        Constraint::Min(20),
                    ],
                )
                .header(
                    Row::new(["Camera", "IP address", "MAC address", "Evidence or vendor"])
                        .style(Style::new().add_modifier(Modifier::UNDERLINED)),
                );
                frame.render_widget(table, table_area);
            }
        }
    }

    fn draw_followers(&self, frame: &mut Frame, area: Rect) {
        let block = Block::bordered().title(" Devices seen at two or more places ");
        if !self.session.has_log() {
            frame.render_widget(Paragraph::new("The log is off, so there is no history.").block(block), area);
            return;
        }
        if self.followers.is_empty() {
            let text = vec![
                Line::from("No device was seen at two or more places."),
                Line::from("Run bugsweep at different places. Mark your own devices with m.").dim(),
                Line::from("Many devices change their address often and send no name, so this check can miss a tracker.").dim(),
            ];
            frame.render_widget(Paragraph::new(text).wrap(Wrap { trim: false }).block(block), area);
            return;
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        let rows = self.followers.iter().map(|f| {
            Row::new([
                Cell::from(f.title.clone().unwrap_or_else(|| "(no name)".into())),
                Cell::from(f.signature.clone().unwrap_or_default()),
                Cell::from(format!("same {}", f.basis.label())),
                Cell::from(f.places.len().to_string()),
                Cell::from(format_age(Duration::from_secs((now - f.first_seen).max(0) as u64))),
                Cell::from(format_age(Duration::from_secs((now - f.last_seen).max(0) as u64))),
                Cell::from(f.key.clone()),
            ])
        });
        let table = Table::new(
            rows,
            [
                Constraint::Percentage(25),
                Constraint::Percentage(25),
                Constraint::Length(16),
                Constraint::Length(6),
                Constraint::Length(6),
                Constraint::Length(6),
                Constraint::Min(12),
            ],
        )
        .header(
            Row::new(["Device", "Signature", "Match", "Places", "First", "Last", "Key"])
                .style(Style::new().add_modifier(Modifier::UNDERLINED)),
        )
        .block(block);
        frame.render_widget(table, area);
    }
}

// ---------------------------------------------------------------- helpers

fn level_tag(level: Level) -> &'static str {
    match level {
        Level::High => "HIGH",
        Level::Medium => "MED",
        Level::Low => "low",
        Level::Info => "info",
    }
}

fn level_style(level: Option<Level>) -> Style {
    match level {
        Some(Level::High) => Style::new().red().bold(),
        Some(Level::Medium) => Style::new().yellow(),
        Some(Level::Low) => Style::new().cyan(),
        Some(Level::Info) | None => Style::new(),
    }
}

/// Map RSSI to 0..=100. -100 dBm is nothing, -35 dBm is next to the antenna.
pub fn signal_percent(rssi: f32) -> u16 {
    (((rssi + 100.0) / 65.0).clamp(0.0, 1.0) * 100.0).round() as u16
}

fn bar(percent: u16, width: usize) -> String {
    let filled = ((percent as usize * width) + 50) / 100;
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

/// The estimate is too rough to show values outside 0.5 m to 30 m.
pub fn format_distance(metres: f32) -> String {
    match metres {
        m if m < 0.5 => "<0.5 m".into(),
        m if m < 10.0 => format!("{m:.1} m"),
        m if m <= 30.0 => format!("{m:.0} m"),
        _ => ">30 m".into(),
    }
}

pub fn format_age(age: Duration) -> String {
    let secs = age.as_secs();
    match secs {
        0..60 => format!("{secs}s"),
        60..3600 => format!("{}m", secs / 60),
        3600..86_400 => format!("{}h", secs / 3600),
        _ => format!("{}d", secs / 86_400),
    }
}

fn hex_short(data: &[u8], max_bytes: usize) -> String {
    let shown = hex::encode(&data[..data.len().min(max_bytes)]);
    if data.len() > max_bytes { format!("{shown}… ({} bytes)", data.len()) } else { shown }
}

fn with_owner(uuid: &uuid::Uuid) -> String {
    match vendors::uuid_owner(uuid) {
        Some(owner) => format!("{} ({owner})", uuid_label(uuid)),
        None => uuid_label(uuid),
    }
}

/// One-line summary of why a network host looks like a camera.
pub fn lan_evidence(host: &LanHost) -> String {
    let mut parts = Vec::new();
    if let (true, Some(vendor)) = (host.camera_vendor, &host.vendor) {
        parts.push(format!("camera maker: {vendor}"));
    }
    if let Some(onvif) = &host.onvif {
        let detail: Vec<&str> =
            [onvif.name.as_deref(), onvif.hardware.as_deref()].into_iter().flatten().collect();
        parts.push(if detail.is_empty() {
            "ONVIF camera".to_string()
        } else {
            format!("ONVIF camera: {}", detail.join(" / "))
        });
    }
    if let Some(rtsp) = &host.rtsp {
        parts.push(if rtsp == "yes" { "RTSP server".to_string() } else { format!("RTSP server: {rtsp}") });
    }
    for port in &host.open_ports {
        parts.push(format!("port {} ({})", port.port, port.meaning));
    }
    if let (false, Some(vendor)) = (host.camera_vendor, &host.vendor) {
        parts.push(format!("vendor: {vendor}"));
    }
    parts.join("; ")
}

#[cfg(test)]
mod tests {
    use std::cell::Cell as StdCell;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::lan::{Neighbour, OpenPort};
    use crate::model::{Advert, parse_uuid};
    use crate::signatures::SignatureDb;
    use crate::store::Store;

    fn session() -> Session {
        let db = Arc::new(SignatureDb::embedded().unwrap());
        let store = Store::in_memory().unwrap();
        store.record("id:phone", "home", Some(-50), Some("My phone"), None).unwrap();
        store.record("name:My phone", "home", Some(-50), Some("My phone"), None).unwrap();
        let mut session = Session::new(db, Some(store), "office".into());

        let mut tile = Advert { id: "tile".into(), rssi: Some(-48), ..Default::default() };
        tile.services.push(parse_uuid("feed").unwrap());
        session.ingest(tile);

        let mut glasses = Advert { id: "glasses".into(), rssi: Some(-70), ..Default::default() };
        glasses.manufacturer_data.insert(0x01AB, vec![1, 2, 3]);
        session.ingest(glasses);

        let phone = Advert {
            id: "phone".into(),
            name: Some("My phone".into()),
            rssi: Some(-40),
            ..Default::default()
        };
        session.ingest(phone);
        let lamp = Advert {
            id: "lamp".into(),
            name: Some("Desk lamp".into()),
            rssi: Some(-60),
            ..Default::default()
        };
        session.ingest(lamp);
        session
    }

    fn render(app: &mut App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        let buffer = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                text.push_str(buffer[(x, y)].symbol());
            }
            text.push('\n');
        }
        text
    }

    #[test]
    fn device_view_lists_findings_in_order() {
        let noop = || {};
        let mut app = App::new(session(), &noop);
        let screen = render(&mut app);
        let row = |needle: &str| {
            screen
                .lines()
                .position(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("{needle} missing:\n{screen}"))
        };
        // High first, then medium findings by signal, then devices without a finding.
        assert!(row("Meta smart glasses") < row("Tile tracker"));
        assert!(row("Tile tracker") < row("Desk lamp"));
        assert!(row("seen at 1 other place(s), same ID") < row("Desk lamp"));
        assert!(screen.contains("flagged: 3"), "{screen}");
        // The first row is selected, so the details show its evidence and source.
        assert!(screen.contains("from a paper or a published capture"), "{screen}");
        assert!(screen.contains("banrays"), "{screen}");

        app.on_key(KeyCode::Char('a'));
        let screen = render(&mut app);
        assert!(!screen.contains("Desk lamp"), "{screen}");
        assert!(screen.contains("Flagged devices"), "{screen}");
    }

    #[test]
    fn mark_as_known_removes_the_flag() {
        let noop = || {};
        let mut app = App::new(session(), &noop);
        render(&mut app);
        assert_eq!(app.selected.as_deref(), Some("glasses"));
        app.on_key(KeyCode::Char('m'));
        let screen = render(&mut app);
        assert!(screen.contains("flagged: 2"), "{screen}");
        assert!(screen.contains("known · Meta smart glasses"), "{screen}");
        // The selection stays on the same device after the order changes.
        assert_eq!(app.selected.as_deref(), Some("glasses"));
    }

    #[test]
    fn selection_moves_and_finder_opens() {
        let noop = || {};
        let mut app = App::new(session(), &noop);
        render(&mut app);
        app.on_key(KeyCode::Down);
        render(&mut app);
        assert_eq!(app.selected.as_deref(), Some("phone"));
        app.on_key(KeyCode::Char('f'));
        app.sample_finder();
        let screen = render(&mut app);
        assert!(screen.contains("Finder"), "{screen}");
        assert!(screen.contains("My phone"), "{screen}");
        assert!(screen.contains("-40 dBm"), "{screen}");
        // q leaves the finder and does not quit.
        assert!(app.on_key(KeyCode::Char('q')));
        assert!(app.finder.is_none());
        assert!(!app.on_key(KeyCode::Char('q')));
    }

    #[test]
    fn network_view_starts_the_sweep_once_and_shows_the_result() {
        let starts = StdCell::new(0);
        let start = || starts.set(starts.get() + 1);
        let mut app = App::new(session(), &start);
        app.on_key(KeyCode::Char('l'));
        assert_eq!(starts.get(), 0, "l does nothing outside the network view");
        app.on_key(KeyCode::Tab);
        assert!(render(&mut app).contains("Press l to start the sweep."));
        app.on_key(KeyCode::Char('l'));
        app.on_key(KeyCode::Char('l'));
        assert_eq!(starts.get(), 1);
        assert!(render(&mut app).contains("The sweep runs"));

        app.on_app_event(AppEvent::Lan(Ok(LanReport {
            networks: vec!["192.168.1.0/24 (en0)".into()],
            addresses_probed: 253,
            seconds: 5.5,
            hosts: vec![LanHost {
                ip: Ipv4Addr::new(192, 168, 1, 64),
                mac: Some("aa:bb:cc:dd:ee:ff".into()),
                vendor: Some("Some Maker".into()),
                camera_vendor: false,
                verdict: Verdict::Likely,
                open_ports: vec![OpenPort { port: 554, meaning: "RTSP video stream" }],
                rtsp: Some("Hipcam".into()),
                onvif: None,
            }],
            others: vec![Neighbour {
                ip: Ipv4Addr::new(192, 168, 1, 1),
                mac: "00:11:22:33:44:55".into(),
                vendor: Some("Router Maker".into()),
                note: None,
            }],
        })));
        let screen = render(&mut app);
        assert!(screen.contains("LIKELY"), "{screen}");
        assert!(screen.contains("192.168.1.64"), "{screen}");
        assert!(screen.contains("RTSP server: Hipcam; port 554"), "{screen}");
        assert!(screen.contains("vendor: Some Maker"), "{screen}");
        assert!(screen.contains("1 other host(s) answered"), "{screen}");
        // Other hosts show only after the user asks for them.
        assert!(!screen.contains("Router Maker"), "{screen}");
        app.on_key(KeyCode::Char('a'));
        assert!(render(&mut app).contains("Router Maker"));
    }

    #[test]
    fn followers_view_reads_the_log() {
        let noop = || {};
        let mut app = App::new(session(), &noop);
        app.on_key(KeyCode::Char('3'));
        let screen = render(&mut app);
        assert!(screen.contains("My phone"), "{screen}");
        assert!(screen.contains("same ID"), "{screen}");
        // The name key of the same device does not make a second row.
        assert_eq!(screen.matches("My phone").count(), 1, "{screen}");
        assert!(!screen.contains("Desk lamp"), "{screen}");
    }

    #[test]
    fn print_screen() {
        // Run with `cargo test print_screen -- --nocapture` to see the layout.
        let noop = || {};
        let mut app = App::new(session(), &noop);
        app.on_app_event(AppEvent::Ble(BleEvent::Started("CoreBluetooth".into())));
        println!("{}", render(&mut app));
    }

    #[test]
    fn signal_scale() {
        assert_eq!(signal_percent(-120.0), 0);
        assert_eq!(signal_percent(-100.0), 0);
        assert_eq!(signal_percent(-35.0), 100);
        assert_eq!(signal_percent(-10.0), 100);
        assert_eq!(bar(0, 8), "░░░░░░░░");
        assert_eq!(bar(100, 8), "████████");
        assert_eq!(bar(50, 8), "████░░░░");
    }

    #[test]
    fn ages_and_distances() {
        assert_eq!(format_age(Duration::from_secs(5)), "5s");
        assert_eq!(format_age(Duration::from_secs(125)), "2m");
        assert_eq!(format_age(Duration::from_secs(7300)), "2h");
        assert_eq!(format_age(Duration::from_secs(200_000)), "2d");
        assert_eq!(format_distance(0.04), "<0.5 m");
        assert_eq!(format_distance(1.23), "1.2 m");
        assert_eq!(format_distance(14.6), "15 m");
        assert_eq!(format_distance(109.0), ">30 m");
    }
}

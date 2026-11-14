//! Terminal interface.

use std::collections::VecDeque;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use ratatui::backend::Backend;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Gauge, Paragraph, Row, Sparkline, Table, TableState, Tabs, Wrap};
use ratatui::{Frame, Terminal};

use crate::ble::BleEvent;
use crate::identity::Basis;
use crate::lan::{LanHost, LanReport, Neighbour, Verdict};
use crate::model::uuid_label;
use crate::session::{Device, Follow, Session, follow_text};
use crate::signatures::Level;
use crate::store::Follower;
use crate::vendors;

pub enum AppEvent {
    Ble(BleEvent),
    Lan(Result<LanReport, String>),
}

/// A device that was silent for this time shows dim.
pub(crate) const STALE_AFTER: Duration = Duration::from_secs(30);
/// Time between two finder samples, and between two redraws.
pub(crate) const TICK: Duration = Duration::from_millis(200);
pub(crate) const FINDER_SAMPLES: usize = 120;

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

/// Run the interface on `terminal` until the user quits. `start_lan` starts
/// one network sweep, whose result must arrive as `AppEvent::Lan`.
/// `next_key` waits up to the given time for one key event.
pub(crate) fn run<B: Backend>(
    terminal: &mut Terminal<B>,
    session: Session,
    events: Receiver<AppEvent>,
    start_lan: &dyn Fn(),
    next_key: &mut dyn FnMut(Duration) -> Result<Option<KeyEvent>>,
) -> Result<()>
where
    B::Error: Send + Sync + 'static,
{
    App::new(session, start_lan).event_loop(terminal, events, next_key)
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

    /// Draw, handle events and handle keys until the user quits. `next_key`
    /// waits up to the given time for one key event.
    fn event_loop<B: Backend>(
        &mut self,
        terminal: &mut Terminal<B>,
        events: Receiver<AppEvent>,
        next_key: &mut dyn FnMut(Duration) -> Result<Option<KeyEvent>>,
    ) -> Result<()>
    where
        B::Error: Send + Sync + 'static,
    {
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
            if let Some(key) = next_key(TICK)?
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
        let finding = finding_text(&self.session, device);
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
            lines.push(Line::from(format!("{} Press m if it is yours.", follow_warning(follow))).yellow());
        }
        if device.hits.is_empty() && device.follow().is_none() {
            lines.push(Line::from("No finding for this device.").dim());
        }

        lines.extend(detail_fields(device).into_iter().map(|(label, value)| field(label, value)));
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

        let FinderReading { stale, percent, label } = FinderReading::of(device);
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
                    Row::new([
                        Cell::from(""),
                        Cell::from(other.ip.to_string()),
                        Cell::from(other.mac.clone()),
                        Cell::from(neighbour_detail(other)),
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

pub(crate) fn level_tag(level: Level) -> &'static str {
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

/// The finding column of the device list: the top signature, the other
/// places and the "known" mark.
pub(crate) fn finding_text(session: &Session, device: &Device) -> String {
    let mut finding = session.top_signature(device).map(|sig| sig.name.clone()).unwrap_or_default();
    if let Some(follow) = device.follow() {
        let follow = follow_text(follow);
        finding = if finding.is_empty() { follow } else { format!("{finding}; {follow}") };
    }
    if device.known {
        finding = if finding.is_empty() { "known".into() } else { format!("known · {finding}") };
    }
    finding
}

/// "This device was seen at 2 other place(s), same name. A different device
/// of the same model can have this name."
pub(crate) fn follow_warning(follow: Follow) -> String {
    let caution = match follow.basis {
        Basis::Name => " A different device of the same model can have this name.",
        Basis::Data => " A different device of the same model can send this data.",
        _ => "",
    };
    format!("This device was {}.{caution}", follow_text(follow))
}

/// The raw data of a device, as label and value pairs.
pub(crate) fn detail_fields(device: &Device) -> Vec<(&'static str, String)> {
    let advert = &device.advert;
    let mut fields = vec![("Name", advert.name.clone().unwrap_or_else(|| "(no name)".into()))];
    let id = match &advert.address {
        Some(address) => format!("{address}  ({})", advert.id),
        None => format!("{}  (the system hides the address)", advert.id),
    };
    fields.push(("ID", id));
    for (company, data) in &advert.manufacturer_data {
        let vendor = vendors::company(*company).unwrap_or("unknown company");
        fields.push(("Maker data", format!("{company:#06x} {vendor}: {}", hex_short(data, 24))));
    }
    for uuid in &advert.services {
        fields.push(("Service", with_owner(uuid)));
    }
    for (uuid, data) in &advert.service_data {
        fields.push(("Svc data", format!("{}: {}", with_owner(uuid), hex_short(data, 24))));
    }
    fields.push((
        "Stats",
        format!(
            "{} updates, first seen {} ago{}",
            device.updates,
            format_age(device.first_seen.elapsed()),
            advert.tx_power.map(|p| format!(", TX power {p} dBm")).unwrap_or_default()
        ),
    ));
    fields
}

/// What the finder shows for one device.
pub(crate) struct FinderReading {
    /// No signal for some seconds.
    pub stale: bool,
    pub percent: u16,
    pub label: String,
}

impl FinderReading {
    pub(crate) fn of(device: &Device) -> Self {
        let stale = device.age() > Duration::from_secs(5);
        let percent = device.rssi_avg.map(signal_percent).unwrap_or(0);
        let label = match (device.rssi_avg, device.distance_m()) {
            _ if stale => format!("no signal for {}", format_age(device.age())),
            (Some(rssi), Some(distance)) => {
                format!("{rssi:.0} dBm   about {}", format_distance(distance))
            }
            _ => "no signal value".into(),
        };
        FinderReading { stale, percent, label }
    }
}

/// The vendor and note of a network host without camera evidence.
pub(crate) fn neighbour_detail(other: &Neighbour) -> String {
    match (&other.vendor, other.note) {
        (Some(vendor), Some(note)) => format!("{vendor} ({note})"),
        (Some(vendor), None) => vendor.clone(),
        (None, Some(note)) => note.to_string(),
        (None, None) => "unknown vendor".to_string(),
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
    use crate::lan::{Neighbour, Onvif, OpenPort};
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

    /// `start_lan` for tests that do not count the sweeps.
    fn noop() {}

    fn render(app: &mut App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        screen_of(&terminal)
    }

    #[test]
    fn device_view_lists_findings_in_order() {
        let mut app = App::new(session(), &noop);
        let screen = render(&mut app);
        let row = |needle: &str| {
            let position = screen.lines().position(|l| l.contains(needle));
            assert!(position.is_some(), "{needle} missing:\n{screen}");
            position.unwrap()
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
        let mut app = App::new(session(), &noop);
        app.on_key(KeyCode::Char('3'));
        let screen = render(&mut app);
        assert!(screen.contains("My phone"), "{screen}");
        assert!(screen.contains("same ID"), "{screen}");
        // The name key of the same device does not make a second row.
        assert_eq!(screen.matches("My phone").count(), 1, "{screen}");
        assert!(!screen.contains("Desk lamp"), "{screen}");
    }

    fn press(code: KeyCode) -> Option<KeyEvent> {
        Some(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn screen_of(terminal: &Terminal<TestBackend>) -> String {
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

    fn text_of(lines: &[Line]) -> String {
        lines.iter().map(|line| line.to_string()).collect::<Vec<_>>().join("\n")
    }

    /// Run the event loop with a list of key results. The list must end the loop.
    fn run_keys(
        app: &mut App,
        events: Receiver<AppEvent>,
        keys: Vec<Result<Option<KeyEvent>>>,
    ) -> (Result<()>, String) {
        let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
        let mut keys = VecDeque::from(keys);
        let result = app.event_loop(&mut terminal, events, &mut |wait| {
            assert_eq!(wait, TICK);
            keys.pop_front().expect("the loop must end before the keys do")
        });
        (result, screen_of(&terminal))
    }

    #[test]
    fn event_loop_reads_events_and_keys_until_quit() {
        let mut app = App::new(session(), &noop);
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(AppEvent::Ble(BleEvent::Started("hci0".into()))).unwrap();
        tx.send(AppEvent::Ble(BleEvent::Advert(Advert { id: "new".into(), ..Default::default() }))).unwrap();
        let mut release = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        release.kind = KeyEventKind::Release;
        let keys = vec![Ok(None), Ok(Some(release)), Ok(press(KeyCode::Tab)), Ok(press(KeyCode::Char('q')))];
        let (result, screen) = run_keys(&mut app, rx, keys);
        result.unwrap();
        // The release of q did not quit, and Tab changed the view before q quit.
        assert!(app.view == View::Network);
        assert!(app.session.get("new").is_some());
        assert!(screen.contains("scanning (hci0)"), "{screen}");
        assert!(screen.contains("Press l to start the sweep."), "{screen}");
    }

    #[test]
    fn run_quits_on_q() {
        let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
        let (_tx, rx) = std::sync::mpsc::channel();
        run(&mut terminal, session(), rx, &noop, &mut |_| Ok(press(KeyCode::Char('q')))).unwrap();
        assert!(screen_of(&terminal).contains("1 Bluetooth"));
    }

    #[test]
    fn ctrl_c_quits_also_in_the_finder() {
        let mut app = App::new(session(), &noop);
        app.finder = Some("phone".into());
        let (_tx, rx) = std::sync::mpsc::channel();
        let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        // A plain c does nothing in the finder.
        let keys = vec![Ok(press(KeyCode::Char('c'))), Ok(Some(ctrl_c))];
        let (result, screen) = run_keys(&mut app, rx, keys);
        result.unwrap();
        assert!(app.finder.is_some());
        assert!(screen.contains("Finder"), "{screen}");
    }

    #[test]
    fn key_errors_end_the_loop() {
        let mut app = App::new(session(), &noop);
        let (_tx, rx) = std::sync::mpsc::channel();
        let (result, _) = run_keys(&mut app, rx, vec![Err(anyhow::anyhow!("no terminal"))]);
        assert_eq!(result.unwrap_err().to_string(), "no terminal");
    }

    #[test]
    fn finder_samples_the_signal_each_tick() {
        let mut app = App::new(session(), &noop);
        app.finder = Some("phone".into());
        let (_tx, rx) = std::sync::mpsc::channel();
        let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
        let mut calls = 0;
        app.event_loop(&mut terminal, rx, &mut |_| {
            calls += 1;
            if calls == 1 {
                std::thread::sleep(TICK);
                return Ok(None);
            }
            Ok(Some(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)))
        })
        .unwrap();
        // -40 dBm is 92 percent.
        assert_eq!(app.finder_history, [92]);
    }

    #[test]
    fn bluetooth_and_sweep_events_change_the_status() {
        let mut app = App::new(session(), &noop);
        let header = |app: &mut App| render(app).lines().next().unwrap().to_string();
        assert!(header(&mut app).contains("Bluetooth: starting"));
        app.on_app_event(AppEvent::Ble(BleEvent::Power(true)));
        assert!(app.ble_ok);
        assert!(header(&mut app).contains("Bluetooth: scanning"));
        app.on_app_event(AppEvent::Ble(BleEvent::Power(false)));
        assert!(!app.ble_ok);
        assert!(header(&mut app).contains("Bluetooth is off"));
        app.on_app_event(AppEvent::Ble(BleEvent::Failed("no adapter".into())));
        assert!(header(&mut app).contains("failed: no adapter"));

        app.session.store_error = Some("disk full".into());
        assert!(header(&mut app).contains("log error: disk full"));

        app.on_key(KeyCode::Char('2'));
        app.on_key(KeyCode::Char('l'));
        assert!(matches!(app.lan, LanState::Running(_)));
        app.on_app_event(AppEvent::Lan(Err("no private IPv4 network found".into())));
        let screen = render(&mut app);
        assert!(screen.contains("The sweep failed: no private IPv4 network found"), "{screen}");
        assert!(screen.contains("Press l to try again."), "{screen}");
    }

    #[test]
    fn views_cycle_with_tab_and_numbers() {
        let mut app = App::new(session(), &noop);
        let footer = |app: &mut App| render(app).lines().rev().nth(1).unwrap().to_string();
        assert!(footer(&mut app).contains("m mark as known"));
        app.on_key(KeyCode::Tab);
        assert!(app.view == View::Network);
        assert!(footer(&mut app).contains("l start the sweep"));
        app.on_key(KeyCode::Tab);
        assert!(app.view == View::Followers);
        assert!(footer(&mut app).trim_end().ends_with("Tab view   q quit"));
        app.on_key(KeyCode::Tab);
        assert!(app.view == View::Devices);
        app.on_key(KeyCode::Char('3'));
        assert!(app.view == View::Followers);
        // Device keys do nothing in the other views.
        app.on_key(KeyCode::Down);
        app.on_key(KeyCode::Char('m'));
        assert_eq!(app.selected.as_deref(), Some("glasses"));
        assert!(!app.session.get("glasses").unwrap().known);
        app.on_key(KeyCode::Char('1'));
        assert!(app.view == View::Devices);
    }

    #[test]
    fn empty_lists_explain_themselves() {
        let db = Arc::new(SignatureDb::embedded().unwrap());
        let mut app = App::new(Session::new(db, None, "office".into()), &noop);
        assert!(render(&mut app).contains("No devices yet."));
        app.on_key(KeyCode::Down);
        assert_eq!(app.selected, None);
        // m and f without a selection do nothing.
        app.on_key(KeyCode::Char('m'));
        app.on_key(KeyCode::Enter);
        assert!(app.finder.is_none());
        app.on_key(KeyCode::Char('a'));
        assert!(render(&mut app).contains("No flagged devices. Press a to show all devices."));
        app.on_key(KeyCode::Char('3'));
        assert!(render(&mut app).contains("The log is off, so there is no history."));

        let db = Arc::new(SignatureDb::embedded().unwrap());
        let store = Store::in_memory().unwrap();
        let mut app = App::new(Session::new(db, Some(store), "office".into()), &noop);
        app.on_key(KeyCode::Char('3'));
        assert!(render(&mut app).contains("No device was seen at two or more places."));
    }

    #[test]
    fn followers_without_a_name() {
        let db = Arc::new(SignatureDb::embedded().unwrap());
        let store = Store::in_memory().unwrap();
        store.record("id:anon", "home", None, None, None).unwrap();
        store.record("id:anon", "gym", None, None, None).unwrap();
        let mut app = App::new(Session::new(db, Some(store), "office".into()), &noop);
        app.on_key(KeyCode::Char('3'));
        let screen = render(&mut app);
        assert!(screen.contains("(no name)"), "{screen}");
        assert!(screen.contains("id:anon"), "{screen}");
    }

    #[test]
    fn selection_moves_up_and_stops_at_the_ends() {
        let mut app = App::new(session(), &noop);
        app.on_key(KeyCode::Char('k'));
        assert_eq!(app.selected.as_deref(), Some("glasses"));
        app.on_key(KeyCode::Up);
        assert_eq!(app.selected.as_deref(), Some("glasses"));
        for _ in 0..10 {
            app.on_key(KeyCode::Char('j'));
        }
        assert_eq!(app.selected.as_deref(), Some("lamp"));
        app.on_key(KeyCode::Up);
        assert_eq!(app.selected.as_deref(), Some("tile"));
    }

    #[test]
    fn known_device_and_stale_device_rows() {
        let mut session = session();
        let long_ago = Instant::now().checked_sub(Duration::from_secs(90)).unwrap();
        session.ingest_at(
            Advert { id: "old".into(), name: Some("Old speaker".into()), ..Default::default() },
            long_ago,
        );
        let mut app = App::new(session, &noop);
        app.selected = Some("lamp".into());
        app.on_key(KeyCode::Char('m'));
        let screen = render(&mut app);
        let row = |needle: &str| screen.lines().find(|l| l.contains(needle)).unwrap().to_string();
        assert!(row("Desk lamp").contains("known"), "{screen}");
        assert!(row("Old speaker").contains("1m"), "{screen}");
        // A device without a signal value has no signal bar and no distance.
        assert!(!row("Old speaker").contains("dBm"), "{screen}");
    }

    #[test]
    fn finder_states() {
        let mut session = session();
        let long_ago = Instant::now().checked_sub(Duration::from_secs(90)).unwrap();
        session.ingest_at(Advert { id: "old".into(), rssi: Some(-50), ..Default::default() }, long_ago);
        session.ingest(Advert { id: "quiet".into(), ..Default::default() });
        session.ingest(Advert { id: "far".into(), rssi: Some(-90), ..Default::default() });
        let mut app = App::new(session, &noop);

        let finder = |app: &mut App, id: &str| {
            app.selected = Some(id.into());
            app.on_key(KeyCode::Enter);
            let screen = render(app);
            app.on_key(KeyCode::Esc);
            assert!(app.finder.is_none());
            screen
        };
        assert!(finder(&mut app, "old").contains("no signal for 1m"));
        assert!(finder(&mut app, "quiet").contains("no signal value"));
        assert!(finder(&mut app, "far").contains("-90 dBm"));
        assert!(finder(&mut app, "glasses").contains("-70 dBm"));
        let screen = finder(&mut app, "phone");
        assert!(screen.contains("f/Esc leave the finder"), "{screen}");

        app.finder = Some("gone".into());
        app.sample_finder();
        assert!(app.finder_history.is_empty());
        assert!(render(&mut app).contains("The device is gone."));

        app.finder = Some("phone".into());
        for _ in 0..FINDER_SAMPLES + 5 {
            app.sample_finder();
        }
        assert_eq!(app.finder_history.len(), FINDER_SAMPLES);
        assert!(app.on_key(KeyCode::Char('f')));
        assert!(app.finder.is_none());
        assert!(app.finder_history.is_empty());
    }

    #[test]
    fn details_show_all_advert_fields() {
        let mut session = session();
        let mut advert = Advert {
            id: "full".into(),
            address: Some("aa:bb:cc:dd:ee:ff".into()),
            tx_power: Some(-8),
            ..Default::default()
        };
        advert.manufacturer_data.insert(0xFFFE, vec![0xAB; 30]);
        advert.services.push(parse_uuid("feed").unwrap());
        advert.services.push(parse_uuid("12345678-1234-1234-1234-123456789abc").unwrap());
        advert.service_data.insert(parse_uuid("feed").unwrap(), vec![1, 2]);
        session.ingest(advert);
        let app = App::new(session, &noop);
        let device = app.session.get("full").unwrap();
        let text = text_of(&app.detail_lines(device));
        assert!(text.contains("Tile tracker"), "{text}");
        assert!(text.contains("A Tile sends the same frame"), "{text}");
        assert!(text.contains("aa:bb:cc:dd:ee:ff  (full)"), "{text}");
        assert!(text.contains("0xfffe unknown company: "), "{text}");
        assert!(text.contains("… (30 bytes)"), "{text}");
        assert!(text.contains("feed (Tile, Inc.)"), "{text}");
        assert!(text.contains("12345678-1234-1234-1234-123456789abc"), "{text}");
        assert!(text.contains("Svc data"), "{text}");
        assert!(text.contains("TX power -8 dBm"), "{text}");

        let lamp = app.session.get("lamp").unwrap();
        let text = text_of(&app.detail_lines(lamp));
        assert!(text.contains("No finding for this device."), "{text}");
        assert!(text.contains("the system hides the address"), "{text}");
    }

    #[test]
    fn details_of_a_signature_without_notes() {
        let mut session = session();
        let mut advert = Advert { id: "quest".into(), ..Default::default() };
        advert.manufacturer_data.insert(0x058E, vec![1]);
        session.ingest(advert);
        let app = App::new(session, &noop);
        let text = text_of(&app.detail_lines(app.session.get("quest").unwrap()));
        let lines: Vec<&str> = text.lines().collect();
        let name =
            lines.iter().position(|line| line.contains("Meta device (glasses or Quest headset)")).unwrap();
        // The source follows the name at once, because there are no notes.
        assert!(lines[name + 1].trim_start().starts_with("Source: Company IDs 0x058E"), "{text}");
    }

    #[test]
    fn details_warn_when_a_name_or_payload_match_can_be_another_device() {
        let db = Arc::new(SignatureDb::embedded().unwrap());
        let mut payload = Advert { id: "id-2".into(), rssi: Some(-50), ..Default::default() };
        payload.manufacturer_data.insert(0x0075, vec![0x42, 4, 1, 0x80, 0x60, 0xCC, 0x6E]);
        let named = Advert { id: "id-3".into(), name: Some("Key tag".into()), ..Default::default() };

        let store = Store::in_memory().unwrap();
        for key in crate::identity::keys(&payload, true).iter().chain(&crate::identity::keys(&named, false)) {
            if key.basis != crate::identity::Basis::Id {
                store.record(&key.text, "home", None, None, None).unwrap();
            }
        }
        let mut session = Session::new(db, Some(store), "office".into());
        let start = Instant::now();
        session.ingest_at(payload.clone(), start);
        session.ingest_at(payload, start + Duration::from_secs(61));
        session.ingest(named);
        let app = App::new(session, &noop);

        let text = text_of(&app.detail_lines(app.session.get("id-2").unwrap()));
        assert!(
            text.contains("same data. A different device of the same model can send this data."),
            "{text}"
        );
        let text = text_of(&app.detail_lines(app.session.get("id-3").unwrap()));
        assert!(
            text.contains("same name. A different device of the same model can have this name."),
            "{text}"
        );
    }

    #[test]
    fn network_results_without_evidence_and_with_weak_evidence() {
        let mut app = App::new(session(), &noop);
        app.on_key(KeyCode::Char('2'));
        app.on_app_event(AppEvent::Lan(Ok(LanReport {
            networks: vec!["10.0.0.0/24 (en0)".into()],
            addresses_probed: 253,
            seconds: 4.0,
            hosts: vec![],
            others: vec![],
        })));
        let screen = render(&mut app);
        assert!(screen.contains("No camera evidence found. 0 other host(s) answered."), "{screen}");

        let other = |last: u8, vendor: Option<&str>, note: Option<&'static str>| Neighbour {
            ip: Ipv4Addr::new(10, 0, 0, last),
            mac: format!("00:11:22:33:44:{last:02x}"),
            vendor: vendor.map(str::to_string),
            note,
        };
        app.on_app_event(AppEvent::Lan(Ok(LanReport {
            networks: vec!["10.0.0.0/24 (en0)".into()],
            addresses_probed: 253,
            seconds: 4.0,
            hosts: vec![LanHost {
                ip: Ipv4Addr::new(10, 0, 0, 9),
                mac: None,
                vendor: None,
                camera_vendor: false,
                verdict: Verdict::Possible,
                open_ports: vec![OpenPort { port: 8000, meaning: "Hikvision device port" }],
                rtsp: None,
                onvif: None,
            }],
            others: vec![
                other(2, Some("Espressif Inc."), Some("Wi-Fi chip")),
                other(3, None, Some("private address")),
                other(4, None, None),
            ],
        })));
        app.on_key(KeyCode::Char('a'));
        let screen = render(&mut app);
        assert!(screen.contains("1 host(s) with camera evidence. 3 other host(s) answered."), "{screen}");
        assert!(screen.contains("maybe"), "{screen}");
        assert!(screen.contains("port 8000 (Hikvision device port)"), "{screen}");
        assert!(screen.contains("Espressif Inc. (Wi-Fi chip)"), "{screen}");
        assert!(screen.contains("private address"), "{screen}");
        assert!(screen.contains("unknown vendor"), "{screen}");
    }

    #[test]
    fn evidence_text_for_camera_makers_and_onvif() {
        let host = LanHost {
            ip: Ipv4Addr::new(10, 0, 0, 9),
            mac: None,
            vendor: Some("Hangzhou Hikvision".into()),
            camera_vendor: true,
            verdict: Verdict::Likely,
            open_ports: vec![],
            rtsp: Some("yes".into()),
            onvif: Some(Onvif { name: Some("Door".into()), hardware: Some("DS-2".into()), address: None }),
        };
        assert_eq!(
            lan_evidence(&host),
            "camera maker: Hangzhou Hikvision; ONVIF camera: Door / DS-2; RTSP server"
        );
        let bare = LanHost { vendor: None, rtsp: None, onvif: Some(Onvif::default()), ..host };
        assert_eq!(lan_evidence(&bare), "ONVIF camera");
    }

    #[test]
    fn level_tags_and_styles() {
        let levels = [Level::High, Level::Medium, Level::Low, Level::Info];
        let tags: Vec<&str> = levels.into_iter().map(level_tag).collect();
        assert_eq!(tags, ["HIGH", "MED", "low", "info"]);
        assert_eq!(level_style(Some(Level::Low)), Style::new().cyan());
        assert_eq!(level_style(Some(Level::Info)), Style::new());
        assert_eq!(level_style(None), Style::new());
    }

    #[test]
    fn print_screen() {
        // Run with `cargo test print_screen -- --nocapture` to see the layout.
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

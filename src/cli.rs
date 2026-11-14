//! The command line. It reaches the radio, the network and the terminal
//! only through [`Hardware`], so tests can run each command with fakes.

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use futures::future::BoxFuture;
use serde_json::json;

use crate::ble::BleEvent;
use crate::lan::{LanReport, Verdict};
use crate::model::uuid_label;
use crate::place;
use crate::session::{Session, follow_text};
use crate::signatures::SignatureDb;
use crate::store::{self, Store};
use crate::tui::{AppEvent, format_age, format_distance, lan_evidence};

/// The parts of the machine that the commands use.
pub trait Hardware: Sync {
    /// Scan Bluetooth and give each event to `emit`, until `emit` returns
    /// `false` or the scan ends.
    fn ble(&self, emit: Box<dyn Fn(BleEvent) -> bool + Send + Sync>) -> BoxFuture<'static, ()>;
    /// Sweep the local network for cameras.
    fn lan(&self) -> BoxFuture<'static, Result<LanReport>>;
    /// Run the terminal interface until the user quits. `start_lan` starts
    /// one network sweep, whose result arrives as `AppEvent::Lan`.
    fn terminal(&self, session: Session, events: Receiver<AppEvent>, start_lan: &dyn Fn()) -> Result<()>;
}

/// A radio check for trackers, cameras, recorders and smart glasses.
///
/// Without a subcommand, bugsweep opens the terminal interface.
#[derive(Parser)]
#[command(name = "bugsweep", version)]
struct Cli {
    /// Name of the current place, for example "home" or "hotel-rome".
    /// The default is a key made from the local network.
    #[arg(long, global = true)]
    place: Option<String>,
    /// Use this signature file and not the built-in database.
    #[arg(long, global = true, value_name = "FILE")]
    signatures: Option<PathBuf>,
    /// Path of the local log database.
    #[arg(long, global = true, value_name = "FILE")]
    db: Option<PathBuf>,
    /// Do not read or write the local log.
    #[arg(long, global = true)]
    no_log: bool,
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan Bluetooth for some seconds and print the result.
    Scan {
        /// Scan time in seconds.
        #[arg(long, short, default_value_t = 15)]
        seconds: u64,
        /// Print JSON.
        #[arg(long)]
        json: bool,
        /// Print only flagged devices.
        #[arg(long)]
        flagged: bool,
    },
    /// Sweep the local network for cameras. Sends connection attempts to
    /// each address, so use it only where you are allowed to.
    Lan {
        /// Print JSON.
        #[arg(long)]
        json: bool,
        /// Also list the hosts without camera evidence.
        #[arg(long)]
        all: bool,
    },
    /// List devices that the log has at two or more places.
    Followers,
    /// List the signature database.
    Signatures,
}

/// Standard output and standard error of a command.
pub struct Output<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
}

/// Parse the arguments and run the command. A parse error, `--help` and
/// `--version` come back as a [`clap::Error`].
pub fn run(args: Vec<OsString>, hardware: &dyn Hardware, io: Output) -> Result<()> {
    let cli = Cli::try_parse_from(args)?;
    let db = Arc::new(match &cli.signatures {
        Some(path) => SignatureDb::from_file(path)?,
        None => SignatureDb::embedded()?,
    });

    match &cli.command {
        Some(Cmd::Signatures) => list_signatures(&db, io.out),
        Some(Cmd::Lan { json, all }) => run_lan(hardware, *json, *all, io),
        Some(Cmd::Followers) => {
            let Some(store) = open_store(&cli)? else {
                bail!("the log is off (--no-log)");
            };
            list_followers(&store, io.out)
        }
        Some(Cmd::Scan { seconds, json, flagged }) => {
            let session = new_session(&cli, db)?;
            run_scan(hardware, session, *seconds, *json, *flagged, io)
        }
        None => {
            let session = new_session(&cli, db)?;
            run_tui(hardware, session)
        }
    }
}

fn open_store(cli: &Cli) -> Result<Option<Store>> {
    if cli.no_log {
        return Ok(None);
    }
    let path = match &cli.db {
        Some(path) => path.clone(),
        None => store::default_path().context("cannot find a data directory; use --db")?,
    };
    Store::open(&path).map(Some)
}

fn new_session(cli: &Cli, db: Arc<SignatureDb>) -> Result<Session> {
    let store = open_store(cli)?;
    let place = cli.place.clone().unwrap_or_else(place::detect);
    Ok(Session::new(db, store, place))
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("cannot start the async runtime")
}

fn run_tui(hardware: &dyn Hardware, session: Session) -> Result<()> {
    let runtime = runtime()?;
    let (tx, rx) = mpsc::channel::<AppEvent>();

    let ble_tx = tx.clone();
    runtime.spawn(hardware.ble(Box::new(move |event| ble_tx.send(AppEvent::Ble(event)).is_ok())));

    let handle = runtime.handle().clone();
    let start_lan = move || {
        let lan_tx = tx.clone();
        let sweep = hardware.lan();
        handle.spawn(async move {
            let result = sweep.await.map_err(|error| format!("{error:#}"));
            let _ = lan_tx.send(AppEvent::Lan(result));
        });
    };

    let result = hardware.terminal(session, rx, &start_lan);
    runtime.shutdown_timeout(Duration::from_millis(300));
    result
}

/// Give the Bluetooth events to `session` until `deadline`. Returns the
/// reason when the scan failed.
fn collect(session: &mut Session, events: &Receiver<BleEvent>, deadline: Instant) -> Option<String> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        match events.recv_timeout(left) {
            Ok(BleEvent::Advert(advert)) => session.ingest(advert),
            Ok(BleEvent::Failed(error)) => return Some(error),
            Ok(BleEvent::Power(false)) => return Some("Bluetooth is off".to_string()),
            Ok(_) => {}
            Err(_) => return None,
        }
    }
}

fn run_scan(
    hardware: &dyn Hardware,
    mut session: Session,
    seconds: u64,
    as_json: bool,
    flagged_only: bool,
    io: Output,
) -> Result<()> {
    if !as_json {
        writeln!(io.err, "Scanning Bluetooth for {seconds} s at place {:?}…", session.place)?;
    }
    let runtime = runtime()?;
    let (tx, rx) = mpsc::channel::<BleEvent>();
    runtime.spawn(hardware.ble(Box::new(move |event| tx.send(event).is_ok())));
    let failure = collect(&mut session, &rx, Instant::now() + Duration::from_secs(seconds));
    drop(rx);
    runtime.shutdown_timeout(Duration::from_millis(300));
    if let Some(error) = failure {
        bail!("Bluetooth scan failed: {error}");
    }

    if as_json {
        print_scan_json(&session, flagged_only, io.out)
    } else {
        print_scan_table(&session, flagged_only, io)
    }
}

fn print_scan_json(session: &Session, flagged_only: bool, out: &mut dyn Write) -> Result<()> {
    let list: Vec<_> = session
        .sorted(!flagged_only)
        .iter()
        .map(|device| {
            let advert = &device.advert;
            json!({
                "id": advert.id,
                "address": advert.address,
                "name": advert.name,
                "vendor": device.vendor(),
                "rssi": device.rssi_avg.map(|r| r.round() as i32),
                "distance_m": device.distance_m().map(|d| (d * 10.0).round() / 10.0),
                "level": session.level(device).map(|l| l.label()),
                "flagged": session.is_flagged(device),
                "known": device.known,
                "other_places": device.follow().map(|f| f.places).unwrap_or(0),
                "other_places_match": device.follow().map(|f| f.basis.label()),
                "findings": device.hits.iter().map(|&i| session.db().get(i).id.clone()).collect::<Vec<_>>(),
                "company_ids": advert.manufacturer_data.keys().map(|id| format!("{id:#06x}")).collect::<Vec<_>>(),
                "services": advert.services.iter().map(uuid_label).collect::<Vec<_>>(),
                "service_data": advert.service_data.keys().map(uuid_label).collect::<Vec<_>>(),
            })
        })
        .collect();
    writeln!(out, "{}", serde_json::to_string_pretty(&json!({ "place": session.place, "devices": list }))?)?;
    Ok(())
}

fn print_scan_table(session: &Session, flagged_only: bool, io: Output) -> Result<()> {
    let devices = session.sorted(!flagged_only);
    writeln!(io.out, "{:<6} {:<9} {:<30} {:>8} {:>7}  FINDING", "LEVEL", "TYPE", "DEVICE", "SIGNAL", "DIST")?;
    for device in &devices {
        let signature = session.top_signature(device);
        let mut finding = signature.map(|sig| sig.name.clone()).unwrap_or_default();
        if let Some(follow) = device.follow() {
            finding = format!("{finding} [{}]", follow_text(follow));
        }
        if device.known {
            finding = format!("{finding} [known]");
        }
        let mut title = device.title().unwrap_or_else(|| "(no name)".into());
        if title.chars().count() > 30 {
            title = title.chars().take(29).chain(['…']).collect();
        }
        writeln!(
            io.out,
            "{:<6} {:<9} {:<30} {:>8} {:>7}  {}",
            session.level(device).map(|l| l.label()).unwrap_or("-"),
            signature.map(|sig| sig.category.label()).unwrap_or("-"),
            title,
            device.rssi_avg.map(|r| format!("{r:.0} dBm")).unwrap_or_default(),
            device.distance_m().map(format_distance).unwrap_or_default(),
            finding.trim(),
        )?;
    }
    let flagged = devices.iter().filter(|d| session.is_flagged(d)).count();
    writeln!(io.err, "\n{} device(s), {flagged} flagged.", session.len())?;
    writeln!(io.err, "Radio check only. A device that sends no radio signal stays hidden.")?;
    if session.is_empty() {
        writeln!(
            io.err,
            "No devices at all usually means that the terminal app has no Bluetooth permission.\n\
             On macOS, see System Settings > Privacy & Security > Bluetooth."
        )?;
    }
    if let Some(error) = &session.store_error {
        writeln!(io.err, "Log error: {error}")?;
    }
    Ok(())
}

fn run_lan(hardware: &dyn Hardware, as_json: bool, all: bool, io: Output) -> Result<()> {
    if !as_json {
        writeln!(io.err, "Sweeping the local network for cameras…")?;
    }
    let report = runtime()?.block_on(hardware.lan())?;
    if as_json {
        writeln!(io.out, "{}", serde_json::to_string_pretty(&report)?)?;
        return Ok(());
    }
    writeln!(
        io.out,
        "{} addresses checked in {:.1} s on {}.",
        report.addresses_probed,
        report.seconds,
        report.networks.join(", ")
    )?;
    if report.hosts.is_empty() {
        writeln!(io.out, "No camera evidence found.")?;
    }
    for host in &report.hosts {
        let verdict = match host.verdict {
            Verdict::Likely => "LIKELY",
            Verdict::Possible => "maybe",
        };
        writeln!(
            io.out,
            "{:<7} {:<16} {:<18} {}",
            verdict,
            host.ip,
            host.mac.as_deref().unwrap_or("-"),
            lan_evidence(host)
        )?;
    }
    if all {
        for other in &report.others {
            writeln!(
                io.out,
                "{:<7} {:<16} {:<18} {}{}",
                "-",
                other.ip,
                other.mac,
                other.vendor.as_deref().unwrap_or("unknown vendor"),
                other.note.map(|note| format!(" ({note})")).unwrap_or_default()
            )?;
        }
    } else {
        writeln!(io.out, "{} other host(s) answered. Use --all to list them.", report.others.len())?;
    }
    writeln!(io.err, "A camera on a different network, or one that only records to a card, stays hidden.")?;
    Ok(())
}

fn list_followers(store: &Store, out: &mut dyn Write) -> Result<()> {
    let followers = store.followers()?;
    if followers.is_empty() {
        writeln!(out, "No device was seen at two or more places.")?;
        return Ok(());
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let ago = |then: i64| format_age(Duration::from_secs((now - then).max(0) as u64));
    for follower in followers {
        writeln!(
            out,
            "{}  {}  {}  same {}  places: {}  first seen {} ago, last seen {} ago",
            follower.key,
            follower.title.as_deref().unwrap_or("(no name)"),
            follower.signature.as_deref().unwrap_or("-"),
            follower.basis.label(),
            follower.places.join(", "),
            ago(follower.first_seen),
            ago(follower.last_seen),
        )?;
    }
    Ok(())
}

fn list_signatures(db: &SignatureDb, out: &mut dyn Write) -> Result<()> {
    writeln!(out, "{:<36} {:<9} {:<7} {:<7} {:<9} NAME", "ID", "TYPE", "LEVEL", "CONF.", "EVIDENCE")?;
    for sig in db.all() {
        writeln!(
            out,
            "{:<36} {:<9} {:<7} {:<7} {:<9} {}",
            sig.id,
            sig.category.label(),
            sig.severity.label(),
            sig.confidence.label(),
            sig.evidence.label(),
            sig.name
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::path::Path;
    use std::sync::Mutex;

    use futures::FutureExt;
    use tempfile::TempDir;

    use super::*;
    use crate::lan::{LanHost, Neighbour, Onvif, OpenPort};
    use crate::model::Advert;

    /// A machine that the tests control.
    struct Fake {
        ble: fn() -> Vec<BleEvent>,
        /// After the events, send adverts until the receiver stops, as a
        /// real radio in a busy room does.
        endless: bool,
        lan: fn() -> Result<LanReport>,
        /// What the fake terminal received.
        seen: Mutex<Vec<String>>,
    }

    impl Fake {
        fn new(ble: fn() -> Vec<BleEvent>) -> Self {
            Fake {
                ble,
                endless: false,
                lan: || Ok(report(Vec::new(), Vec::new())),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    fn describe(event: AppEvent) -> String {
        match event {
            AppEvent::Ble(BleEvent::Started(info)) => format!("started {info}"),
            AppEvent::Ble(BleEvent::Power(on)) => format!("power {on}"),
            AppEvent::Ble(BleEvent::Advert(advert)) => format!("advert {}", advert.id),
            AppEvent::Ble(BleEvent::Failed(error)) => format!("failed {error}"),
            AppEvent::Lan(Ok(report)) => format!("lan {} hosts", report.hosts.len()),
            AppEvent::Lan(Err(error)) => format!("lan error {error}"),
        }
    }

    impl Hardware for Fake {
        fn ble(&self, emit: Box<dyn Fn(BleEvent) -> bool + Send + Sync>) -> BoxFuture<'static, ()> {
            let (events, endless) = ((self.ble)(), self.endless);
            async move {
                events.into_iter().for_each(|event| _ = emit(event));
                while endless && emit(BleEvent::Advert(advert("busy", None, Some(-70)))) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
            .boxed()
        }

        fn lan(&self) -> BoxFuture<'static, Result<LanReport>> {
            let result = (self.lan)();
            async move { result }.boxed()
        }

        /// Start a sweep, and read all Bluetooth events and the sweep result.
        fn terminal(&self, session: Session, events: Receiver<AppEvent>, start_lan: &dyn Fn()) -> Result<()> {
            start_lan();
            let count = (self.ble)().len() + 1;
            // A missing event fails the test and does not hang it.
            let wait = Duration::from_secs(10);
            let mut seen: Vec<String> =
                (0..count).map(|_| describe(events.recv_timeout(wait).expect("an event"))).collect();
            seen.sort();
            seen.push(format!("place {}", session.place));
            *self.seen.lock().unwrap() = seen;
            Ok(())
        }
    }

    fn command_line(args: &[&str]) -> Vec<OsString> {
        std::iter::once("bugsweep").chain(args.iter().copied()).map(OsString::from).collect()
    }

    /// Run a command and return its standard output and standard error.
    fn run_with(hardware: &Fake, args: &[&str]) -> Result<(String, String)> {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        run(command_line(args), hardware, Output { out: &mut out, err: &mut err })?;
        Ok((String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap()))
    }

    fn db_arg(dir: &TempDir) -> String {
        dir.path().join("log.db").display().to_string()
    }

    fn advert(id: &str, name: Option<&str>, rssi: Option<i16>) -> Advert {
        Advert { id: id.into(), name: name.map(str::to_string), rssi, ..Advert::default() }
    }

    /// An AirTag away from its owner.
    fn airtag() -> Advert {
        let mut data = vec![0x12, 0x19, 0x10];
        data.extend([0u8; 24]);
        let mut tag = advert("tag-1", None, Some(-55));
        tag.manufacturer_data.insert(0x004C, data);
        tag.services.push(crate::model::parse_uuid("fd44").unwrap());
        tag.service_data.insert(crate::model::parse_uuid("fd44").unwrap(), vec![1]);
        tag
    }

    fn room() -> Vec<BleEvent> {
        vec![
            BleEvent::Started("fake".into()),
            BleEvent::Power(true),
            BleEvent::Advert(airtag()),
            BleEvent::Advert(advert("long", Some("A very long device name that does not fit"), None)),
            BleEvent::Advert(advert("plain", None, Some(-80))),
        ]
    }

    #[test]
    fn scan_prints_a_table() {
        let dir = TempDir::new().unwrap();
        let db = db_arg(&dir);
        // The tag was at home before, and the user knows the plain device.
        run_with(&Fake::new(|| vec![BleEvent::Advert(airtag())]), &["--db", &db, "--place", "home", "scan"])
            .unwrap();
        Store::open(Path::new(&db)).unwrap().set_known("id:plain", None, true).unwrap();

        let (out, err) =
            run_with(&Fake::new(room), &["--db", &db, "--place", "hotel", "scan", "-s", "5"]).unwrap();
        assert!(out.starts_with("LEVEL"), "{out}");
        let tag = out.lines().find(|line| line.contains("Apple AirTag")).unwrap();
        assert!(tag.starts_with("high") && tag.contains("tracker"), "{tag}");
        assert!(tag.contains("[seen at 1 other place(s), same ID]"), "{tag}");
        assert!(tag.contains("-55 dBm"), "{tag}");
        assert!(out.contains("A very long device name that …"), "{out}");
        let plain = out.lines().find(|line| line.contains("(no name)")).unwrap();
        assert!(plain.starts_with("-") && plain.ends_with("[known]"), "{plain}");
        assert!(err.starts_with("Scanning Bluetooth for 5 s at place \"hotel\""), "{err}");
        assert!(err.contains("3 device(s), 1 flagged."), "{err}");
        assert!(!err.contains("No devices at all"), "{err}");

        // Only the flagged device.
        let (out, _) =
            run_with(&Fake::new(room), &["--db", &db, "--place", "hotel", "scan", "--flagged"]).unwrap();
        assert_eq!(out.lines().count(), 2, "{out}");
    }

    #[test]
    fn scan_prints_json() {
        let dir = TempDir::new().unwrap();
        let db = db_arg(&dir);
        run_with(&Fake::new(|| vec![BleEvent::Advert(airtag())]), &["--db", &db, "--place", "home", "scan"])
            .unwrap();
        let (out, err) =
            run_with(&Fake::new(room), &["--db", &db, "--place", "hotel", "scan", "--json", "--flagged"])
                .unwrap();
        assert_eq!(err, "");
        let value: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(value["place"], "hotel");
        let devices = value["devices"].as_array().unwrap();
        assert_eq!(devices.len(), 1);
        let tag = &devices[0];
        assert_eq!(tag["id"], "tag-1");
        assert_eq!(tag["vendor"], "Apple, Inc.");
        assert_eq!(tag["rssi"], -55);
        assert!(tag["distance_m"].as_f64().unwrap() > 0.0);
        assert_eq!(tag["level"], "high");
        assert_eq!(tag["flagged"], true);
        assert_eq!(tag["other_places"], 1);
        assert_eq!(tag["other_places_match"], "ID");
        assert_eq!(tag["findings"][0], "apple-airtag-separated");
        assert_eq!(tag["company_ids"][0], "0x004c");
        assert_eq!(tag["services"][0], tag["service_data"][0]);
    }

    #[test]
    fn scan_ends_at_the_deadline_while_devices_still_send() {
        let busy = Fake { endless: true, ..Fake::new(Vec::new) };
        let started = Instant::now();
        let (out, err) = run_with(&busy, &["--no-log", "--place", "x", "scan", "-s", "1"]).unwrap();
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
        assert!(out.contains("(no name)"), "{out}");
        assert!(err.contains("1 device(s), 0 flagged."), "{err}");
    }

    #[test]
    fn empty_scan_explains_the_permission() {
        // No --place: the place comes from this machine's network.
        let (out, err) = run_with(&Fake::new(Vec::new), &["--no-log", "scan", "--seconds", "0"]).unwrap();
        assert_eq!(out.lines().count(), 1);
        assert!(err.contains("0 device(s), 0 flagged."), "{err}");
        assert!(err.contains("Privacy & Security > Bluetooth"), "{err}");
    }

    #[test]
    fn scan_failures_are_errors() {
        let failed = Fake::new(|| vec![BleEvent::Failed("no Bluetooth adapter found".into())]);
        let error = run_with(&failed, &["--no-log", "--place", "x", "scan"]).unwrap_err();
        assert_eq!(error.to_string(), "Bluetooth scan failed: no Bluetooth adapter found");

        let off = Fake::new(|| vec![BleEvent::Started("fake".into()), BleEvent::Power(false)]);
        let error = run_with(&off, &["--no-log", "--place", "x", "scan"]).unwrap_err();
        assert_eq!(error.to_string(), "Bluetooth scan failed: Bluetooth is off");
    }

    #[test]
    fn scan_reports_log_errors() {
        let dir = TempDir::new().unwrap();
        let db = db_arg(&dir);
        drop(Store::open(Path::new(&db)).unwrap());
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER no_writes BEFORE INSERT ON sightings BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
        )
        .unwrap();
        let (_, err) = run_with(&Fake::new(room), &["--db", &db, "--place", "x", "scan"]).unwrap();
        assert!(err.contains("Log error: disk full"), "{err}");
    }

    #[test]
    fn terminal_gets_bluetooth_and_network_events() {
        let fake = Fake::new(|| vec![BleEvent::Started("fake".into()), BleEvent::Advert(airtag())]);
        run_with(&fake, &["--no-log", "--place", "desk"]).unwrap();
        assert_eq!(*fake.seen.lock().unwrap(), ["advert tag-1", "lan 0 hosts", "started fake", "place desk"]);

        let fake = Fake {
            lan: || bail!("no private IPv4 network found"),
            ..Fake::new(|| vec![BleEvent::Power(false), BleEvent::Failed("gone".into())])
        };
        run_with(&fake, &["--no-log", "--place", "desk"]).unwrap();
        assert_eq!(
            *fake.seen.lock().unwrap(),
            ["failed gone", "lan error no private IPv4 network found", "power false", "place desk"]
        );
    }

    fn report(hosts: Vec<LanHost>, others: Vec<Neighbour>) -> LanReport {
        LanReport {
            networks: vec!["192.168.1.0/24 (en0)".into()],
            addresses_probed: 253,
            seconds: 4.04,
            hosts,
            others,
        }
    }

    fn cameras() -> Result<LanReport> {
        let host = |last, verdict, mac: Option<&str>| LanHost {
            ip: Ipv4Addr::new(192, 168, 1, last),
            mac: mac.map(str::to_string),
            vendor: None,
            camera_vendor: false,
            verdict,
            open_ports: vec![OpenPort { port: 554, meaning: "RTSP video stream" }],
            rtsp: None,
            onvif: Some(Onvif::default()),
        };
        let other = |last, vendor: Option<&str>, note| Neighbour {
            ip: Ipv4Addr::new(192, 168, 1, last),
            mac: format!("00:11:22:00:00:{last:02}"),
            vendor: vendor.map(str::to_string),
            note,
        };
        Ok(report(
            vec![host(5, Verdict::Likely, Some("00:11:22:00:00:05")), host(6, Verdict::Possible, None)],
            vec![other(7, Some("Espressif Inc."), Some("Wi-Fi chip")), other(8, None, None)],
        ))
    }

    fn lan_fake(lan: fn() -> Result<LanReport>) -> Fake {
        Fake { lan, ..Fake::new(Vec::new) }
    }

    #[test]
    fn lan_prints_the_cameras() {
        let (out, err) = run_with(&lan_fake(cameras), &["lan"]).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "253 addresses checked in 4.0 s on 192.168.1.0/24 (en0).");
        assert!(lines[1].starts_with("LIKELY  192.168.1.5      00:11:22:00:00:05  ONVIF camera"), "{out}");
        assert!(lines[2].starts_with("maybe   192.168.1.6      -"), "{out}");
        assert_eq!(lines[3], "2 other host(s) answered. Use --all to list them.");
        assert!(err.starts_with("Sweeping the local network"), "{err}");
        assert!(err.contains("stays hidden"), "{err}");

        let (out, _) = run_with(&lan_fake(cameras), &["lan", "--all"]).unwrap();
        assert!(out.contains("192.168.1.7      00:11:22:00:00:07  Espressif Inc. (Wi-Fi chip)"), "{out}");
        assert!(out.contains("192.168.1.8      00:11:22:00:00:08  unknown vendor\n"), "{out}");
    }

    #[test]
    fn lan_without_cameras() {
        let (out, _) = run_with(&Fake::new(Vec::new), &["lan"]).unwrap();
        assert!(out.contains("No camera evidence found."), "{out}");
    }

    #[test]
    fn lan_prints_json() {
        let (out, err) = run_with(&lan_fake(cameras), &["lan", "--json"]).unwrap();
        assert_eq!(err, "");
        let value: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(value["hosts"][0]["verdict"], "likely");
        assert_eq!(value["others"][1]["mac"], "00:11:22:00:00:08");
    }

    #[test]
    fn lan_errors_pass_through() {
        let fake = lan_fake(|| bail!("no private IPv4 network found"));
        assert_eq!(run_with(&fake, &["lan"]).unwrap_err().to_string(), "no private IPv4 network found");
    }

    #[test]
    fn followers_lists_the_log() {
        let dir = TempDir::new().unwrap();
        let db = db_arg(&dir);
        let store = Store::open(Path::new(&db)).unwrap();
        for place in ["home", "office"] {
            store.record("id:tag-1", place, Some(-50), Some("Tag"), Some("apple-airtag-separated")).unwrap();
            store.record("name:Bob", place, None, None, None).unwrap();
        }
        let (out, _) = run_with(&Fake::new(Vec::new), &["--db", &db, "followers"]).unwrap();
        assert!(
            out.contains("id:tag-1  Tag  apple-airtag-separated  same ID  places: home, office"),
            "{out}"
        );
        assert!(out.contains("name:Bob  (no name)  -  same name"), "{out}");
        // The clock can pass a second boundary while the test runs.
        let ages = ["0s ago, last seen 0s ago", "1s ago, last seen 1s ago", "1s ago, last seen 0s ago"];
        assert!(ages.iter().any(|age| out.contains(&format!("first seen {age}"))), "{out}");
    }

    #[test]
    fn signature_file_replaces_the_built_in_database() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("custom.toml");
        std::fs::write(
            &path,
            "[[signature]]\nid = \"test-tag\"\nname = \"Test tag\"\ncategory = \"tracker\"\n\
             severity = \"high\"\nconfidence = \"low\"\nevidence = \"guess\"\nsource = \"test\"\n\
             [[signature.match]]\nname_regex = \"^TestTag\"\n",
        )
        .unwrap();
        let path = path.display().to_string();
        let (out, _) = run_with(&Fake::new(Vec::new), &["--signatures", &path, "signatures"]).unwrap();
        assert_eq!(out.lines().count(), 2, "{out}");
        assert!(out.contains("test-tag"), "{out}");
        let missing = dir.path().join("missing.toml").display().to_string();
        assert!(run_with(&Fake::new(Vec::new), &["--signatures", &missing, "signatures"]).is_err());
    }

    #[test]
    fn parse_errors_are_clap_errors() {
        let error = run_with(&Fake::new(Vec::new), &["--version"]).unwrap_err();
        let error = error.downcast_ref::<clap::Error>().unwrap();
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    #[test]
    fn signatures_and_log_switches() {
        let (out, _) = run_with(&Fake::new(Vec::new), &["signatures"]).unwrap();
        assert!(out.contains("apple-airtag-separated"));
        let error = run_with(&Fake::new(Vec::new), &["--no-log", "followers"]).unwrap_err();
        assert_eq!(error.to_string(), "the log is off (--no-log)");
    }

    /// Run a command again with standard output, then standard error, full
    /// at the start of each line that it writes. Each write error must come
    /// back as an error.
    fn check_write_errors(fake: &Fake, args: &[&str]) {
        let (out, err) = run_with(fake, args).unwrap();
        for (to_out, text) in [(true, out), (false, err)] {
            let starts = std::iter::once(0).chain(text.match_indices('\n').map(|(i, _)| i + 1));
            for at in starts.filter(|at| *at < text.len()) {
                let mut small = vec![0u8; at];
                let mut full = std::io::Cursor::new(&mut small[..]);
                let mut other = Vec::new();
                let io = if to_out {
                    Output { out: &mut full, err: &mut other }
                } else {
                    Output { out: &mut other, err: &mut full }
                };
                let error = run(command_line(args), fake, io).unwrap_err();
                let kind = error.downcast_ref::<std::io::Error>().map(std::io::Error::kind);
                assert_eq!(kind, Some(std::io::ErrorKind::WriteZero), "{args:?} at {at}: {error}");
            }
        }
    }

    #[test]
    fn write_errors_are_errors() {
        let dir = TempDir::new().unwrap();
        let db = db_arg(&dir);
        Store::open(Path::new(&db)).unwrap().record("id:tag-1", "home", None, None, None).unwrap();
        check_write_errors(&Fake::new(Vec::new), &["--db", &db, "followers"]);
        Store::open(Path::new(&db)).unwrap().record("id:tag-1", "office", None, None, None).unwrap();
        check_write_errors(&Fake::new(Vec::new), &["--db", &db, "followers"]);
        check_write_errors(&Fake::new(Vec::new), &["signatures"]);
        check_write_errors(&Fake::new(room), &["--no-log", "--place", "x", "scan"]);
        check_write_errors(&Fake::new(room), &["--no-log", "--place", "x", "scan", "--json"]);
        check_write_errors(&Fake::new(Vec::new), &["--no-log", "--place", "x", "scan", "-s", "0"]);
        check_write_errors(&lan_fake(cameras), &["lan", "--all"]);
        check_write_errors(&lan_fake(cameras), &["lan"]);
        check_write_errors(&lan_fake(cameras), &["lan", "--json"]);
    }
}

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde_json::json;

use bugsweep::ble::{self, BleEvent};
use bugsweep::model::uuid_label;
use bugsweep::session::{Session, follow_text};
use bugsweep::signatures::SignatureDb;
use bugsweep::store::{self, Store};
use bugsweep::tui::{self, AppEvent, format_age, format_distance, lan_evidence};
use bugsweep::{lan, place};

/// A radio check for trackers, cameras, recorders and smart glasses.
///
/// Without a subcommand, bugsweep opens the terminal interface.
#[derive(Parser)]
#[command(version)]
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    let db = Arc::new(match &cli.signatures {
        Some(path) => SignatureDb::from_file(path)?,
        None => SignatureDb::embedded()?,
    });

    match &cli.command {
        Some(Cmd::Signatures) => {
            list_signatures(&db);
            Ok(())
        }
        Some(Cmd::Lan { json, all }) => run_lan(*json, *all),
        Some(Cmd::Followers) => {
            let Some(store) = open_store(&cli)? else {
                bail!("the log is off (--no-log)");
            };
            list_followers(&store)
        }
        Some(Cmd::Scan { seconds, json, flagged }) => {
            let session = new_session(&cli, db)?;
            run_scan(session, *seconds, *json, *flagged)
        }
        None => {
            let session = new_session(&cli, db)?;
            run_tui(session)
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

fn run_tui(session: Session) -> Result<()> {
    let runtime = runtime()?;
    let (tx, rx) = mpsc::channel::<AppEvent>();

    let ble_tx = tx.clone();
    runtime.spawn(ble::run(move |event| ble_tx.send(AppEvent::Ble(event)).is_ok()));

    let handle = runtime.handle().clone();
    let start_lan = move || {
        let lan_tx = tx.clone();
        handle.spawn(async move {
            let result = lan::sweep().await.map_err(|error| format!("{error:#}"));
            let _ = lan_tx.send(AppEvent::Lan(result));
        });
    };

    let result = tui::run(session, rx, &start_lan);
    runtime.shutdown_timeout(Duration::from_millis(300));
    result
}

fn run_scan(mut session: Session, seconds: u64, as_json: bool, flagged_only: bool) -> Result<()> {
    let runtime = runtime()?;
    let (tx, rx) = mpsc::channel::<BleEvent>();
    runtime.spawn(ble::run(move |event| tx.send(event).is_ok()));

    if !as_json {
        eprintln!("Scanning Bluetooth for {seconds} s at place {:?}…", session.place);
    }
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut failure = None;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match rx.recv_timeout(left) {
            Ok(BleEvent::Advert(advert)) => session.ingest(advert),
            Ok(BleEvent::Failed(error)) => {
                failure = Some(error);
                break;
            }
            Ok(BleEvent::Power(false)) => {
                failure = Some("Bluetooth is off".to_string());
                break;
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    drop(rx);
    runtime.shutdown_timeout(Duration::from_millis(300));
    if let Some(error) = failure {
        bail!("Bluetooth scan failed: {error}");
    }

    let devices = session.sorted(!flagged_only);
    if as_json {
        let list: Vec<_> = devices
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
        println!("{}", serde_json::to_string_pretty(&json!({ "place": session.place, "devices": list }))?);
        return Ok(());
    }

    println!("{:<6} {:<9} {:<30} {:>8} {:>7}  FINDING", "LEVEL", "TYPE", "DEVICE", "SIGNAL", "DIST");
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
        println!(
            "{:<6} {:<9} {:<30} {:>8} {:>7}  {}",
            session.level(device).map(|l| l.label()).unwrap_or("-"),
            signature.map(|sig| sig.category.label()).unwrap_or("-"),
            title,
            device.rssi_avg.map(|r| format!("{r:.0} dBm")).unwrap_or_default(),
            device.distance_m().map(format_distance).unwrap_or_default(),
            finding.trim(),
        );
    }
    let flagged = devices.iter().filter(|d| session.is_flagged(d)).count();
    eprintln!("\n{} device(s), {flagged} flagged.", session.len());
    eprintln!("Radio check only. A device that sends no radio signal stays hidden.");
    if session.is_empty() {
        eprintln!(
            "No devices at all usually means that the terminal app has no Bluetooth permission.\n\
             On macOS, see System Settings > Privacy & Security > Bluetooth."
        );
    }
    if let Some(error) = &session.store_error {
        eprintln!("Log error: {error}");
    }
    Ok(())
}

fn run_lan(as_json: bool, all: bool) -> Result<()> {
    if !as_json {
        eprintln!("Sweeping the local network for cameras…");
    }
    let report = runtime()?.block_on(lan::sweep())?;
    if as_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    println!(
        "{} addresses checked in {:.1} s on {}.",
        report.addresses_probed,
        report.seconds,
        report.networks.join(", ")
    );
    if report.hosts.is_empty() {
        println!("No camera evidence found.");
    }
    for host in &report.hosts {
        let verdict = match host.verdict {
            lan::Verdict::Likely => "LIKELY",
            lan::Verdict::Possible => "maybe",
        };
        println!(
            "{:<7} {:<16} {:<18} {}",
            verdict,
            host.ip,
            host.mac.as_deref().unwrap_or("-"),
            lan_evidence(host)
        );
    }
    if all {
        for other in &report.others {
            println!(
                "{:<7} {:<16} {:<18} {}{}",
                "-",
                other.ip,
                other.mac,
                other.vendor.as_deref().unwrap_or("unknown vendor"),
                other.note.map(|note| format!(" ({note})")).unwrap_or_default()
            );
        }
    } else {
        println!("{} other host(s) answered. Use --all to list them.", report.others.len());
    }
    eprintln!("A camera on a different network, or one that only records to a card, stays hidden.");
    Ok(())
}

fn list_followers(store: &Store) -> Result<()> {
    let followers = store.followers()?;
    if followers.is_empty() {
        println!("No device was seen at two or more places.");
        return Ok(());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let ago = |then: i64| format_age(Duration::from_secs((now - then).max(0) as u64));
    for follower in followers {
        println!(
            "{}  {}  {}  same {}  places: {}  first seen {} ago, last seen {} ago",
            follower.key,
            follower.title.as_deref().unwrap_or("(no name)"),
            follower.signature.as_deref().unwrap_or("-"),
            follower.basis.label(),
            follower.places.join(", "),
            ago(follower.first_seen),
            ago(follower.last_seen),
        );
    }
    Ok(())
}

fn list_signatures(db: &SignatureDb) {
    println!("{:<36} {:<9} {:<7} {:<7} {:<9} NAME", "ID", "TYPE", "LEVEL", "CONF.", "EVIDENCE");
    for sig in db.all() {
        println!(
            "{:<36} {:<9} {:<7} {:<7} {:<9} {}",
            sig.id,
            sig.category.label(),
            sig.severity.label(),
            sig.confidence.label(),
            sig.evidence.label(),
            sig.name
        );
    }
}

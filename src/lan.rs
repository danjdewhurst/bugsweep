//! Sweep of the local IPv4 network for cameras.
//!
//! Four kinds of evidence:
//! 1. ONVIF WS-Discovery: IP cameras answer a multicast probe.
//! 2. Open TCP ports that cameras and recorders use.
//! 3. An RTSP answer on an open RTSP port.
//! 4. A MAC address prefix that belongs to a camera maker. This also finds
//!    cloud cameras, which have no open ports.
//!
//! The sweep sends connection attempts to each address of the local network.
//! Run it only on a network where you are allowed to do that.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use if_addrs::IfAddr;
use regex::Regex;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::place::normalise_mac;
use crate::vendors;

/// First pass over all addresses. Short, because most addresses are empty.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(400);
/// Second pass over the hosts that answered. A host on Wi-Fi can need more
/// time than the first pass gives, most of all for its first packet.
const RETRY_TIMEOUT: Duration = Duration::from_millis(1500);
const RTSP_TIMEOUT: Duration = Duration::from_millis(900);
const ONVIF_WAIT: Duration = Duration::from_millis(2500);
const PARALLEL_CONNECTS: usize = 128;

/// (port, meaning, strong evidence of a camera).
const PORTS: &[(u16, &str, bool)] = &[
    (554, "RTSP video stream", true),
    (8554, "RTSP video stream (alternative port)", true),
    (37777, "Dahua camera or recorder", true),
    (34567, "XMEye camera or recorder", true),
    (8899, "ONVIF on low-cost cameras", false),
    (8000, "Hikvision device port (also used by other software)", false),
    (1935, "RTMP video stream", false),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VendorClass {
    /// Almost all network products of this vendor are cameras or recorders.
    Camera,
    /// The vendor makes cameras and other products.
    Mixed,
    /// A Wi-Fi chip or module maker. Many low-cost cameras use these parts,
    /// and so do many other products.
    Module,
}

/// Start of the vendor name in the IEEE registry, in lower case. A prefix
/// test keeps "Ring LLC" apart from each name that contains "ring".
/// Sources: the IEEE registry, the camera list of all-cameras-are-beacons,
/// and the DHCP matchers of Home Assistant.
const VENDOR_CLASSES: &[(&str, VendorClass)] = &[
    ("hangzhou hikvision", VendorClass::Camera),
    ("prama hikvision", VendorClass::Camera),
    ("hangzhou ezviz", VendorClass::Camera),
    ("zhejiang dahua", VendorClass::Camera),
    ("hangzhou huacheng network", VendorClass::Camera),
    ("amcrest technologies", VendorClass::Camera),
    ("axis communications", VendorClass::Camera),
    ("reolink innovation", VendorClass::Camera),
    ("zhejiang uniview", VendorClass::Camera),
    ("vivotek", VendorClass::Camera),
    ("hanwha vision", VendorClass::Camera),
    ("samsung techwin", VendorClass::Camera),
    ("lorex technology", VendorClass::Camera),
    ("swann communications", VendorClass::Camera),
    ("arlo technology", VendorClass::Camera),
    ("ring llc", VendorClass::Camera),
    ("blink by amazon", VendorClass::Camera),
    ("verkada", VendorClass::Camera),
    ("i-pro co", VendorClass::Camera),
    ("guangzhou juan", VendorClass::Camera),
    ("guangdong juan", VendorClass::Camera),
    ("night owl sp", VendorClass::Camera),
    ("skybell", VendorClass::Camera),
    ("canary connect", VendorClass::Camera),
    ("dropcam", VendorClass::Camera),
    ("mobotix", VendorClass::Camera),
    ("geovision", VendorClass::Camera),
    ("tiandy technologies", VendorClass::Camera),
    ("zhuhai raysharp", VendorClass::Camera),
    ("shanghai xiaoyi technology", VendorClass::Camera),
    ("shanghai imilab technology", VendorClass::Camera),
    ("zmodo technology", VendorClass::Camera),
    ("arecont vision", VendorClass::Camera),
    ("march networks", VendorClass::Camera),
    ("beijing hanbang technology", VendorClass::Camera),
    ("sunell electronics", VendorClass::Camera),
    ("udisense", VendorClass::Camera),
    ("pittasoft", VendorClass::Camera),
    ("thinkware", VendorClass::Camera),
    ("70mai", VendorClass::Camera),
    ("gopro", VendorClass::Camera),
    ("arashi vision", VendorClass::Camera),
    ("flock safety", VendorClass::Camera),
    ("axon enterprise", VendorClass::Camera),
    ("watchguard video", VendorClass::Camera),
    ("digital ally", VendorClass::Camera),
    ("wyze labs", VendorClass::Mixed),
    ("nest labs", VendorClass::Mixed),
    ("beken corporation", VendorClass::Module),
    ("taixin semiconductor", VendorClass::Module),
    ("tuya smart", VendorClass::Module),
    ("espressif", VendorClass::Module),
];

fn vendor_class(vendor: &str) -> Option<VendorClass> {
    let vendor = vendor.to_ascii_lowercase();
    VENDOR_CLASSES.iter().find(|(start, _)| vendor.starts_with(start)).map(|(_, class)| *class)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Only weak evidence.
    Possible,
    /// ONVIF answer, RTSP answer, a camera-specific port or a camera maker.
    Likely,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpenPort {
    pub port: u16,
    pub meaning: &'static str,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Onvif {
    pub name: Option<String>,
    pub hardware: Option<String>,
    pub address: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LanHost {
    pub ip: Ipv4Addr,
    pub mac: Option<String>,
    /// Registered owner of the MAC address prefix.
    pub vendor: Option<String>,
    /// The vendor is a known camera maker.
    pub camera_vendor: bool,
    pub verdict: Verdict,
    pub open_ports: Vec<OpenPort>,
    /// `Server` header of the RTSP answer, or "yes" when there is no header.
    pub rtsp: Option<String>,
    pub onvif: Option<Onvif>,
}

/// A host on the network without camera evidence.
#[derive(Debug, Clone, Serialize)]
pub struct Neighbour {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub vendor: Option<String>,
    pub note: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LanReport {
    pub networks: Vec<String>,
    pub addresses_probed: usize,
    pub seconds: f32,
    /// Hosts with camera evidence, most probable first.
    pub hosts: Vec<LanHost>,
    /// All other hosts that answered, for a manual check.
    pub others: Vec<Neighbour>,
}

#[derive(Debug, Clone)]
struct Network {
    interface: String,
    local: Ipv4Addr,
    base: u32,
    prefix: u8,
}

impl Network {
    fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & (u32::MAX << (32 - self.prefix)) == self.base
    }

    fn label(&self) -> String {
        format!("{}/{} ({})", Ipv4Addr::from(self.base), self.prefix, self.interface)
    }

    fn hosts(&self) -> impl Iterator<Item = Ipv4Addr> + use<> {
        let size = 1u32 << (32 - self.prefix);
        let (base, local) = (self.base, u32::from(self.local));
        (1..size - 1).map(move |i| base + i).filter(move |ip| *ip != local).map(Ipv4Addr::from)
    }
}

/// Private IPv4 networks of this machine. Large networks shrink to the /24
/// around the local address, so the sweep stays small.
fn local_networks() -> Result<Vec<Network>> {
    let mut networks: Vec<Network> = Vec::new();
    for interface in if_addrs::get_if_addrs()? {
        let IfAddr::V4(v4) = &interface.addr else { continue };
        if !v4.ip.is_private() || v4.prefixlen > 30 {
            continue;
        }
        let prefix = v4.prefixlen.max(24);
        let mask = u32::MAX << (32 - prefix);
        let base = u32::from(v4.ip) & mask;
        if networks.iter().any(|n| n.base == base) {
            continue;
        }
        networks.push(Network { interface: interface.name.clone(), local: v4.ip, base, prefix });
    }
    Ok(networks)
}

async fn port_is_open(ip: Ipv4Addr, port: u16, wait: Duration) -> bool {
    let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
    matches!(timeout(wait, TcpStream::connect(addr)).await, Ok(Ok(_)))
}

/// Try all targets at the same time, with a limit, and return the open ones.
async fn open_ports(targets: Vec<(Ipv4Addr, u16)>, wait: Duration) -> Vec<(Ipv4Addr, u16)> {
    let limit = Arc::new(Semaphore::new(PARALLEL_CONNECTS));
    let tasks: Vec<_> = targets
        .into_iter()
        .map(|(ip, port)| {
            let limit = limit.clone();
            tokio::spawn(async move {
                let _permit = limit.acquire_owned().await.ok()?;
                port_is_open(ip, port, wait).await.then_some((ip, port))
            })
        })
        .collect();
    let mut open = Vec::new();
    for task in tasks {
        if let Ok(Some(found)) = task.await {
            open.push(found);
        }
    }
    open
}

/// Ask an RTSP server for its options. Returns the `Server` header, or "yes".
async fn rtsp_probe(ip: Ipv4Addr, port: u16) -> Option<String> {
    let exchange = async {
        let mut stream = TcpStream::connect((ip, port)).await.ok()?;
        let request =
            format!("OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: bugsweep\r\n\r\n");
        stream.write_all(request.as_bytes()).await.ok()?;
        let mut buffer = vec![0u8; 1024];
        let read = stream.read(&mut buffer).await.ok()?;
        Some(String::from_utf8_lossy(&buffer[..read]).into_owned())
    };
    let answer = timeout(RTSP_TIMEOUT, exchange).await.ok()??;
    parse_rtsp_answer(&answer)
}

fn parse_rtsp_answer(answer: &str) -> Option<String> {
    if !answer.starts_with("RTSP/") {
        return None;
    }
    let server = answer.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case("server").then(|| value.trim().to_string())
    });
    Some(server.filter(|s| !s.is_empty()).unwrap_or_else(|| "yes".to_string()))
}

fn onvif_probe_message() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dn="http://www.onvif.org/ver10/network/wsdl"><e:Header><w:MessageID>uuid:{}</w:MessageID><w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To><w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>"#,
        uuid::Uuid::new_v4()
    )
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(hex) = text.get(i + 1..i + 3)
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_onvif_answer(xml: &str) -> Option<Onvif> {
    if !xml.contains("ProbeMatch") {
        return None;
    }
    let element = |tag: &str| {
        let pattern = format!(r"(?s)<(?:[A-Za-z0-9_]+:)?{tag}[^>]*>(.*?)</(?:[A-Za-z0-9_]+:)?{tag}>");
        let captures = Regex::new(&pattern).ok()?.captures(xml)?;
        Some(captures.get(1)?.as_str().trim().to_string())
    };
    let scopes = element("Scopes").unwrap_or_default();
    let scope = |kind: &str| {
        let marker = format!("onvif://www.onvif.org/{kind}/");
        scopes.split_whitespace().find_map(|s| s.strip_prefix(marker.as_str())).map(percent_decode)
    };
    Some(Onvif {
        name: scope("name"),
        hardware: scope("hardware"),
        address: element("XAddrs").and_then(|a| a.split_whitespace().next().map(str::to_string)),
    })
}

/// Send the ONVIF probe from one local address and collect the answers.
async fn onvif_discover(local: Ipv4Addr) -> BTreeMap<Ipv4Addr, Onvif> {
    let mut found = BTreeMap::new();
    let Ok(socket) = UdpSocket::bind((local, 0)).await else {
        return found;
    };
    let target = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 3702);
    let message = onvif_probe_message();
    for _ in 0..2 {
        let _ = socket.send_to(message.as_bytes(), target).await;
    }
    let deadline = Instant::now() + ONVIF_WAIT;
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match timeout(left, socket.recv_from(&mut buffer)).await {
            Ok(Ok((read, SocketAddr::V4(from)))) => {
                let xml = String::from_utf8_lossy(&buffer[..read]);
                if let Some(onvif) = parse_onvif_answer(&xml) {
                    found.entry(*from.ip()).or_insert(onvif);
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(_)) | Err(_) => break,
        }
    }
    found
}

/// Read the ARP table of the operating system: IP address to MAC address.
fn arp_table() -> BTreeMap<Ipv4Addr, String> {
    let mut table = BTreeMap::new();
    let args: &[&str] = if cfg!(windows) { &["-a"] } else { &["-an"] };
    let Ok(output) = Command::new("arp").args(args).output() else {
        return table;
    };
    parse_arp(&String::from_utf8_lossy(&output.stdout), &mut table);
    table
}

fn parse_arp(text: &str, table: &mut BTreeMap<Ipv4Addr, String>) {
    // macOS and Linux: "? (192.168.1.1) at a4:b:c:d:e:f on en0 ..."
    // Windows:         "  192.168.1.1    a4-0b-0c-0d-0e-0f    dynamic"
    let pattern = Regex::new(
        r"\(?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)?\s+(?:at\s+)?([0-9A-Fa-f]{1,2}(?:[:-][0-9A-Fa-f]{1,2}){5})",
    )
    .expect("valid pattern");
    for captures in pattern.captures_iter(text) {
        let (Ok(ip), Some(mac)) = (captures[1].parse::<Ipv4Addr>(), normalise_mac(&captures[2])) else {
            continue;
        };
        if mac != "ff:ff:ff:ff:ff:ff" {
            table.insert(ip, mac);
        }
    }
}

/// Run the full sweep.
pub async fn sweep() -> Result<LanReport> {
    let started = Instant::now();
    let networks = local_networks()?;
    if networks.is_empty() {
        bail!("no private IPv4 network found");
    }

    // ONVIF discovery runs at the same time as the port sweep.
    let onvif_tasks: Vec<_> = networks.iter().map(|n| tokio::spawn(onvif_discover(n.local))).collect();

    let addresses: Vec<Ipv4Addr> = networks.iter().flat_map(Network::hosts).collect();
    let addresses_probed = addresses.len();
    let first_pass: Vec<(Ipv4Addr, u16)> =
        addresses.iter().flat_map(|ip| PORTS.iter().map(move |(port, _, _)| (*ip, *port))).collect();
    let mut open: BTreeMap<Ipv4Addr, Vec<u16>> = BTreeMap::new();
    for (ip, port) in open_ports(first_pass, CONNECT_TIMEOUT).await {
        open.entry(ip).or_default().push(port);
    }

    // The first pass made the system ask for the MAC address of each host,
    // so the ARP table now lists every host that answered. Try those hosts
    // again with more time: the first pass can be too fast for them.
    let in_networks =
        |ip: &Ipv4Addr| networks.iter().any(|network| network.contains(*ip) && network.local != *ip);
    let alive: Vec<Ipv4Addr> = arp_table().into_keys().filter(in_networks).collect();
    let second_pass: Vec<(Ipv4Addr, u16)> = alive
        .iter()
        .flat_map(|ip| PORTS.iter().map(move |(port, _, _)| (*ip, *port)))
        .filter(|(ip, port)| !open.get(ip).is_some_and(|ports| ports.contains(port)))
        .collect();
    for (ip, port) in open_ports(second_pass, RETRY_TIMEOUT).await {
        open.entry(ip).or_default().push(port);
    }

    let mut onvif: BTreeMap<Ipv4Addr, Onvif> = BTreeMap::new();
    for task in onvif_tasks {
        if let Ok(found) = task.await {
            onvif.extend(found);
        }
    }

    let arp: BTreeMap<Ipv4Addr, String> = arp_table().into_iter().filter(|(ip, _)| in_networks(ip)).collect();
    let class_of =
        |ip: &Ipv4Addr| arp.get(ip).and_then(|mac| vendors::mac_vendor(mac)).and_then(vendor_class);
    let by_vendor =
        arp.keys().filter(|ip| matches!(class_of(ip), Some(VendorClass::Camera | VendorClass::Mixed)));
    let mut ips: Vec<Ipv4Addr> = open.keys().chain(onvif.keys()).chain(by_vendor).copied().collect();
    ips.sort();
    ips.dedup();

    let mut hosts = Vec::new();
    for ip in ips {
        let mut ports = open.remove(&ip).unwrap_or_default();
        ports.sort();
        let mut rtsp = None;
        for port in ports.iter().copied().filter(|p| matches!(p, 554 | 8554)) {
            rtsp = rtsp_probe(ip, port).await;
            if rtsp.is_some() {
                break;
            }
        }
        let onvif = onvif.remove(&ip);
        let strong_port = ports
            .iter()
            .any(|port| PORTS.iter().any(|(p, _, strong)| p == port && *strong && !matches!(p, 554 | 8554)));
        let class = class_of(&ip);
        let camera_vendor = matches!(class, Some(VendorClass::Camera | VendorClass::Mixed));
        let verdict =
            if onvif.is_some() || rtsp.is_some() || strong_port || class == Some(VendorClass::Camera) {
                Verdict::Likely
            } else {
                Verdict::Possible
            };
        let open_ports = ports
            .iter()
            .filter_map(|port| {
                let (_, meaning, _) = PORTS.iter().find(|(p, _, _)| p == port)?;
                Some(OpenPort { port: *port, meaning })
            })
            .collect();
        let mac = arp.get(&ip).cloned();
        let vendor = mac.as_deref().and_then(vendors::mac_vendor).map(str::to_string);
        hosts.push(LanHost { ip, mac, vendor, camera_vendor, verdict, open_ports, rtsp, onvif });
    }
    hosts.sort_by(|a, b| b.verdict.cmp(&a.verdict).then(a.ip.cmp(&b.ip)));

    let others = arp
        .iter()
        .filter(|(ip, _)| !hosts.iter().any(|host| host.ip == **ip))
        .map(|(ip, mac)| neighbour(*ip, mac))
        .collect();

    Ok(LanReport {
        networks: networks.iter().map(Network::label).collect(),
        addresses_probed,
        seconds: started.elapsed().as_secs_f32(),
        hosts,
        others,
    })
}

fn neighbour(ip: Ipv4Addr, mac: &str) -> Neighbour {
    let vendor = vendors::mac_vendor(mac);
    let note = match vendor.and_then(vendor_class) {
        Some(VendorClass::Module) => Some("Wi-Fi chip that many low-cost cameras use"),
        _ if vendor.is_none() && vendors::mac_is_private(mac) => Some("private address (phone or laptop)"),
        _ => None,
    };
    Neighbour { ip, mac: mac.to_string(), vendor: vendor.map(str::to_string), note }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_classes_match_registry_names() {
        // Each start must match a name in the IEEE table, or it can never match.
        let table = include_str!("../data/oui.tsv").to_ascii_lowercase();
        for (start, _) in VENDOR_CLASSES {
            assert!(table.contains(&format!("\t{start}")), "{start} is not in data/oui.tsv");
        }
        assert_eq!(vendor_class("Ring LLC"), Some(VendorClass::Camera));
        assert_eq!(vendor_class("Hangzhou Hikvision Digital Technology Co.,Ltd."), Some(VendorClass::Camera));
        assert_eq!(vendor_class("Wyze Labs Inc"), Some(VendorClass::Mixed));
        assert_eq!(vendor_class("Espressif Inc."), Some(VendorClass::Module));
        // Names that only contain a camera name are not cameras.
        assert_eq!(vendor_class("Engineering Ring LLC Partners"), None);
        assert_eq!(vendor_class("Apple, Inc."), None);
    }

    #[test]
    fn neighbour_notes() {
        let ip = Ipv4Addr::new(192, 168, 1, 5);
        let chip_mac = include_str!("../data/oui.tsv")
            .lines()
            .find(|line| line.ends_with("\tEspressif Inc."))
            .map(|line| format!("{}:{}:{}:00:00:01", &line[0..2], &line[2..4], &line[4..6]))
            .unwrap();
        let chip = neighbour(ip, &chip_mac);
        assert_eq!(chip.vendor.as_deref(), Some("Espressif Inc."));
        assert!(chip.note.unwrap().contains("low-cost cameras"));
        assert!(neighbour(ip, "da:a1:19:00:00:01").note.unwrap().contains("private address"));
        assert_eq!(neighbour(ip, "00:25:df:00:00:01").note, None);
    }

    #[test]
    fn network_contains_only_its_addresses() {
        let network = Network {
            interface: "en0".into(),
            local: Ipv4Addr::new(192, 168, 1, 20),
            base: u32::from(Ipv4Addr::new(192, 168, 1, 0)),
            prefix: 24,
        };
        assert!(network.contains(Ipv4Addr::new(192, 168, 1, 254)));
        assert!(!network.contains(Ipv4Addr::new(192, 168, 2, 1)));
        assert!(!network.contains(Ipv4Addr::new(224, 0, 0, 251)));
    }

    #[test]
    fn network_hosts_skip_edges_and_self() {
        let network = Network {
            interface: "en0".into(),
            local: Ipv4Addr::new(192, 168, 1, 20),
            base: u32::from(Ipv4Addr::new(192, 168, 1, 0)),
            prefix: 24,
        };
        let hosts: Vec<Ipv4Addr> = network.hosts().collect();
        assert_eq!(hosts.len(), 253);
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(*hosts.last().unwrap(), Ipv4Addr::new(192, 168, 1, 254));
        assert!(!hosts.contains(&network.local));
    }

    #[tokio::test]
    async fn open_port_and_rtsp_probe_against_a_local_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buffer = [0u8; 512];
                    // The port check connects and sends nothing, so the read can return 0.
                    if stream.read(&mut buffer).await.unwrap_or(0) > 0 {
                        let _ = stream
                            .write_all(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: TestCam/1.0\r\n\r\n")
                            .await;
                    }
                });
            }
        });
        let ip = Ipv4Addr::LOCALHOST;
        assert!(port_is_open(ip, port, CONNECT_TIMEOUT).await);
        assert_eq!(rtsp_probe(ip, port).await.as_deref(), Some("TestCam/1.0"));

        // A closed port: bind, read the port number, then drop the listener.
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_port = closed.local_addr().unwrap().port();
        drop(closed);
        assert!(!port_is_open(ip, closed_port, CONNECT_TIMEOUT).await);
        assert_eq!(rtsp_probe(ip, closed_port).await, None);

        let found = open_ports(vec![(ip, port), (ip, closed_port)], CONNECT_TIMEOUT).await;
        assert_eq!(found, [(ip, port)]);
    }

    #[test]
    fn rtsp_answer() {
        let answer =
            "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Hipcam RealServer/V1.0\r\nPublic: OPTIONS\r\n\r\n";
        assert_eq!(parse_rtsp_answer(answer).as_deref(), Some("Hipcam RealServer/V1.0"));
        assert_eq!(parse_rtsp_answer("RTSP/1.0 401 Unauthorized\r\n\r\n").as_deref(), Some("yes"));
        assert_eq!(parse_rtsp_answer("HTTP/1.1 400 Bad Request\r\n\r\n"), None);
    }

    #[test]
    fn onvif_answer() {
        let xml = r#"<SOAP-ENV:Envelope><SOAP-ENV:Body><d:ProbeMatches><d:ProbeMatch>
            <d:Types>dn:NetworkVideoTransmitter</d:Types>
            <d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/hardware/DS-2CD2043 onvif://www.onvif.org/name/Front%20Door</d:Scopes>
            <d:XAddrs>http://192.168.1.64/onvif/device_service http://[fe80::1]/onvif/device_service</d:XAddrs>
            </d:ProbeMatch></d:ProbeMatches></SOAP-ENV:Body></SOAP-ENV:Envelope>"#;
        let onvif = parse_onvif_answer(xml).unwrap();
        assert_eq!(onvif.name.as_deref(), Some("Front Door"));
        assert_eq!(onvif.hardware.as_deref(), Some("DS-2CD2043"));
        assert_eq!(onvif.address.as_deref(), Some("http://192.168.1.64/onvif/device_service"));
        assert!(parse_onvif_answer("<Envelope><Probe/></Envelope>").is_none());
    }

    #[test]
    fn arp_formats() {
        let mut table = BTreeMap::new();
        let text = "? (192.168.1.1) at a4:b:c:d:e:f on en0 ifscope [ethernet]\n\
                    ? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]\n\
                    ? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n\
                    \x20 192.168.1.7           00-11-22-aa-bb-cc     dynamic\n";
        parse_arp(text, &mut table);
        assert_eq!(table.len(), 2);
        assert_eq!(table[&Ipv4Addr::new(192, 168, 1, 1)], "a4:0b:0c:0d:0e:0f");
        assert_eq!(table[&Ipv4Addr::new(192, 168, 1, 7)], "00:11:22:aa:bb:cc");
    }
}

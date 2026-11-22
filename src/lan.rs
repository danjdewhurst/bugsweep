//! Sweep of the local IPv4 network for cameras.
//!
//! Four kinds of evidence:
//! 1. ONVIF WS-Discovery: IP cameras answer a multicast probe.
//! 2. Open TCP ports that cameras and recorders use.
//! 3. An RTSP answer on an open RTSP port.
//! 4. A MAC address prefix that belongs to a camera maker. This also finds
//!    cloud cameras, which have no open ports.
//!
//! The sweep also asks for the name of each host that answered: a reverse
//! DNS query to the default gateway, and unicast mDNS queries to the host
//! itself for its name and its DNS-SD service types. A name or a service is
//! a hint for a manual check only. It never changes a verdict or a note,
//! because the device chooses it.
//!
//! The sweep sends connection attempts to each address of the local network.
//! Run it only on a network where you are allowed to do that.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use futures::future::join_all;
use if_addrs::{IfAddr, Interface};
use regex::Regex;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::dns;
use crate::place::{self, normalise_mac, output_any_status};
use crate::vendors;

/// First pass over all addresses. Short, because most addresses are empty.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(400);
/// Second pass over the hosts that answered. A host on Wi-Fi can need more
/// time than the first pass gives, most of all for its first packet.
const RETRY_TIMEOUT: Duration = Duration::from_millis(1500);
const RTSP_TIMEOUT: Duration = Duration::from_millis(900);
const ONVIF_WAIT: Duration = Duration::from_millis(2500);
const ONVIF_TARGET: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 3702));
const PARALLEL_CONNECTS: usize = 128;
/// How long a name query waits for its answer. The query goes out again
/// after half of this time.
const NAME_WAIT: Duration = Duration::from_millis(1200);
/// All name queries of one sweep end after this time, also on a large
/// network where many hosts do not answer.
const NAMES_BUDGET: Duration = Duration::from_millis(2500);
/// Name queries at the same time. Each query uses one socket.
const PARALLEL_LOOKUPS: usize = 64;
const DNS_PORT: u16 = 53;
const MDNS_PORT: u16 = 5353;

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
    /// A maker of small Linux computers. A camera module turns one into a
    /// camera.
    Computer,
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
    // "Raspberry Pi Foundation", "Raspberry Pi Trading Ltd" and
    // "Raspberry Pi (Trading) Ltd".
    ("raspberry pi", VendorClass::Computer),
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
    /// Host name from mDNS or from the DNS of the gateway. Untrusted.
    pub name: Option<String>,
    /// DNS-SD service types that the host advertises, for example
    /// "_hap._tcp". Untrusted.
    pub services: Vec<String>,
}

/// A host on the network without camera evidence.
#[derive(Debug, Clone, Serialize)]
pub struct Neighbour {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub vendor: Option<String>,
    pub note: Option<&'static str>,
    /// The vendor makes parts that cameras use, so the host needs a manual
    /// check.
    pub needs_check: bool,
    /// As in [`LanHost::name`]. Untrusted.
    pub name: Option<String>,
    /// As in [`LanHost::services`]. Untrusted.
    pub services: Vec<String>,
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
pub(crate) struct Network {
    interface: String,
    local: Ipv4Addr,
    base: u32,
    /// The swept prefix: at least /24.
    prefix: u8,
    /// The prefix of the interface. It can be larger than the swept one.
    link_prefix: u8,
}

impl Network {
    fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & (u32::MAX << (32 - self.prefix)) == self.base
    }

    /// The address is on the link of the interface, also outside the
    /// swept part of a large network.
    fn on_link(&self, ip: Ipv4Addr) -> bool {
        let mask = u32::MAX.checked_shl(32 - u32::from(self.link_prefix)).unwrap_or(0);
        u32::from(ip) & mask == u32::from(self.local) & mask
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

/// Private IPv4 networks in a list of interfaces. Large networks shrink to
/// the /24 around the local address, so the sweep stays small.
fn networks_from(interfaces: &[Interface]) -> Vec<Network> {
    let mut networks: Vec<Network> = Vec::new();
    for interface in interfaces {
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
        networks.push(Network {
            interface: interface.name.clone(),
            local: v4.ip,
            base,
            prefix,
            link_prefix: v4.prefixlen,
        });
    }
    networks
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

/// Send the ONVIF probe from one local address to `target`, and collect the
/// answers that arrive in `wait`.
async fn onvif_discover(local: Ipv4Addr, target: SocketAddr, wait: Duration) -> BTreeMap<Ipv4Addr, Onvif> {
    let mut found = BTreeMap::new();
    let Ok(socket) = UdpSocket::bind((local, 0)).await else {
        return found;
    };
    let message = onvif_probe_message();
    for _ in 0..2 {
        let _ = socket.send_to(message.as_bytes(), target).await;
    }
    let deadline = Instant::now() + wait;
    let mut buffer = vec![0u8; 16 * 1024];
    // Check the time before each read: a host that never stops sending must
    // not keep the sweep alive. The socket is IPv4, so each answer comes
    // from an IPv4 address.
    let mut left = wait;
    while !left.is_zero()
        && let Ok(Ok((read, SocketAddr::V4(from)))) = timeout(left, socket.recv_from(&mut buffer)).await
    {
        let xml = String::from_utf8_lossy(&buffer[..read]);
        if let Some(onvif) = parse_onvif_answer(&xml) {
            found.entry(*from.ip()).or_insert(onvif);
        }
        left = deadline.saturating_duration_since(Instant::now());
    }
    found
}

/// Parse an ARP table: IP address to MAC address.
fn parse_arp(text: &str) -> BTreeMap<Ipv4Addr, String> {
    // macOS and Linux: "? (192.168.1.1) at a4:b:c:d:e:f on en0 ..."
    // Windows:         "  192.168.1.1    a4-0b-0c-0d-0e-0f    dynamic"
    let pattern = Regex::new(
        r"\(?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)?\s+(?:at\s+)?([0-9A-Fa-f]{1,2}(?:[:-][0-9A-Fa-f]{1,2}){5})",
    )
    .expect("valid pattern");
    let mut table = BTreeMap::new();
    for captures in pattern.captures_iter(text) {
        let (Ok(ip), Some(mac)) = (captures[1].parse::<Ipv4Addr>(), normalise_mac(&captures[2])) else {
            continue;
        };
        if mac != "ff:ff:ff:ff:ff:ff" {
            table.insert(ip, mac);
        }
    }
    table
}

/// Send `query` to `server` and return the first answer with the ID of the
/// query. The query goes out again after half of `wait`. The socket is
/// connected, so the system drops packets from other hosts, and a host with
/// no server on the port ends the wait at once.
async fn dns_exchange(server: SocketAddrV4, query: &[u8], wait: Duration) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.ok()?;
    socket.connect(server).await.ok()?;
    let mut buffer = vec![0u8; 4096];
    for until in [Instant::now() + wait / 2, Instant::now() + wait] {
        socket.send(query).await.ok()?;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            match timeout(left, socket.recv(&mut buffer)).await {
                Ok(Ok(read)) if buffer[..read].starts_with(&query[..2]) => {
                    return Some(buffer[..read].to_vec());
                }
                // An answer to another query.
                Ok(Ok(_)) => {}
                // The host has no server on this port.
                Ok(Err(_)) => return None,
                Err(_) => break,
            }
        }
    }
    None
}

/// What the sweep needs from the system. Tests use a fake.
pub(crate) trait Probe {
    /// The local networks to sweep.
    fn networks(&self) -> Result<Vec<Network>>;
    /// The ARP table: IP address to MAC address.
    fn arp_table(&self) -> BTreeMap<Ipv4Addr, String>;
    /// The targets that accept a TCP connection in `wait`.
    async fn open_ports(&self, targets: Vec<(Ipv4Addr, u16)>, wait: Duration) -> Vec<(Ipv4Addr, u16)>;
    /// The ONVIF answers to a probe from `local`.
    async fn onvif(&self, local: Ipv4Addr) -> BTreeMap<Ipv4Addr, Onvif>;
    /// The RTSP answer of a host, as in [`rtsp_probe`].
    async fn rtsp(&self, ip: Ipv4Addr, port: u16) -> Option<String>;
    /// The IPv4 address of the default gateway.
    fn gateway(&self) -> Option<Ipv4Addr>;
    /// The answer to a DNS query, as in [`dns_exchange`].
    async fn dns(&self, server: SocketAddrV4, query: Vec<u8>, wait: Duration) -> Option<Vec<u8>>;
}

/// The real network of this machine.
pub(crate) struct System {
    /// Where the ONVIF probe goes, and how long to wait for answers.
    onvif_target: SocketAddr,
    onvif_wait: Duration,
}

/// This machine, with the ONVIF probe to the WS-Discovery multicast group.
pub(crate) const MACHINE: System = System { onvif_target: ONVIF_TARGET, onvif_wait: ONVIF_WAIT };

impl Probe for System {
    fn networks(&self) -> Result<Vec<Network>> {
        Ok(networks_from(&if_addrs::get_if_addrs()?))
    }

    fn arp_table(&self) -> BTreeMap<Ipv4Addr, String> {
        // Some arp tools print a good table and still fail, so the exit
        // status does not matter.
        let args: &[&str] = if cfg!(windows) { &["-a"] } else { &["-an"] };
        parse_arp(&output_any_status("arp", args).unwrap_or_default().1)
    }

    async fn open_ports(&self, targets: Vec<(Ipv4Addr, u16)>, wait: Duration) -> Vec<(Ipv4Addr, u16)> {
        open_ports(targets, wait).await
    }

    async fn onvif(&self, local: Ipv4Addr) -> BTreeMap<Ipv4Addr, Onvif> {
        onvif_discover(local, self.onvif_target, self.onvif_wait).await
    }

    async fn rtsp(&self, ip: Ipv4Addr, port: u16) -> Option<String> {
        rtsp_probe(ip, port).await
    }

    fn gateway(&self) -> Option<Ipv4Addr> {
        place::gateway()
    }

    async fn dns(&self, server: SocketAddrV4, query: Vec<u8>, wait: Duration) -> Option<Vec<u8>> {
        dns_exchange(server, &query, wait).await
    }
}

/// What a host says about itself.
#[derive(Debug, Default)]
struct Names {
    name: Option<String>,
    services: Vec<String>,
}

/// The shared limits of the name queries of one sweep.
struct Lookups {
    /// Queries at the same time.
    limit: Semaphore,
    /// No query waits past this time.
    deadline: tokio::time::Instant,
}

/// Send one PTR query for `name` to `server`, and return the targets.
async fn ask(probe: &impl Probe, lookups: &Lookups, server: SocketAddrV4, name: &str) -> Vec<String> {
    let _permit = lookups.limit.acquire().await;
    let wait = NAME_WAIT.min(lookups.deadline.saturating_duration_since(tokio::time::Instant::now()));
    if wait.is_zero() {
        return Vec::new();
    }
    let id = uuid::Uuid::new_v4().as_u128() as u16;
    match probe.dns(server, dns::query(id, name), wait).await {
        Some(answer) => dns::ptr_targets(&answer, id, name),
        None => Vec::new(),
    }
}

/// The name and the service types of one host. The name the host gives
/// over mDNS comes first; the name from the gateway's DNS is the fallback.
async fn names_of(probe: &impl Probe, lookups: &Lookups, ip: Ipv4Addr, gateway: Option<Ipv4Addr>) -> Names {
    let reverse = dns::reverse_name(ip);
    let host = SocketAddrV4::new(ip, MDNS_PORT);
    let from_gateway = async {
        match gateway {
            Some(gateway) => ask(probe, lookups, SocketAddrV4::new(gateway, DNS_PORT), &reverse).await,
            None => Vec::new(),
        }
    };
    let (own, router, services) = tokio::join!(
        ask(probe, lookups, host, &reverse),
        from_gateway,
        ask(probe, lookups, host, dns::SERVICES)
    );
    Names { name: dns::host_name(own.iter().chain(&router)), services: dns::service_types(&services) }
}

/// Run the full sweep with `probe`.
pub(crate) async fn sweep_with(probe: &impl Probe) -> Result<LanReport> {
    let started = Instant::now();
    let networks = probe.networks()?;
    if networks.is_empty() {
        bail!("no private IPv4 network found");
    }
    let in_networks =
        |ip: &Ipv4Addr| networks.iter().any(|network| network.contains(*ip) && network.local != *ip);

    let addresses: Vec<Ipv4Addr> = networks.iter().flat_map(Network::hosts).collect();
    let addresses_probed = addresses.len();
    let port_sweep = async {
        let first_pass: Vec<(Ipv4Addr, u16)> =
            addresses.iter().flat_map(|ip| PORTS.iter().map(move |(port, _, _)| (*ip, *port))).collect();
        let mut open: BTreeMap<Ipv4Addr, Vec<u16>> = BTreeMap::new();
        for (ip, port) in probe.open_ports(first_pass, CONNECT_TIMEOUT).await {
            open.entry(ip).or_default().push(port);
        }

        // The first pass made the system ask for the MAC address of each
        // host, so the ARP table now lists every host that answered. Try
        // those hosts again with more time: the first pass can be too fast
        // for them.
        let alive: Vec<Ipv4Addr> = probe.arp_table().into_keys().filter(in_networks).collect();
        let second_pass: Vec<(Ipv4Addr, u16)> = alive
            .iter()
            .flat_map(|ip| PORTS.iter().map(move |(port, _, _)| (*ip, *port)))
            .filter(|(ip, port)| !open.get(ip).is_some_and(|ports| ports.contains(port)))
            .collect();
        for (ip, port) in probe.open_ports(second_pass, RETRY_TIMEOUT).await {
            open.entry(ip).or_default().push(port);
        }
        open
    };
    // ONVIF discovery runs at the same time as the port sweep.
    let discovery = join_all(networks.iter().map(|n| probe.onvif(n.local)));
    let (open, found) = tokio::join!(port_sweep, discovery);
    let onvif: BTreeMap<Ipv4Addr, Onvif> = found.into_iter().flatten().collect();

    let arp: BTreeMap<Ipv4Addr, String> =
        probe.arp_table().into_iter().filter(|(ip, _)| in_networks(ip)).collect();
    let class_of =
        |ip: &Ipv4Addr| arp.get(ip).and_then(|mac| vendors::mac_vendor(mac)).and_then(vendor_class);
    let by_vendor =
        arp.keys().filter(|ip| matches!(class_of(ip), Some(VendorClass::Camera | VendorClass::Mixed)));
    let mut ips: Vec<Ipv4Addr> = open.keys().chain(onvif.keys()).chain(by_vendor).copied().collect();
    ips.sort();
    ips.dedup();

    // The name queries run at the same time as the RTSP probes. They go only
    // to addresses in the swept networks.
    let everyone: BTreeSet<Ipv4Addr> = ips.iter().chain(arp.keys()).copied().filter(in_networks).collect();
    // The gateway is on the link also when the network is larger than the
    // swept /24.
    let gateway = probe.gateway().filter(|ip| networks.iter().any(|n| n.on_link(*ip) && n.local != *ip));
    let limits = Lookups {
        limit: Semaphore::new(PARALLEL_LOOKUPS),
        deadline: tokio::time::Instant::now() + NAMES_BUDGET,
    };
    let lookups = join_all(everyone.iter().map(|ip| names_of(probe, &limits, *ip, gateway)));
    let (mut hosts, names) = tokio::join!(hosts_with_evidence(probe, ips, open, onvif, &arp), lookups);
    let mut names: BTreeMap<Ipv4Addr, Names> = everyone.into_iter().zip(names).collect();
    // A name never changes the verdict or the note: it only adds a hint.
    for host in &mut hosts {
        let found = names.remove(&host.ip).unwrap_or_default();
        (host.name, host.services) = (found.name, found.services);
    }
    hosts.sort_by(|a, b| b.verdict.cmp(&a.verdict).then(a.ip.cmp(&b.ip)));

    let others = arp
        .iter()
        .filter(|(ip, _)| !hosts.iter().any(|host| host.ip == **ip))
        .map(|(ip, mac)| {
            let found = names.remove(ip).unwrap_or_default();
            Neighbour { name: found.name, services: found.services, ..neighbour(*ip, mac) }
        })
        .collect();

    Ok(LanReport {
        networks: networks.iter().map(Network::label).collect(),
        addresses_probed,
        seconds: started.elapsed().as_secs_f32(),
        hosts,
        others,
    })
}

/// Build the hosts with camera evidence, with an RTSP probe of each open
/// RTSP port.
async fn hosts_with_evidence(
    probe: &impl Probe,
    ips: Vec<Ipv4Addr>,
    mut open: BTreeMap<Ipv4Addr, Vec<u16>>,
    mut onvif: BTreeMap<Ipv4Addr, Onvif>,
    arp: &BTreeMap<Ipv4Addr, String>,
) -> Vec<LanHost> {
    let class_of =
        |ip: &Ipv4Addr| arp.get(ip).and_then(|mac| vendors::mac_vendor(mac)).and_then(vendor_class);
    let mut hosts = Vec::new();
    for ip in ips {
        let mut ports = open.remove(&ip).unwrap_or_default();
        ports.sort();
        let mut rtsp = None;
        for port in ports.iter().copied().filter(|p| matches!(p, 554 | 8554)) {
            rtsp = probe.rtsp(ip, port).await;
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
        hosts.push(LanHost {
            ip,
            mac,
            vendor,
            camera_vendor,
            verdict,
            open_ports,
            rtsp,
            onvif,
            name: None,
            services: Vec::new(),
        });
    }
    hosts
}

fn neighbour(ip: Ipv4Addr, mac: &str) -> Neighbour {
    let vendor = vendors::mac_vendor(mac);
    let class = vendor.and_then(vendor_class);
    let note = match class {
        Some(VendorClass::Module) => Some("Wi-Fi chip that many low-cost cameras use"),
        Some(VendorClass::Computer) => Some("small Linux computer that can run a camera"),
        _ if vendor.is_none() && vendors::mac_is_private(mac) => Some("private address (phone or laptop)"),
        _ => None,
    };
    Neighbour {
        ip,
        mac: mac.to_string(),
        vendor: vendor.map(str::to_string),
        note,
        needs_check: matches!(class, Some(VendorClass::Module | VendorClass::Computer)),
        name: None,
        services: Vec::new(),
    }
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
        for name in ["Raspberry Pi Foundation", "Raspberry Pi Trading Ltd", "Raspberry Pi (Trading) Ltd"] {
            let full = format!("\t{}", name.to_ascii_lowercase());
            assert!(table.lines().any(|line| line.ends_with(&full)), "{name} is not in data/oui.tsv");
            assert_eq!(vendor_class(name), Some(VendorClass::Computer), "{name}");
        }
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
        assert!(chip.needs_check);
        let computer = neighbour(ip, &mac_of("\tRaspberry Pi Foundation", 1));
        assert_eq!(computer.note, Some("small Linux computer that can run a camera"));
        assert!(computer.needs_check);
        let phone = neighbour(ip, "da:a1:19:00:00:01");
        assert!(phone.note.unwrap().contains("private address"));
        assert!(!phone.needs_check);
        assert_eq!(neighbour(ip, "00:25:df:00:00:01").note, None);
    }

    #[test]
    fn network_contains_only_its_addresses() {
        let network = Network {
            interface: "en0".into(),
            local: Ipv4Addr::new(192, 168, 1, 20),
            base: u32::from(Ipv4Addr::new(192, 168, 1, 0)),
            prefix: 24,
            link_prefix: 24,
        };
        assert!(network.contains(Ipv4Addr::new(192, 168, 1, 254)));
        assert!(!network.contains(Ipv4Addr::new(192, 168, 2, 1)));
        assert!(!network.contains(Ipv4Addr::new(224, 0, 0, 251)));
        assert!(network.on_link(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!network.on_link(Ipv4Addr::new(192, 168, 0, 1)));
        let wide = Network { link_prefix: 22, ..network };
        assert!(wide.on_link(Ipv4Addr::new(192, 168, 0, 1)));
        assert!(!wide.on_link(Ipv4Addr::new(192, 168, 4, 1)));
        assert!(Network { link_prefix: 0, ..wide }.on_link(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn network_hosts_skip_edges_and_self() {
        let network = Network {
            interface: "en0".into(),
            local: Ipv4Addr::new(192, 168, 1, 20),
            base: u32::from(Ipv4Addr::new(192, 168, 1, 0)),
            prefix: 24,
            link_prefix: 24,
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

        let found = MACHINE.open_ports(vec![(ip, port), (ip, closed_port)], CONNECT_TIMEOUT).await;
        assert_eq!(found, [(ip, port)]);
        assert_eq!(MACHINE.rtsp(ip, port).await.as_deref(), Some("TestCam/1.0"));
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
        let text = "? (192.168.1.1) at a4:b:c:d:e:f on en0 ifscope [ethernet]\n\
                    ? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]\n\
                    ? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n\
                    ? (999.1.1.1) at a4:b:c:d:e:f on en0 ifscope [ethernet]\n\
                    \x20 192.168.1.7           00-11-22-aa-bb-cc     dynamic\n";
        let table = parse_arp(text);
        assert_eq!(table.len(), 2);
        assert_eq!(table[&Ipv4Addr::new(192, 168, 1, 1)], "a4:0b:0c:0d:0e:0f");
        assert_eq!(table[&Ipv4Addr::new(192, 168, 1, 7)], "00:11:22:aa:bb:cc");
    }

    fn interface(name: &str, addr: IfAddr) -> Interface {
        Interface {
            name: name.into(),
            addr,
            index: None,
            oper_status: if_addrs::IfOperStatus::Up,
            is_p2p: false,
            #[cfg(windows)]
            adapter_name: String::new(),
        }
    }

    fn v4(ip: [u8; 4], prefixlen: u8) -> IfAddr {
        IfAddr::V4(if_addrs::Ifv4Addr {
            ip: Ipv4Addr::from(ip),
            netmask: Ipv4Addr::from(u32::MAX << (32 - prefixlen)),
            prefixlen,
            broadcast: None,
        })
    }

    #[test]
    fn networks_from_interfaces() {
        let interfaces = [
            interface("lo0", v4([127, 0, 0, 1], 8)),
            interface(
                "en0",
                IfAddr::V6(if_addrs::Ifv6Addr {
                    ip: "fe80::1".parse().unwrap(),
                    netmask: "ffff:ffff:ffff:ffff::".parse().unwrap(),
                    prefixlen: 64,
                    broadcast: None,
                }),
            ),
            interface("en0", v4([10, 1, 2, 3], 16)),
            interface("en1", v4([10, 1, 2, 4], 24)),
            interface("utun0", v4([192, 168, 7, 2], 32)),
            interface("en2", v4([192, 168, 1, 20], 24)),
        ];
        let labels: Vec<String> = networks_from(&interfaces).iter().map(Network::label).collect();
        assert_eq!(labels, ["10.1.2.0/24 (en0)", "192.168.1.0/24 (en2)"]);
    }

    #[test]
    fn system_reads_this_machine() {
        // The results depend on the machine. The calls must not fail.
        let networks = MACHINE.networks().unwrap();
        assert!(networks.iter().all(|n| n.prefix >= 24));
        assert!(MACHINE.arp_table().values().all(|mac| mac.len() == 17));
        // The gateway depends on the network. The call must not fail.
        let _ = MACHINE.gateway();
    }

    /// A fake ONVIF camera on the loopback address. It answers the first
    /// probe with some noise and one probe match.
    async fn fake_camera() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0u8; 4096];
            let (_, from) = socket.recv_from(&mut buffer).await.unwrap();
            socket.send_to(b"not ONVIF", from).await.unwrap();
            let answer = "<d:ProbeMatch><d:Scopes>onvif://www.onvif.org/name/Cam</d:Scopes></d:ProbeMatch>";
            socket.send_to(answer.as_bytes(), from).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn onvif_discovery_against_a_local_camera() {
        let camera = fake_camera().await;
        let found = onvif_discover(Ipv4Addr::LOCALHOST, camera, Duration::from_millis(300)).await;
        assert_eq!(found.len(), 1);
        assert_eq!(found[&Ipv4Addr::LOCALHOST].name.as_deref(), Some("Cam"));

        // An address that is not on this machine cannot send a probe.
        let foreign = Ipv4Addr::new(192, 0, 2, 1);
        assert!(onvif_discover(foreign, camera, Duration::from_millis(300)).await.is_empty());
    }

    #[tokio::test]
    async fn system_onvif_uses_its_target() {
        let system = System { onvif_target: fake_camera().await, onvif_wait: Duration::from_millis(300) };
        let found = system.onvif(Ipv4Addr::LOCALHOST).await;
        assert_eq!(found[&Ipv4Addr::LOCALHOST].name.as_deref(), Some("Cam"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn onvif_discovery_ends_while_a_host_still_sends() {
        // A thread sends answers without a pause, so the socket of the
        // discovery is always readable.
        let flood = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = flood.local_addr().unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sender = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut buffer = [0u8; 4096];
                let (_, from) = flood.recv_from(&mut buffer).unwrap();
                let answer =
                    b"<d:ProbeMatch><d:Scopes>onvif://www.onvif.org/name/Flood</d:Scopes></d:ProbeMatch>";
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = flood.send_to(answer, from);
                }
            })
        };
        let discovery = onvif_discover(Ipv4Addr::LOCALHOST, addr, Duration::from_millis(300));
        let result = timeout(Duration::from_secs(5), discovery).await;
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        sender.join().unwrap();
        let found = result.expect("discovery must end at its deadline");
        assert_eq!(found[&Ipv4Addr::LOCALHOST].name.as_deref(), Some("Flood"));
    }

    fn mac_of(vendor: &str, last: u8) -> String {
        let line = include_str!("../data/oui.tsv").lines().find(|line| line.ends_with(vendor)).unwrap();
        format!("{}:{}:{}:00:00:{last:02x}", &line[0..2], &line[2..4], &line[4..6])
    }

    /// A network that the tests control.
    #[derive(Default)]
    struct FakeProbe {
        /// `None` makes `networks` fail.
        networks: Option<Vec<Network>>,
        arp: BTreeMap<Ipv4Addr, String>,
        /// Ports that answer in the first pass.
        fast: Vec<(Ipv4Addr, u16)>,
        /// Ports that answer only in the second pass.
        slow: Vec<(Ipv4Addr, u16)>,
        onvif: BTreeMap<Ipv4Addr, Onvif>,
        rtsp: BTreeMap<(Ipv4Addr, u16), String>,
        gateway: Option<Ipv4Addr>,
        /// PTR targets by server and asked name. A missing entry gives no answer.
        dns: BTreeMap<(SocketAddrV4, String), Vec<&'static str>>,
        /// The servers that got a name query.
        asked: std::sync::Mutex<Vec<SocketAddrV4>>,
        /// Each name query waits its full time and gets no answer.
        silent: bool,
    }

    impl Probe for FakeProbe {
        fn networks(&self) -> Result<Vec<Network>> {
            self.networks.clone().ok_or_else(|| anyhow::anyhow!("no interfaces"))
        }

        fn arp_table(&self) -> BTreeMap<Ipv4Addr, String> {
            self.arp.clone()
        }

        async fn open_ports(&self, targets: Vec<(Ipv4Addr, u16)>, wait: Duration) -> Vec<(Ipv4Addr, u16)> {
            let answering = if wait == CONNECT_TIMEOUT { &self.fast } else { &self.slow };
            targets.into_iter().filter(|target| answering.contains(target)).collect()
        }

        async fn onvif(&self, local: Ipv4Addr) -> BTreeMap<Ipv4Addr, Onvif> {
            if local == Ipv4Addr::new(192, 168, 1, 20) { self.onvif.clone() } else { BTreeMap::new() }
        }

        async fn rtsp(&self, ip: Ipv4Addr, port: u16) -> Option<String> {
            self.rtsp.get(&(ip, port)).cloned()
        }

        fn gateway(&self) -> Option<Ipv4Addr> {
            self.gateway
        }

        async fn dns(&self, server: SocketAddrV4, query: Vec<u8>, wait: Duration) -> Option<Vec<u8>> {
            assert!(!wait.is_zero() && wait <= NAME_WAIT, "{wait:?}");
            self.asked.lock().unwrap().push(server);
            let (_, name) = dns::tests::asked(&query);
            // No query asks for recursion.
            assert_eq!(query[2..4], [0, 0]);
            if self.silent {
                tokio::time::sleep(wait).await;
                return None;
            }
            let targets = self.dns.get(&(server, name.clone()))?;
            Some(dns::tests::answer(&query, 0x8400, &name, targets))
        }
    }

    fn home_network() -> Network {
        Network {
            interface: "en0".into(),
            local: Ipv4Addr::new(192, 168, 1, 20),
            base: u32::from(Ipv4Addr::new(192, 168, 1, 0)),
            prefix: 24,
            link_prefix: 24,
        }
    }

    #[tokio::test]
    async fn sweep_finds_cameras() {
        let ip = |last| Ipv4Addr::new(192, 168, 1, last);
        let guest = Network {
            interface: "en1".into(),
            local: Ipv4Addr::new(10, 0, 0, 2),
            base: u32::from(Ipv4Addr::new(10, 0, 0, 0)),
            prefix: 24,
            link_prefix: 24,
        };
        let probe = FakeProbe {
            networks: Some(vec![home_network(), guest]),
            arp: BTreeMap::from([
                (ip(2), mac_of("\tHangzhou Hikvision Digital Technology Co.,Ltd.", 2)),
                (ip(3), mac_of("\tWyze Labs Inc", 3)),
                (ip(4), mac_of("\tEspressif Inc.", 4)),
                (ip(5), "da:a1:19:00:00:05".into()),
                (ip(6), "00:11:22:00:00:06".into()),
                (ip(20), "00:11:22:00:00:20".into()),
                (Ipv4Addr::new(172, 16, 0, 1), "00:11:22:00:00:99".into()),
            ]),
            fast: vec![(ip(6), 8000), (ip(7), 554), (ip(8), 8554), (ip(8), 554), (ip(9), 37777)],
            slow: vec![(ip(6), 1935), (ip(6), 8000)],
            onvif: BTreeMap::from([(ip(10), Onvif { name: Some("Door".into()), ..Onvif::default() })]),
            rtsp: BTreeMap::from([((ip(7), 554), "yes".to_string()), ((ip(8), 8554), "Cam/1".to_string())]),
            ..FakeProbe::default()
        };
        let report = sweep_with(&probe).await.unwrap();
        assert_eq!(report.networks, ["192.168.1.0/24 (en0)", "10.0.0.0/24 (en1)"]);
        assert_eq!(report.addresses_probed, 2 * 253);

        let summary: Vec<(u8, Verdict, Option<&str>)> =
            report.hosts.iter().map(|h| (h.ip.octets()[3], h.verdict, h.rtsp.as_deref())).collect();
        assert_eq!(
            summary,
            [
                (2, Verdict::Likely, None),
                (7, Verdict::Likely, Some("yes")),
                (8, Verdict::Likely, Some("Cam/1")),
                (9, Verdict::Likely, None),
                (10, Verdict::Likely, None),
                (3, Verdict::Possible, None),
                (6, Verdict::Possible, None),
            ]
        );
        let hikvision = &report.hosts[0];
        assert!(hikvision.camera_vendor);
        assert!(hikvision.vendor.as_deref().unwrap().starts_with("Hangzhou Hikvision"));
        // The second pass adds 1935; 8000 answered in the first pass already.
        let ports: Vec<u16> = report.hosts[6].open_ports.iter().map(|p| p.port).collect();
        assert_eq!(ports, [1935, 8000]);
        assert_eq!(report.hosts[4].onvif.as_ref().unwrap().name.as_deref(), Some("Door"));

        // Other hosts: in the network, not the local address, no evidence.
        let others: Vec<(u8, Option<&str>)> =
            report.others.iter().map(|o| (o.ip.octets()[3], o.note)).collect();
        assert_eq!(others.len(), 2);
        assert_eq!(others[0].0, 4);
        assert!(others[0].1.unwrap().contains("low-cost cameras"));
        assert_eq!(others[1].0, 5);
        assert!(others[1].1.unwrap().contains("private address"));
    }

    #[tokio::test]
    async fn sweep_adds_names_and_services() {
        let ip = |last| Ipv4Addr::new(192, 168, 1, last);
        let mdns = |last| SocketAddrV4::new(ip(last), MDNS_PORT);
        let router = SocketAddrV4::new(ip(1), DNS_PORT);
        let reverse = |last| dns::reverse_name(ip(last));
        let services = dns::SERVICES.to_string();
        let probe = FakeProbe {
            networks: Some(vec![home_network()]),
            arp: BTreeMap::from([
                (ip(1), "00:11:22:00:00:01".into()),
                (ip(4), mac_of("\tEspressif Inc.", 4)),
                (ip(5), mac_of("\tRaspberry Pi Trading Ltd", 5)),
            ]),
            onvif: BTreeMap::from([(ip(10), Onvif::default())]),
            gateway: Some(ip(1)),
            dns: BTreeMap::from([
                // The host's own name comes first; the gateway's is the fallback.
                ((mdns(4), reverse(4)), vec!["heat-hub-1234.local"]),
                ((router, reverse(4)), vec!["heat-hub.lan"]),
                ((mdns(4), services.clone()), vec!["_meshcop._udp.local", "_hap._tcp.local"]),
                ((router, reverse(5)), vec!["charger\u{1b}[2J.lan"]),
                // A camera that calls itself harmless stays a camera.
                ((mdns(10), reverse(10)), vec!["harmless-printer.local"]),
                ((mdns(10), services), vec!["_ipp._tcp.local"]),
            ]),
            ..FakeProbe::default()
        };
        let report = sweep_with(&probe).await.unwrap();
        let camera = &report.hosts[0];
        assert_eq!(camera.verdict, Verdict::Likely);
        assert_eq!(camera.name.as_deref(), Some("harmless-printer.local"));
        assert_eq!(camera.services, ["_ipp._tcp"]);

        let by_ip = |last| report.others.iter().find(|o| o.ip == ip(last)).unwrap();
        let chip = by_ip(4);
        assert_eq!(chip.name.as_deref(), Some("heat-hub-1234.local"));
        assert_eq!(chip.services, ["_hap._tcp", "_meshcop._udp"]);
        // A name never removes the note.
        assert!(chip.needs_check && chip.note.unwrap().contains("low-cost cameras"));
        let computer = by_ip(5);
        assert_eq!(computer.name.as_deref(), Some("charger2J.lan"));
        assert!(computer.services.is_empty());
        assert!(computer.needs_check && computer.note.unwrap().contains("Linux computer"));
        let gateway = by_ip(1);
        assert_eq!((gateway.name.as_ref(), gateway.needs_check), (None, false));

        // Three queries for each host: two over mDNS, one to the gateway.
        let asked = probe.asked.lock().unwrap();
        assert_eq!(asked.len(), 4 * 3);
        assert_eq!(asked.iter().filter(|server| **server == router).count(), 4);
    }

    #[tokio::test]
    async fn gateway_outside_the_networks_gets_no_query() {
        let ip = Ipv4Addr::new(192, 168, 1, 4);
        let probe = FakeProbe {
            networks: Some(vec![home_network()]),
            arp: BTreeMap::from([(ip, "00:11:22:00:00:04".into())]),
            gateway: Some(Ipv4Addr::new(10, 9, 9, 1)),
            ..FakeProbe::default()
        };
        let report = sweep_with(&probe).await.unwrap();
        assert_eq!(report.others[0].name, None);
        assert_eq!(*probe.asked.lock().unwrap(), [SocketAddrV4::new(ip, MDNS_PORT); 2]);
    }

    #[tokio::test]
    async fn gateway_of_a_large_network_gets_queries() {
        // The interface is on a /22, and the sweep covers only its /24.
        let network = Network { link_prefix: 22, ..home_network() };
        let ip = Ipv4Addr::new(192, 168, 1, 4);
        let gateway = SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), DNS_PORT);
        let probe = FakeProbe {
            networks: Some(vec![network]),
            arp: BTreeMap::from([(ip, "00:11:22:00:00:04".into())]),
            gateway: Some(*gateway.ip()),
            dns: BTreeMap::from([((gateway, dns::reverse_name(ip)), vec!["box.lan"])]),
            ..FakeProbe::default()
        };
        let report = sweep_with(&probe).await.unwrap();
        assert_eq!(report.others[0].name.as_deref(), Some("box.lan"));
    }

    #[tokio::test(start_paused = true)]
    async fn name_queries_end_within_the_budget() {
        // 199 hosts that never answer: without the budget, their 398
        // queries take 7 rounds of NAME_WAIT.
        let arp = (1..=200)
            .map(|last| (Ipv4Addr::new(192, 168, 1, last), format!("00:11:22:00:00:{last:02x}")))
            .collect();
        let probe =
            FakeProbe { networks: Some(vec![home_network()]), arp, silent: true, ..FakeProbe::default() };
        let started = tokio::time::Instant::now();
        let report = sweep_with(&probe).await.unwrap();
        assert_eq!(report.others.len(), 199);
        assert!(started.elapsed() <= NAMES_BUDGET, "{:?}", started.elapsed());
        let asked = probe.asked.lock().unwrap().len();
        assert!((PARALLEL_LOOKUPS..2 * 199).contains(&asked), "{asked}");
    }

    #[tokio::test]
    async fn host_outside_the_networks_gets_no_name_query() {
        // An ONVIF answer can come from an address outside the swept networks.
        let outside = Ipv4Addr::new(172, 16, 0, 9);
        let probe = FakeProbe {
            networks: Some(vec![home_network()]),
            onvif: BTreeMap::from([(outside, Onvif::default())]),
            ..FakeProbe::default()
        };
        let report = sweep_with(&probe).await.unwrap();
        assert_eq!(report.hosts[0].ip, outside);
        assert!(probe.asked.lock().unwrap().is_empty());
    }

    /// Packets to send, each with `true` when the server socket sends it.
    type Replies = Vec<(bool, Vec<u8>)>;

    /// A DNS server on the loopback address. It reads up to two queries,
    /// then sends for each one the answers that `reply` gives, from the
    /// server socket (`true`) or from another socket (`false`).
    async fn fake_dns(reply: fn(usize, &[u8]) -> Replies) -> SocketAddrV4 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, socket.local_addr().unwrap().port());
        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            for count in 0..2 {
                let (read, from) = socket.recv_from(&mut buffer).await.unwrap();
                for (own, packet) in reply(count, &buffer[..read]) {
                    let sender = if own { &socket } else { &other };
                    sender.send_to(&packet, from).await.unwrap();
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn dns_exchange_against_a_local_server() {
        let wait = Duration::from_millis(400);
        let query = dns::query(0x1234, "4.1.168.192.in-addr.arpa");

        // A direct answer.
        let server = fake_dns(|_, q| vec![(true, dns::tests::answer(q, 0x8400, "x", &[]))]).await;
        let answer = MACHINE.dns(server, query.clone(), wait).await.unwrap();
        assert_eq!(answer[..2], [0x12, 0x34]);

        // An answer from another socket and one to another query come
        // first. The one from another socket has the right ID.
        let server = fake_dns(|_, q| {
            let mut forged = q.to_vec();
            forged.push(0xee);
            let mut wrong_id = q.to_vec();
            wrong_id[0] ^= 0xff;
            vec![(false, forged), (true, wrong_id), (true, q.to_vec())]
        })
        .await;
        assert_eq!(dns_exchange(server, &query, wait).await.as_deref(), Some(&query[..]));

        // The first query is lost, and the second one gets the answer.
        let server =
            fake_dns(|count, q| if count == 0 { Vec::new() } else { vec![(true, q.to_vec())] }).await;
        assert!(dns_exchange(server, &query, wait).await.is_some());

        // No answer at all.
        let server = fake_dns(|_, _| Vec::new()).await;
        let started = Instant::now();
        assert_eq!(dns_exchange(server, &query, wait).await, None);
        assert!(started.elapsed() >= wait);

        // A closed port. Linux reports it at once.
        let closed = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let started = Instant::now();
        assert_eq!(dns_exchange(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port), &query, wait).await, None);
        #[cfg(target_os = "linux")]
        assert!(started.elapsed() < wait / 2, "{:?}", started.elapsed());
        let _ = started;
    }

    #[tokio::test]
    async fn sweep_needs_a_network() {
        let failing = FakeProbe::default();
        assert_eq!(sweep_with(&failing).await.unwrap_err().to_string(), "no interfaces");
        let empty = FakeProbe { networks: Some(Vec::new()), ..FakeProbe::default() };
        assert_eq!(sweep_with(&empty).await.unwrap_err().to_string(), "no private IPv4 network found");
    }

    #[tokio::test]
    async fn quiet_network() {
        let probe = FakeProbe { networks: Some(vec![home_network()]), ..FakeProbe::default() };
        let report = sweep_with(&probe).await.unwrap();
        assert!(report.hosts.is_empty());
        assert!(report.others.is_empty());
    }
}

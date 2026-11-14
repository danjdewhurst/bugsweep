//! A laptop has no GPS. The MAC address of the default gateway identifies
//! the network, and the network identifies the place.

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command;

pub const UNKNOWN: &str = "unknown";

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn output(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Pad each MAC octet to two digits. macOS prints "a:b:c:1:2:3".
pub fn normalise_mac(mac: &str) -> Option<String> {
    let parts: Vec<&str> = mac.split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut octets = Vec::with_capacity(6);
    for part in parts {
        octets.push(format!("{:02x}", u8::from_str_radix(part, 16).ok()?));
    }
    Some(octets.join(":"))
}

#[cfg(target_os = "macos")]
fn gateway_mac() -> Option<String> {
    let route = output("route", &["-n", "get", "default"])?;
    let gateway = route.lines().find_map(|line| line.trim().strip_prefix("gateway:"))?.trim().to_string();
    let arp = output("arp", &["-n", &gateway])?;
    let mac = arp.split_whitespace().skip_while(|word| *word != "at").nth(1)?;
    normalise_mac(mac)
}

#[cfg(target_os = "linux")]
fn gateway_mac() -> Option<String> {
    let route = output("ip", &["route", "show", "default"])?;
    let gateway = route.split_whitespace().skip_while(|word| *word != "via").nth(1)?.to_string();
    let neigh = output("ip", &["neigh", "show", &gateway])?;
    let mac = neigh.split_whitespace().skip_while(|word| *word != "lladdr").nth(1)?;
    normalise_mac(mac)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn gateway_mac() -> Option<String> {
    None
}

/// A stable key for the current place, or "unknown".
pub fn detect() -> String {
    match gateway_mac() {
        Some(mac) => format!("net:{mac}"),
        None => UNKNOWN.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_is_padded() {
        assert_eq!(normalise_mac("a:b:c:1:2:3").as_deref(), Some("0a:0b:0c:01:02:03"));
        assert_eq!(normalise_mac("AA-BB-CC-DD-EE-FF").as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(normalise_mac("(incomplete)"), None);
    }
}

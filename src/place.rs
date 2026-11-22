//! A laptop has no GPS. The MAC address of the default gateway identifies
//! the network, and the network identifies the place.

use std::net::Ipv4Addr;
use std::process::Command;

pub const UNKNOWN: &str = "unknown";

/// Runs a command and gives its output.
pub(crate) type Runner<'a> = &'a dyn Fn(&str, &[&str]) -> Option<String>;

/// Run a program and return its standard output, or `None` when it cannot
/// start or fails.
pub(crate) fn output(program: &str, args: &[&str]) -> Option<String> {
    let (success, stdout) = output_any_status(program, args)?;
    success.then_some(stdout)
}

/// Run a program and return whether it succeeded and its standard output,
/// or `None` when it cannot start.
pub(crate) fn output_any_status(program: &str, args: &[&str]) -> Option<(bool, String)> {
    let out = Command::new(program).args(args).output().ok()?;
    Some((out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned()))
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

/// The word that follows `marker` in `text`.
fn word_after<'t>(text: &'t str, marker: &str) -> Option<&'t str> {
    text.split_whitespace().skip_while(|word| *word != marker).nth(1)
}

fn macos_gateway(run: Runner) -> Option<String> {
    let route = run("route", &["-n", "get", "default"])?;
    Some(route.lines().find_map(|line| line.trim().strip_prefix("gateway:"))?.trim().to_string())
}

fn linux_gateway(run: Runner) -> Option<String> {
    let route = run("ip", &["route", "show", "default"])?;
    Some(word_after(&route, "via")?.to_string())
}

fn macos_gateway_mac(run: Runner) -> Option<String> {
    let gateway = macos_gateway(run)?;
    let arp = run("arp", &["-n", &gateway])?;
    normalise_mac(word_after(&arp, "at")?)
}

fn linux_gateway_mac(run: Runner) -> Option<String> {
    let gateway = linux_gateway(run)?;
    let neigh = run("ip", &["neigh", "show", &gateway])?;
    normalise_mac(word_after(&neigh, "lladdr")?)
}

/// The IPv4 address of the default gateway on operating system `os`.
pub(crate) fn gateway_with(os: &str, run: Runner) -> Option<Ipv4Addr> {
    let gateway = match os {
        "macos" => macos_gateway(run),
        "linux" => linux_gateway(run),
        _ => None,
    };
    gateway?.parse().ok()
}

/// The IPv4 address of the default gateway of this machine.
pub(crate) fn gateway() -> Option<Ipv4Addr> {
    gateway_with(std::env::consts::OS, &output)
}

/// The place key on operating system `os` (as in `std::env::consts::OS`).
fn detect_with(os: &str, run: Runner) -> String {
    let mac = match os {
        "macos" => macos_gateway_mac(run),
        "linux" => linux_gateway_mac(run),
        _ => None,
    };
    match mac {
        Some(mac) => format!("net:{mac}"),
        None => UNKNOWN.to_string(),
    }
}

/// A stable key for the current place, or "unknown".
pub fn detect() -> String {
    detect_with(std::env::consts::OS, &output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_is_padded() {
        assert_eq!(normalise_mac("a:b:c:1:2:3").as_deref(), Some("0a:0b:0c:01:02:03"));
        assert_eq!(normalise_mac("AA-BB-CC-DD-EE-FF").as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(normalise_mac("(incomplete)"), None);
        assert_eq!(normalise_mac("zz:b:c:1:2:3"), None);
    }

    /// A runner that answers each command line from a list.
    fn fake(answers: &'static [(&'static str, &'static str)]) -> impl Fn(&str, &[&str]) -> Option<String> {
        move |program, args| {
            let line = std::iter::once(program).chain(args.iter().copied()).collect::<Vec<_>>().join(" ");
            answers.iter().find(|(command, _)| *command == line).map(|(_, answer)| answer.to_string())
        }
    }

    #[test]
    fn macos_gateway() {
        let run = fake(&[
            (
                "route -n get default",
                "   route to: default\ndestination: default\n    gateway: 192.168.1.1\n",
            ),
            ("arp -n 192.168.1.1", "? (192.168.1.1) at a4:b:c:d:e:f on en0 ifscope [ethernet]\n"),
        ]);
        assert_eq!(detect_with("macos", &run), "net:a4:0b:0c:0d:0e:0f");
        // An answer without a MAC address, and a missing gateway line.
        let run = fake(&[
            ("route -n get default", "gateway: 192.168.1.1\n"),
            ("arp -n 192.168.1.1", "192.168.1.1 (192.168.1.1) -- no entry\n"),
        ]);
        assert_eq!(detect_with("macos", &run), UNKNOWN);
        assert_eq!(detect_with("macos", &fake(&[("route -n get default", "interface: en0\n")])), UNKNOWN);
        assert_eq!(detect_with("macos", &fake(&[])), UNKNOWN);
    }

    #[test]
    fn linux_gateway() {
        let run = fake(&[
            ("ip route show default", "default via 10.0.0.1 dev wlan0 proto dhcp metric 600\n"),
            ("ip neigh show 10.0.0.1", "10.0.0.1 dev wlan0 lladdr AA:BB:CC:00:11:22 REACHABLE\n"),
        ]);
        assert_eq!(detect_with("linux", &run), "net:aa:bb:cc:00:11:22");
        let run = fake(&[
            ("ip route show default", "default via 10.0.0.1 dev wlan0\n"),
            ("ip neigh show 10.0.0.1", "10.0.0.1 dev wlan0 FAILED\n"),
        ]);
        assert_eq!(detect_with("linux", &run), UNKNOWN);
        assert_eq!(detect_with("linux", &fake(&[("ip route show default", "")])), UNKNOWN);
        assert_eq!(detect_with("linux", &fake(&[])), UNKNOWN);
    }

    #[test]
    fn gateway_addresses() {
        let mac = fake(&[("route -n get default", "    gateway: 192.168.1.1\n")]);
        assert_eq!(gateway_with("macos", &mac), Some(Ipv4Addr::new(192, 168, 1, 1)));
        let linux = fake(&[("ip route show default", "default via 10.0.0.1 dev wlan0\n")]);
        assert_eq!(gateway_with("linux", &linux), Some(Ipv4Addr::new(10, 0, 0, 1)));
        // An IPv6 gateway, no gateway, and another system.
        let v6 = fake(&[("ip route show default", "default via fe80::1 dev wlan0\n")]);
        assert_eq!(gateway_with("linux", &v6), None);
        assert_eq!(gateway_with("linux", &fake(&[])), None);
        assert_eq!(gateway_with("windows", &mac), None);
        // The result depends on the network of this machine. The call must
        // not fail.
        let _ = gateway();
    }

    #[test]
    fn other_systems_are_unknown() {
        let run = fake(&[("route -n get default", "gateway: 192.168.1.1\n")]);
        assert_eq!(detect_with("windows", &run), UNKNOWN);
    }

    #[test]
    fn detect_on_this_machine() {
        // The result depends on the network, but it always has one of two forms.
        let place = detect();
        assert!(place == UNKNOWN || place.starts_with("net:"), "{place}");
    }

    #[cfg(unix)]
    #[test]
    fn output_of_real_programs() {
        assert_eq!(output("sh", &["-c", "echo hello"]).as_deref(), Some("hello\n"));
        assert_eq!(output("sh", &["-c", "echo partial; exit 3"]), None);
        let partial = output_any_status("sh", &["-c", "echo partial; exit 3"]);
        assert_eq!(partial, Some((false, "partial\n".to_string())));
        assert_eq!(output("bugsweep-no-such-program", &[]), None);
    }
}

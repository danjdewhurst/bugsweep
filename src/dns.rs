//! A small DNS client for the names of hosts on the local network: the PTR
//! record of an address, and the DNS-SD list of service types. It makes one
//! query and reads one answer. The network code is in `lan`.
//!
//! Names and services come from the devices on the network, so they are
//! untrusted text. [`clean`] keeps only the characters of a host name and
//! limits the length.

use std::net::Ipv4Addr;

const TYPE_PTR: u16 = 12;
const CLASS_IN: u16 = 1;
/// mDNS uses the top bit of the class for "cache flush".
const CLASS_MASK: u16 = 0x7fff;
/// The DNS-SD name whose PTR records are the service types of a host.
pub const SERVICES: &str = "_services._dns-sd._udp.local";
/// Longest host name that the sweep keeps, in characters.
pub const MAX_NAME: usize = 80;
/// Longest service type that the sweep keeps, in characters.
const MAX_SERVICE: usize = 48;
/// Most service types that the sweep keeps for one host.
const MAX_SERVICES: usize = 16;
/// Most compression pointers in one name. More means a loop.
const MAX_JUMPS: usize = 16;
/// Longest name on the wire, in bytes (RFC 1035).
const MAX_WIRE_NAME: usize = 255;
/// Most PTR targets that the parser keeps from one answer.
const MAX_TARGETS: usize = 32;

/// The reverse name of an address, for example "4.1.168.192.in-addr.arpa".
pub fn reverse_name(ip: Ipv4Addr) -> String {
    let [a, b, c, d] = ip.octets();
    format!("{d}.{c}.{b}.{a}.in-addr.arpa")
}

/// A PTR query for `name`. The "recursion desired" bit stays off. It asks a
/// router to answer from its own data (for example its DHCP leases), and
/// most routers then do not send the question to their upstream DNS.
pub fn query(id: u16, name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(18 + name.len());
    out.extend(id.to_be_bytes());
    // No flags, one question, no records.
    out.extend([0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend(label.as_bytes());
    }
    out.push(0);
    out.extend(TYPE_PTR.to_be_bytes());
    out.extend(CLASS_IN.to_be_bytes());
    out
}

fn u16_at(packet: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*packet.get(at)?, *packet.get(at + 1)?]))
}

/// Read the name that starts at `start`. Returns the name and the position
/// after it.
fn read_name(packet: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut at = start;
    let mut after = None;
    let mut jumps = 0;
    let mut wire_length = 1;
    loop {
        let length = usize::from(*packet.get(at)?);
        match length & 0xc0 {
            0 if length == 0 => break,
            0 => {
                let label = packet.get(at + 1..at + 1 + length)?;
                wire_length += 1 + length;
                if wire_length > MAX_WIRE_NAME {
                    return None;
                }
                labels.push(String::from_utf8_lossy(label).into_owned());
                at += 1 + length;
            }
            0xc0 => {
                jumps += 1;
                if jumps > MAX_JUMPS {
                    return None;
                }
                let low = usize::from(*packet.get(at + 1)?);
                after.get_or_insert(at + 2);
                at = ((length & 0x3f) << 8) | low;
            }
            _ => return None,
        }
    }
    Some((labels.join("."), after.unwrap_or(at + 1)))
}

/// The targets of the PTR records for `name` in the answer to query `id`.
/// An error answer, or one that does not parse, gives no targets.
pub fn ptr_targets(packet: &[u8], id: u16, name: &str) -> Vec<String> {
    let mut targets = Vec::new();
    let (Some(answer_id), Some(flags)) = (u16_at(packet, 0), u16_at(packet, 2)) else {
        return targets;
    };
    // The answer bit must be set, and the result code must be 0.
    if answer_id != id || flags & 0x8000 == 0 || flags & 0x000f != 0 {
        return targets;
    }
    let questions = u16_at(packet, 4).unwrap_or(0);
    let answers = u16_at(packet, 6).unwrap_or(0);
    let mut at = 12;
    for _ in 0..questions {
        let Some((_, after)) = read_name(packet, at) else { return targets };
        at = after + 4;
    }
    for _ in 0..answers {
        if targets.len() == MAX_TARGETS {
            break;
        }
        let Some((owner, after)) = read_name(packet, at) else { break };
        let (Some(kind), Some(class), Some(length)) =
            (u16_at(packet, after), u16_at(packet, after + 2), u16_at(packet, after + 8))
        else {
            break;
        };
        let data = after + 10;
        if kind == TYPE_PTR
            && class & CLASS_MASK == CLASS_IN
            && owner.eq_ignore_ascii_case(name)
            && let Some((target, _)) = read_name(packet, data)
        {
            targets.push(target);
        }
        at = data + usize::from(length);
    }
    targets
}

/// Device text made safe to show. Host names and service types use only
/// ASCII letters, digits, "-", "_" and ".", so every other character is
/// removed: control characters, hidden Unicode, spaces and punctuation that
/// could fake another field. Dots at the ends are removed too, and the text
/// gets at most `max` characters. `None` when nothing is left.
pub fn clean(text: &str, max: usize) -> Option<String> {
    let kept: String =
        text.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')).collect();
    let kept = kept.trim_matches('.');
    if kept.is_empty() {
        return None;
    }
    if kept.chars().count() <= max {
        return Some(kept.to_string());
    }
    Some(kept.chars().take(max - 1).chain(['…']).collect())
}

/// The first host name in a list of PTR targets, made safe to show.
pub fn host_name<'a>(targets: impl IntoIterator<Item = &'a String>) -> Option<String> {
    targets.into_iter().find_map(|target| clean(target, MAX_NAME))
}

/// Service types from the PTR targets of [`SERVICES`], for example
/// "_hap._tcp". Sorted, without repeats, made safe to show, and limited in
/// number. A target that is not a service type is left out.
pub fn service_types(targets: &[String]) -> Vec<String> {
    let mut types: Vec<String> = targets
        .iter()
        .filter_map(|target| {
            let short = match target.len().checked_sub(6) {
                Some(at) if target.get(at..).is_some_and(|end| end.eq_ignore_ascii_case(".local")) => {
                    &target[..at]
                }
                _ => target.as_str(),
            };
            // Each label of a service type has a "_" and a name.
            clean(short, MAX_SERVICE)
                .filter(|kind| kind.split('.').all(|label| label.len() > 1 && label.starts_with('_')))
        })
        .collect();
    types.sort();
    types.dedup();
    types.truncate(MAX_SERVICES);
    types
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Encode a name with no compression.
    fn name_bytes(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend(label.as_bytes());
        }
        out.push(0);
        out
    }

    /// An answer to `query` with one PTR record from `owner` to each target.
    /// The first record points back to the question for its owner, as most
    /// servers do. `flags` is the second header field.
    pub(crate) fn answer(query: &[u8], flags: u16, owner: &str, targets: &[&str]) -> Vec<u8> {
        let mut out = query[..2].to_vec();
        out.extend(flags.to_be_bytes());
        out.extend([0, 1]);
        out.extend((targets.len() as u16).to_be_bytes());
        out.extend([0, 0, 0, 0]);
        out.extend(&query[12..]);
        for (i, target) in targets.iter().enumerate() {
            if i == 0 {
                // A pointer to the name of the question at offset 12.
                out.extend([0xc0, 12]);
            } else {
                out.extend(name_bytes(owner));
            }
            // PTR, class IN with the cache-flush bit, TTL 120.
            out.extend([0, 12, 0x80, 1, 0, 0, 0, 120]);
            let data = name_bytes(target);
            out.extend((data.len() as u16).to_be_bytes());
            out.extend(data);
        }
        out
    }

    /// The ID and the asked name of a query.
    pub(crate) fn asked(query: &[u8]) -> (u16, String) {
        (u16_at(query, 0).unwrap(), read_name(query, 12).unwrap().0)
    }

    #[test]
    fn reverse_names() {
        assert_eq!(reverse_name(Ipv4Addr::new(192, 168, 1, 4)), "4.1.168.192.in-addr.arpa");
    }

    #[test]
    fn query_layout() {
        let packet = query(0xbeef, "a.bc");
        assert_eq!(
            packet,
            [0xbe, 0xef, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 2, b'b', b'c', 0, 0, 12, 0, 1]
        );
        assert_eq!(asked(&packet), (0xbeef, "a.bc".to_string()));
    }

    #[test]
    fn ptr_answer_round_trip() {
        let name = reverse_name(Ipv4Addr::new(10, 0, 0, 7));
        let ask = query(7, &name);
        let packet = answer(&ask, 0x8400, &name, &["heat-hub.local", "other.local"]);
        assert_eq!(ptr_targets(&packet, 7, &name), ["heat-hub.local", "other.local"]);
        // Case does not matter for the owner name.
        assert_eq!(ptr_targets(&packet, 7, &name.to_uppercase()).len(), 2);
    }

    #[test]
    fn wrong_answers_give_nothing() {
        let name = "4.1.168.192.in-addr.arpa";
        let ask = query(9, name);
        let good = answer(&ask, 0x8180, name, &["box.lan"]);
        assert_eq!(ptr_targets(&good, 9, name), ["box.lan"]);
        // Another ID, a query and not an answer, and an error code.
        assert!(ptr_targets(&good, 10, name).is_empty());
        assert!(ptr_targets(&answer(&ask, 0x0100, name, &["box.lan"]), 9, name).is_empty());
        assert!(ptr_targets(&answer(&ask, 0x8183, name, &["box.lan"]), 9, name).is_empty());
        // Too short for a header, and a record for another name.
        assert!(ptr_targets(&good[..3], 9, name).is_empty());
        assert!(ptr_targets(&good, 9, "5.1.168.192.in-addr.arpa").is_empty());
    }

    #[test]
    fn records_of_other_types_are_skipped() {
        let name = "_services._dns-sd._udp.local";
        let mut packet = answer(&query(3, name), 0x8400, name, &["_hap._tcp.local"]);
        // Two answers: an A record first, then the PTR record.
        packet[7] = 2;
        let question_end = 12 + name.len() + 2 + 4;
        let a_record = [0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 10, 0, 0, 7];
        packet.splice(question_end..question_end, a_record);
        assert_eq!(ptr_targets(&packet, 3, name), ["_hap._tcp.local"]);
    }

    #[test]
    fn broken_packets_end_the_parse() {
        let name = "x.local";
        let ask = query(5, name);
        let good = answer(&ask, 0x8400, name, &["a.local", "b.local"]);
        // Each cut gives no panic and at most the records before it.
        for end in 0..good.len() {
            assert!(ptr_targets(&good[..end], 5, name).len() < 2, "cut at {end}");
        }
        // A question that does not parse.
        let mut bad_question = good.clone();
        bad_question[12] = 0x40;
        assert!(ptr_targets(&bad_question, 5, name).is_empty());
        // A target that does not parse.
        let mut bad_target = answer(&ask, 0x8400, name, &["a.local"]);
        let last = bad_target.len() - 9;
        bad_target[last] = 0x80;
        assert!(ptr_targets(&bad_target, 5, name).is_empty());
    }

    #[test]
    fn name_pointers() {
        // "a" then a pointer to "b.c" at offset 6.
        let packet = [1, b'a', 0xc0, 6, 0xff, 0xff, 1, b'b', 1, b'c', 0];
        assert_eq!(read_name(&packet, 0), Some(("a.b.c".to_string(), 4)));
        assert_eq!(read_name(&packet, 6), Some(("b.c".to_string(), 11)));
        // A pointer to itself loops; a cut pointer and a label past the end.
        assert_eq!(read_name(&[0xc0, 0], 0), None);
        assert_eq!(read_name(&[0xc0], 0), None);
        assert_eq!(read_name(&[5, b'a'], 0), None);
        assert_eq!(read_name(&[0x80, 0], 0), None);
        // A name longer than 255 bytes, made from pointers to one label.
        let mut long = vec![63];
        long.extend([b'x'; 63]);
        long.extend([0xc0, 0]);
        assert_eq!(read_name(&long, 0), None);
    }

    #[test]
    fn many_targets_are_capped() {
        let name = "_services._dns-sd._udp.local";
        let targets: Vec<String> = (0..50).map(|i| format!("_s{i}._tcp.local")).collect();
        let refs: Vec<&str> = targets.iter().map(String::as_str).collect();
        let packet = answer(&query(4, name), 0x8400, name, &refs);
        assert_eq!(ptr_targets(&packet, 4, name).len(), MAX_TARGETS);
    }

    #[test]
    fn device_text_is_cleaned() {
        assert_eq!(clean("  heat-hub.local. ", 80).as_deref(), Some("heat-hub.local"));
        assert_eq!(clean("cam\u{1b}[31m\u{202e}era\n", 80).as_deref(), Some("cam31mera"));
        // Hidden Unicode, line separators and text that fakes another field.
        let hidden = "hub\u{e0041}\u{e0042}\u{fe0f}\u{061c}\u{2028}\u{00ad}.local";
        assert_eq!(clean(hidden, 80).as_deref(), Some("hub.local"));
        assert_eq!(clean("x; services: _ipp._tcp (safe)", 80).as_deref(), Some("xservices_ipp._tcpsafe"));
        assert_eq!(clean("\u{7}\u{200b} . ", 80), None);
        assert_eq!(clean("abcdef", 4).as_deref(), Some("abc…"));
        assert_eq!(clean("abcd", 4).as_deref(), Some("abcd"));
        let long = "x".repeat(300);
        assert_eq!(host_name(&[String::new(), long]).unwrap().chars().count(), MAX_NAME);
        assert_eq!(host_name(&[]), None);
    }

    #[test]
    fn service_type_list() {
        let targets: Vec<String> = [
            "_meshcop._udp.local",
            "_hap._tcp.LOCAL",
            "_hap._tcp.local",
            "_raw._tcp",
            "not-a-service.local",
            "\u{1b}",
            "local",
        ]
        .map(str::to_string)
        .into();
        assert_eq!(service_types(&targets), ["_hap._tcp", "_meshcop._udp", "_raw._tcp"]);
        let many: Vec<String> = (0..40).map(|i| format!("_s{i:02}._tcp.local")).collect();
        assert_eq!(service_types(&many).len(), MAX_SERVICES);
        // A multi-byte character just before the end must not split.
        assert_eq!(service_types(&["_é.loca".to_string()]), Vec::<String>::new());
        assert_eq!(service_types(&["_hap.tcp.local".to_string()]), Vec::<String>::new());
    }
}

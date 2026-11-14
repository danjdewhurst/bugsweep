//! Vendor names from the public Bluetooth SIG assigned numbers and from the
//! IEEE MA-L registry of MAC address prefixes.
//! Refresh the data files with `scripts/update-vendors.sh`.

use std::collections::HashMap;
use std::sync::OnceLock;

use uuid::Uuid;

use crate::model::short_uuid;

const COMPANY_IDS: &str = include_str!("../data/company_ids.tsv");
const MEMBER_UUIDS: &str = include_str!("../data/member_uuids.tsv");
const OUI: &str = include_str!("../data/oui.tsv");

fn parse(table: &'static str) -> HashMap<u16, &'static str> {
    table
        .lines()
        .filter_map(|line| {
            let (id, name) = line.split_once('\t')?;
            Some((u16::from_str_radix(id, 16).ok()?, name))
        })
        .collect()
}

/// Company name for a Bluetooth SIG company ID.
pub fn company(id: u16) -> Option<&'static str> {
    static TABLE: OnceLock<HashMap<u16, &'static str>> = OnceLock::new();
    TABLE.get_or_init(|| parse(COMPANY_IDS)).get(&id).copied()
}

/// Owner of a 16-bit member service UUID.
pub fn uuid_owner(uuid: &Uuid) -> Option<&'static str> {
    static TABLE: OnceLock<HashMap<u16, &'static str>> = OnceLock::new();
    let short = short_uuid(uuid)?;
    TABLE.get_or_init(|| parse(MEMBER_UUIDS)).get(&short).copied()
}

/// The first three octets of a MAC address as a number.
fn mac_prefix(mac: &str) -> Option<u32> {
    let mut octets = mac.split([':', '-']);
    let mut prefix = 0u32;
    for _ in 0..3 {
        prefix = (prefix << 8) | u32::from(u8::from_str_radix(octets.next()?, 16).ok()?);
    }
    Some(prefix)
}

/// Registered owner of the MAC address prefix (24-bit blocks only).
pub fn mac_vendor(mac: &str) -> Option<&'static str> {
    static TABLE: OnceLock<HashMap<u32, &'static str>> = OnceLock::new();
    let table = TABLE.get_or_init(|| {
        OUI.lines()
            .filter_map(|line| {
                let (prefix, name) = line.split_once('\t')?;
                Some((u32::from_str_radix(prefix, 16).ok()?, name))
            })
            .collect()
    });
    table.get(&mac_prefix(mac)?).copied()
}

/// A locally administered address. Phones and laptops use a random one of
/// these for each network, so it has no vendor.
pub fn mac_is_private(mac: &str) -> bool {
    mac_prefix(mac).is_some_and(|prefix| (prefix >> 16) & 0x02 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::parse_uuid;

    #[test]
    fn known_vendors() {
        assert_eq!(company(0x004C), Some("Apple, Inc."));
        assert_eq!(company(0x0FB2), Some("PLAUD Inc."));
        assert_eq!(uuid_owner(&parse_uuid("feed").unwrap()), Some("Tile, Inc."));
    }

    #[test]
    fn mac_vendors() {
        assert_eq!(mac_vendor("00:25:df:12:34:56"), Some("Axon Enterprise, Inc."));
        assert_eq!(mac_vendor("00-25-DF-12-34-56"), Some("Axon Enterprise, Inc."));
        assert_eq!(mac_vendor("not a mac"), None);
        assert!(!mac_is_private("00:25:df:12:34:56"));
        assert!(mac_is_private("da:a1:19:00:00:01"));
        assert_eq!(mac_vendor("da:a1:19:00:00:01"), None);
    }
}

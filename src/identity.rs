//! Keys that identify a device across address changes.
//!
//! The platform ID changes when a device changes its Bluetooth address, and
//! most devices do that every few minutes. A device therefore gets more than
//! one key. Each key comes from data that can stay the same for longer:
//!
//! - `id:`       the platform ID (exact, but short-lived)
//! - `findmy:`, `fmdn:`, `smarttag:`  the public key or ID that a tracker
//!   sends. It stays the same for about 24 hours when the tracker is away
//!   from its owner.
//! - `name:`     the advertised name. Two devices of the same model can
//!   have the same name.
//! - `data:`, `svc:`  the payload, when it did not change for some time.
//!   Two devices of the same model can send the same payload.

use crate::model::{Advert, parse_uuid, uuid_label};

/// How a key identifies a device, weakest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Basis {
    Data,
    Name,
    Tracker,
    Id,
}

impl Basis {
    /// Short text for "matched by the same ...".
    pub fn label(self) -> &'static str {
        match self {
            Basis::Id => "ID",
            Basis::Tracker => "tracker key",
            Basis::Name => "name",
            Basis::Data => "data",
        }
    }

    /// The basis of a stored key, from its prefix.
    pub fn of_key(key: &str) -> Basis {
        match key.split_once(':').map(|(prefix, _)| prefix) {
            Some("findmy" | "fmdn" | "smarttag") => Basis::Tracker,
            Some("name") => Basis::Name,
            Some("data" | "svc") => Basis::Data,
            _ => Basis::Id,
        }
    }
}

/// The prefixes of the stored keys.
const PREFIXES: &[&str] = &["id", "findmy", "fmdn", "smarttag", "name", "data", "svc"];

/// The stored key for a device ID that a person or a script gives: a key as
/// `followers` prints it ("id:…", "name:…", "findmy:…"), or a bare platform
/// ID as in the `id` field of `scan --json`. `None` when the ID is empty.
pub fn key_from_user(text: &str) -> Option<String> {
    let text = text.trim();
    let bare = match text.split_once(':') {
        Some((prefix, rest)) if PREFIXES.contains(&prefix) => rest,
        _ => return (!text.is_empty()).then(|| format!("id:{text}")),
    };
    (!bare.trim().is_empty()).then(|| text.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub basis: Basis,
    pub text: String,
}

const APPLE: u16 = 0x004C;
/// A shorter payload has too little data to identify one device.
const MIN_PAYLOAD: usize = 6;
/// Longest payload part that goes into a key.
const MAX_PAYLOAD: usize = 31;
const MIN_NAME: usize = 3;

fn key(basis: Basis, text: String) -> Key {
    Key { basis, text }
}

/// All keys of a device, strongest first. `payload_stable` says that the
/// payload did not change for some time, so it can be an identifier.
pub fn keys(advert: &Advert, payload_stable: bool) -> Vec<Key> {
    let mut keys = vec![key(Basis::Id, format!("id:{}", advert.id))];

    // Apple Find My, separated: 12 19 <status> <22 bytes of the public key>.
    if let Some(data) = advert.manufacturer_data.get(&APPLE)
        && data.starts_with(&[0x12, 0x19])
        && data.len() >= 25
    {
        keys.push(key(Basis::Tracker, format!("findmy:{}", hex::encode(&data[3..25]))));
    }
    let feaa = parse_uuid("feaa").expect("valid UUID");
    let fd5a = parse_uuid("fd5a").expect("valid UUID");
    // Google Find Hub: <frame type 0x40 or 0x41> <20-byte ephemeral ID>.
    if let Some(data) = advert.service_data.get(&feaa)
        && matches!(data.first(), Some(0x40 | 0x41))
        && data.len() >= 21
    {
        keys.push(key(Basis::Tracker, format!("fmdn:{}", hex::encode(&data[1..21]))));
    }
    // Samsung SmartTag: bytes 4..12 are the privacy ID.
    if let Some(data) = advert.service_data.get(&fd5a)
        && data.len() >= 12
    {
        keys.push(key(Basis::Tracker, format!("smarttag:{}", hex::encode(&data[4..12]))));
    }

    if let Some(name) = advert.name.as_deref().map(str::trim)
        && name.chars().count() >= MIN_NAME
    {
        keys.push(key(Basis::Name, format!("name:{name}")));
    }

    if payload_stable {
        for (company, data) in &advert.manufacturer_data {
            // Apple payloads change often or are the same on many devices.
            if *company != APPLE && data.len() >= MIN_PAYLOAD {
                let part = &data[..data.len().min(MAX_PAYLOAD)];
                keys.push(key(Basis::Data, format!("data:{company:04x}:{}", hex::encode(part))));
            }
        }
        for (uuid, data) in &advert.service_data {
            if *uuid != feaa && *uuid != fd5a && data.len() >= MIN_PAYLOAD {
                let part = &data[..data.len().min(MAX_PAYLOAD)];
                keys.push(key(Basis::Data, format!("svc:{}:{}", uuid_label(uuid), hex::encode(part))));
            }
        }
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_from_people_and_scripts() {
        assert_eq!(key_from_user(" 5F3A-UUID ").as_deref(), Some("id:5F3A-UUID"));
        // A Linux ID is a MAC address, and its first octet is not a prefix.
        assert_eq!(key_from_user("AA:BB:CC:DD:EE:FF").as_deref(), Some("id:AA:BB:CC:DD:EE:FF"));
        assert_eq!(key_from_user("id:abc").as_deref(), Some("id:abc"));
        assert_eq!(key_from_user("findmy:00ff").as_deref(), Some("findmy:00ff"));
        assert_eq!(key_from_user("name:My watch").as_deref(), Some("name:My watch"));
        assert_eq!(key_from_user(""), None);
        assert_eq!(key_from_user("name: "), None);
    }

    fn texts(advert: &Advert, stable: bool) -> Vec<String> {
        keys(advert, stable).into_iter().map(|k| k.text).collect()
    }

    #[test]
    fn each_basis_has_its_own_label() {
        let labels: Vec<&str> =
            [Basis::Id, Basis::Tracker, Basis::Name, Basis::Data].into_iter().map(Basis::label).collect();
        assert_eq!(labels, ["ID", "tracker key", "name", "data"]);
    }

    #[test]
    fn plain_device_has_only_the_id() {
        let advert = Advert { id: "abc".into(), ..Default::default() };
        assert_eq!(texts(&advert, true), ["id:abc"]);
    }

    #[test]
    fn name_key_needs_three_characters() {
        let mut advert = Advert { id: "abc".into(), name: Some(" TV ".into()), ..Default::default() };
        assert_eq!(texts(&advert, false), ["id:abc"]);
        advert.name = Some("Key tag".into());
        assert_eq!(texts(&advert, false), ["id:abc", "name:Key tag"]);
    }

    #[test]
    fn find_my_key_is_the_public_key_part() {
        let mut data = vec![0x12, 0x19, 0x24];
        data.extend(1..=22u8);
        data.extend([0xAA, 0xBB]);
        let mut advert = Advert { id: "abc".into(), ..Default::default() };
        advert.manufacturer_data.insert(APPLE, data);
        let expected = format!("findmy:{}", hex::encode((1..=22u8).collect::<Vec<_>>()));
        // Apple payloads never make a data key, also when they are stable.
        assert_eq!(texts(&advert, true), ["id:abc".to_string(), expected]);
    }

    #[test]
    fn tracker_keys_from_service_data() {
        let mut advert = Advert { id: "abc".into(), ..Default::default() };
        let mut frame = vec![0x41];
        frame.extend([7u8; 20]);
        advert.service_data.insert(parse_uuid("feaa").unwrap(), frame);
        advert
            .service_data
            .insert(parse_uuid("fd5a").unwrap(), vec![0x13, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let keys = texts(&advert, true);
        assert!(keys.contains(&format!("fmdn:{}", "07".repeat(20))));
        assert!(keys.contains(&"smarttag:0102030405060708".to_string()));
        assert!(!keys.iter().any(|k| k.starts_with("svc:")), "{keys:?}");
    }

    #[test]
    fn data_keys_need_a_stable_payload() {
        let mut advert = Advert { id: "abc".into(), ..Default::default() };
        advert.manufacturer_data.insert(0x0075, vec![0x42, 4, 1, 0x80, 0x60, 0xCC]);
        advert.manufacturer_data.insert(0x0006, vec![1, 2]);
        advert.service_data.insert(parse_uuid("fe9f").unwrap(), vec![9; 40]);
        assert_eq!(texts(&advert, false), ["id:abc"]);
        assert_eq!(
            texts(&advert, true),
            [
                "id:abc".to_string(),
                "data:0075:4204018060cc".to_string(),
                format!("svc:fe9f:{}", "09".repeat(31)),
            ]
        );
    }

    #[test]
    fn basis_from_key_prefix() {
        assert_eq!(Basis::of_key("id:41314d4a-25a7"), Basis::Id);
        assert_eq!(Basis::of_key("findmy:00ff"), Basis::Tracker);
        assert_eq!(Basis::of_key("smarttag:00ff"), Basis::Tracker);
        assert_eq!(Basis::of_key("name:Key: tag"), Basis::Name);
        assert_eq!(Basis::of_key("svc:fe9f:00"), Basis::Data);
        assert!(Basis::Id > Basis::Tracker && Basis::Tracker > Basis::Name && Basis::Name > Basis::Data);
    }
}

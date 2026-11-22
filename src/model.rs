//! Plain data types shared by the scanner, the classifier and the interfaces.

use std::collections::BTreeMap;

use uuid::Uuid;

/// The latest advertisement data of one Bluetooth LE device.
#[derive(Debug, Clone, Default)]
pub struct Advert {
    /// Platform identifier. A MAC address on Linux, Windows and Android.
    /// A per-host random UUID on macOS and iOS.
    pub id: String,
    /// MAC address, when the platform gives it.
    pub address: Option<String>,
    pub name: Option<String>,
    pub rssi: Option<i16>,
    pub tx_power: Option<i16>,
    /// Manufacturer data by Bluetooth SIG company ID. The ID is not in the bytes.
    pub manufacturer_data: BTreeMap<u16, Vec<u8>>,
    pub service_data: BTreeMap<Uuid, Vec<u8>>,
    pub services: Vec<Uuid>,
}

impl Advert {
    /// The advert carries nothing: no signal value, no name, no transmit
    /// power, no manufacturer data, no services and no service data. Such
    /// an entry is noise, for example a device that the system cached.
    pub fn is_empty(&self) -> bool {
        self.rssi.is_none()
            && self.name.as_deref().is_none_or(|name| name.trim().is_empty())
            && self.tx_power.is_none()
            && self.manufacturer_data.is_empty()
            && self.services.is_empty()
            && self.service_data.is_empty()
    }
}

/// A character that changes the direction of text, hides itself, or breaks
/// a line. `char::is_control` does not cover these.
fn is_hidden(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'
            | '\u{061c}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{e0000}'..='\u{e0fff}'
    )
}

/// Device text for a terminal line: no control characters and no hidden
/// characters, so an advertised name cannot move the cursor, clear the
/// screen or hide text.
pub fn printable(text: &str) -> String {
    text.chars().filter(|c| !c.is_control() && !is_hidden(*c)).collect()
}

const BASE_UUID_TAIL: u128 = 0x0000_1000_8000_0080_5f9b_34fb;

/// Expand a 16-bit or 32-bit short UUID, or parse a full UUID.
pub fn parse_uuid(text: &str) -> Option<Uuid> {
    let text = text.trim();
    let short = text.strip_prefix("0x").unwrap_or(text);
    if short.len() == 4 || short.len() == 8 {
        let value = u32::from_str_radix(short, 16).ok()?;
        return Some(Uuid::from_u128(((value as u128) << 96) | BASE_UUID_TAIL));
    }
    Uuid::parse_str(text).ok()
}

/// The 16-bit form of a UUID, when it is in the Bluetooth base range.
pub fn short_uuid(uuid: &Uuid) -> Option<u16> {
    let value = uuid.as_u128();
    let is_base = value & ((1u128 << 96) - 1) == BASE_UUID_TAIL;
    let head = (value >> 96) as u32;
    (is_base && head <= 0xFFFF).then_some(head as u16)
}

/// Short text form: "fd5a" for base-range UUIDs, the full UUID otherwise.
pub fn uuid_label(uuid: &Uuid) -> String {
    match short_uuid(uuid) {
        Some(short) => format!("{short:04x}"),
        None => uuid.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_uuid_round_trip() {
        let uuid = parse_uuid("fd5a").unwrap();
        assert_eq!(uuid.to_string(), "0000fd5a-0000-1000-8000-00805f9b34fb");
        assert_eq!(short_uuid(&uuid), Some(0xfd5a));
        assert_eq!(uuid_label(&uuid), "fd5a");
    }

    #[test]
    fn empty_adverts() {
        let empty = Advert { id: "a".into(), address: Some("aa:bb:cc:dd:ee:ff".into()), ..Advert::default() };
        assert!(empty.is_empty());
        assert!(Advert { name: Some(" ".into()), ..empty.clone() }.is_empty());
        let uuid = parse_uuid("fd44").unwrap();
        let with_data = [
            Advert { rssi: Some(-90), ..empty.clone() },
            Advert { name: Some("Tag".into()), ..empty.clone() },
            Advert { tx_power: Some(4), ..empty.clone() },
            Advert { manufacturer_data: BTreeMap::from([(0x004c, vec![])]), ..empty.clone() },
            Advert { services: vec![uuid], ..empty.clone() },
            Advert { service_data: BTreeMap::from([(uuid, vec![])]), ..empty.clone() },
        ];
        assert!(with_data.iter().all(|advert| !advert.is_empty()));
    }

    #[test]
    fn printable_text() {
        assert_eq!(printable("My \u{1b}[2Jwatch\u{202e}\u{2028}\u{e0041}"), "My [2Jwatch");
        assert_eq!(printable("Café 🎧"), "Café 🎧");
    }

    #[test]
    fn full_uuid_stays_full() {
        let text = "19b10000-e8f2-537e-4f6c-d104768a1214";
        let uuid = parse_uuid(text).unwrap();
        assert_eq!(short_uuid(&uuid), None);
        assert_eq!(uuid_label(&uuid), text);
    }
}

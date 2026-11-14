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
    fn full_uuid_stays_full() {
        let text = "19b10000-e8f2-537e-4f6c-d104768a1214";
        let uuid = parse_uuid(text).unwrap();
        assert_eq!(short_uuid(&uuid), None);
        assert_eq!(uuid_label(&uuid), text);
    }
}

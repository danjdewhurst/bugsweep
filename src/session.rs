//! One scan session: the live device list, the classification of each
//! device, and the link to the local log.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::identity::{self, Basis};
use crate::model::Advert;
use crate::signatures::{Level, Signature, SignatureDb};
use crate::store::{Follower, Store};
use crate::vendors;

/// Minimum time between two log writes for the same device.
const LOG_INTERVAL: Duration = Duration::from_secs(30);
/// A payload that did not change for this time can identify the device.
const PAYLOAD_STABLE_AFTER: Duration = Duration::from_secs(60);
/// Weight of a new RSSI value in the moving average.
const RSSI_ALPHA: f32 = 0.35;
/// Typical RSSI at one metre. Real devices differ by 10 dB or more.
const RSSI_AT_1M: f32 = -59.0;

/// The log has this device at other places.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Follow {
    pub places: u32,
    /// The strongest kind of key that matched.
    pub basis: Basis,
}

#[derive(Debug)]
pub struct Device {
    pub advert: Advert,
    /// Indexes into the signature database, most severe first.
    pub hits: Vec<usize>,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub rssi_avg: Option<f32>,
    pub updates: u64,
    /// The user marked this device as known.
    pub known: bool,
    follow: Option<Follow>,
    /// When the current payload was first seen.
    payload_since: Instant,
    last_logged: Option<Instant>,
}

impl Device {
    /// First company in the manufacturer data that has a registered name.
    pub fn vendor(&self) -> Option<&'static str> {
        self.advert.manufacturer_data.keys().find_map(|id| vendors::company(*id))
    }

    /// Best short description: the name, else the vendor.
    pub fn title(&self) -> Option<String> {
        self.advert.name.clone().or_else(|| self.vendor().map(str::to_string))
    }

    /// Rough distance in metres. Walls and bodies change it a lot.
    pub fn distance_m(&self) -> Option<f32> {
        let rssi = self.rssi_avg?;
        Some(10f32.powf((RSSI_AT_1M - rssi) / 20.0))
    }

    /// Set when the log has this device at other places and the user did
    /// not mark it as known.
    pub fn follow(&self) -> Option<Follow> {
        self.follow.filter(|_| !self.known)
    }

    pub fn age(&self) -> Duration {
        self.last_seen.elapsed()
    }
}

pub struct Session {
    db: Arc<SignatureDb>,
    store: Option<Store>,
    pub place: String,
    devices: HashMap<String, Device>,
    /// Identity keys that the user marked as known.
    known: HashSet<String>,
    /// The latest log error, if the log failed.
    pub store_error: Option<String>,
}

impl Session {
    pub fn new(db: Arc<SignatureDb>, store: Option<Store>, place: String) -> Self {
        let mut session = Session {
            db,
            store,
            place,
            devices: HashMap::new(),
            known: HashSet::new(),
            store_error: None,
        };
        if let Some(store) = &session.store {
            match store.known_keys() {
                Ok(keys) => session.known = keys,
                Err(error) => session.store_error = Some(format!("{error:#}")),
            }
        }
        session
    }

    pub fn db(&self) -> &SignatureDb {
        &self.db
    }

    pub fn len(&self) -> usize {
        self.devices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    pub fn get(&self, id: &str) -> Option<&Device> {
        self.devices.get(id)
    }

    /// Take in the latest advertisement data of one device.
    pub fn ingest(&mut self, advert: Advert) {
        self.ingest_at(advert, Instant::now());
    }

    fn ingest_at(&mut self, mut advert: Advert, now: Instant) {
        let hits = self.db.classify(&advert);
        let id = advert.id.clone();

        if let Some(device) = self.devices.get_mut(&id) {
            if advert.name.is_none() {
                advert.name = device.advert.name.take();
            }
            if let Some(rssi) = advert.rssi {
                let rssi = rssi as f32;
                device.rssi_avg = Some(match device.rssi_avg {
                    Some(avg) => avg + RSSI_ALPHA * (rssi - avg),
                    None => rssi,
                });
            }
            let payload_changed = advert.manufacturer_data != device.advert.manufacturer_data
                || advert.service_data != device.advert.service_data;
            if payload_changed {
                device.payload_since = now;
            }
            device.advert = advert;
            device.hits = hits;
            device.last_seen = now;
            device.updates += 1;
        } else {
            let device = Device {
                rssi_avg: advert.rssi.map(|r| r as f32),
                advert,
                hits,
                first_seen: now,
                last_seen: now,
                updates: 1,
                known: false,
                follow: None,
                payload_since: now,
                last_logged: None,
            };
            self.devices.insert(id.clone(), device);
        }
        self.log(&id, now);
    }

    /// Write the device to the log and read back what the log knows about
    /// it: other places, and the "known" mark.
    fn log(&mut self, id: &str, now: Instant) {
        let Some(device) = self.devices.get_mut(id) else {
            return;
        };
        if device.last_logged.is_some_and(|at| now.duration_since(at) < LOG_INTERVAL) {
            return;
        }
        device.last_logged = Some(now);

        let stable = now.duration_since(device.payload_since) >= PAYLOAD_STABLE_AFTER;
        let keys = identity::keys(&device.advert, stable);
        device.known = keys.iter().any(|key| self.known.contains(&key.text));

        let Some(store) = &self.store else {
            return;
        };
        let title = device.title();
        let signature = device.hits.first().map(|&index| self.db.get(index).id.as_str());
        let mut follow: Option<Follow> = None;
        let mut result = Ok(());
        for key in &keys {
            result = result
                .and_then(|()| store.record(&key.text, &self.place, device.advert.rssi, title.as_deref(), signature));
            // A device that is known through one key is known through all.
            if device.known && self.known.insert(key.text.clone()) {
                result = result.and_then(|()| store.set_known(&key.text, title.as_deref(), true));
            }
            match store.other_places(&key.text, &self.place) {
                Ok(0) => {}
                Ok(places) => {
                    let found = Follow { places, basis: key.basis };
                    let better = follow.is_none_or(|f| (found.basis, found.places) > (f.basis, f.places));
                    if better {
                        follow = Some(found);
                    }
                }
                Err(error) => result = result.and(Err(error)),
            }
        }
        device.follow = follow;
        if let Err(error) = result {
            self.store_error = Some(format!("{error:#}"));
        }
    }

    /// Flip the "known" mark of a device. Returns the new state.
    pub fn toggle_known(&mut self, id: &str) -> Option<bool> {
        let device = self.devices.get_mut(id)?;
        device.known = !device.known;
        let stable = device.payload_since.elapsed() >= PAYLOAD_STABLE_AFTER;
        let title = device.title();
        let mut result = Ok(());
        for key in identity::keys(&device.advert, stable) {
            if device.known {
                self.known.insert(key.text.clone());
            } else {
                self.known.remove(&key.text);
            }
            if let Some(store) = &self.store {
                result = result.and_then(|()| store.set_known(&key.text, title.as_deref(), device.known));
            }
        }
        if let Err(error) = result {
            self.store_error = Some(format!("{error:#}"));
        }
        Some(device.known)
    }

    /// Keys from the log that were seen at two or more places.
    pub fn followers(&self) -> Vec<Follower> {
        self.store.as_ref().and_then(|store| store.followers().ok()).unwrap_or_default()
    }

    pub fn has_log(&self) -> bool {
        self.store.is_some()
    }

    pub fn top_signature(&self, device: &Device) -> Option<&Signature> {
        device.hits.first().map(|&index| self.db.get(index))
    }

    /// How much attention the device needs. `None` means no finding.
    pub fn level(&self, device: &Device) -> Option<Level> {
        let from_signature = self.top_signature(device).map(|sig| sig.severity);
        // The same payload at two places can come from two devices of one model.
        let from_follow = device.follow().map(|follow| match follow.basis {
            Basis::Data => Level::Low,
            _ => Level::Medium,
        });
        from_signature.max(from_follow)
    }

    /// A device is flagged when it has a finding above "info" and is not known.
    pub fn is_flagged(&self, device: &Device) -> bool {
        !device.known && self.level(device).is_some_and(|level| level > Level::Info)
    }

    /// Devices in display order: flagged first, then by level, then by signal.
    pub fn sorted(&self, include_unflagged: bool) -> Vec<&Device> {
        let mut list: Vec<&Device> = self
            .devices
            .values()
            .filter(|device| include_unflagged || self.is_flagged(device))
            .collect();
        list.sort_by(|a, b| {
            let key = |d: &Device| {
                (
                    std::cmp::Reverse(self.is_flagged(d)),
                    std::cmp::Reverse(self.level(d)),
                    std::cmp::Reverse(d.rssi_avg.map(|r| r.round() as i32).unwrap_or(i32::MIN)),
                )
            };
            key(a).cmp(&key(b)).then_with(|| a.advert.id.cmp(&b.advert.id))
        });
        list
    }
}

/// "seen at 2 other place(s), same name"
pub fn follow_text(follow: Follow) -> String {
    format!("seen at {} other place(s), same {}", follow.places, follow.basis.label())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::parse_uuid;

    fn db() -> Arc<SignatureDb> {
        Arc::new(SignatureDb::embedded().unwrap())
    }

    fn session() -> Session {
        Session::new(db(), Some(Store::in_memory().unwrap()), "office".into())
    }

    fn advert(id: &str, rssi: i16) -> Advert {
        Advert { id: id.into(), rssi: Some(rssi), ..Default::default() }
    }

    fn named(id: &str, name: &str) -> Advert {
        Advert { id: id.into(), name: Some(name.into()), rssi: Some(-50), ..Default::default() }
    }

    fn tile(id: &str, rssi: i16) -> Advert {
        let mut advert = advert(id, rssi);
        advert.services.push(parse_uuid("feed").unwrap());
        advert
    }

    #[test]
    fn flagged_devices_sort_first() {
        let mut session = session();
        session.ingest(advert("plain-near", -30));
        session.ingest(tile("tile-far", -90));
        let order: Vec<&str> = session.sorted(true).iter().map(|d| d.advert.id.as_str()).collect();
        assert_eq!(order, ["tile-far", "plain-near"]);
        assert_eq!(session.sorted(false).len(), 1);
    }

    #[test]
    fn known_devices_are_not_flagged() {
        let mut session = session();
        session.ingest(tile("tile", -50));
        assert!(session.is_flagged(session.get("tile").unwrap()));
        assert_eq!(session.toggle_known("tile"), Some(true));
        assert!(!session.is_flagged(session.get("tile").unwrap()));
        assert!(session.sorted(false).is_empty());
        assert_eq!(session.toggle_known("tile"), Some(false));
        assert!(session.is_flagged(session.get("tile").unwrap()));
    }

    #[test]
    fn name_survives_an_update_without_name() {
        let mut session = session();
        session.ingest(named("a", "Thing"));
        session.ingest(advert("a", -60));
        let device = session.get("a").unwrap();
        assert_eq!(device.advert.name.as_deref(), Some("Thing"));
        assert_eq!(device.updates, 2);
        let avg = device.rssi_avg.unwrap();
        assert!(avg < -50.0 && avg > -60.0);
    }

    #[test]
    fn same_id_at_another_place_is_a_follower() {
        let store = Store::in_memory().unwrap();
        store.record("id:phone", "home", Some(-50), None, None).unwrap();
        let mut session = Session::new(db(), Some(store), "office".into());
        session.ingest(advert("phone", -50));
        session.ingest(advert("printer", -50));
        let phone = session.get("phone").unwrap();
        assert_eq!(phone.follow(), Some(Follow { places: 1, basis: Basis::Id }));
        assert_eq!(session.level(phone), Some(Level::Medium));
        assert!(session.is_flagged(phone));
        assert!(!session.is_flagged(session.get("printer").unwrap()));
    }

    #[test]
    fn new_id_with_the_same_name_is_a_follower() {
        // At home the tag had another platform ID.
        let mut home = Session::new(db(), Some(Store::in_memory().unwrap()), "home".into());
        home.ingest(named("id-at-home", "Key tag"));
        let store = home.store.take().unwrap();

        let mut office = Session::new(db(), Some(store), "office".into());
        office.ingest(named("id-at-office", "Key tag"));
        office.ingest(named("other", "Desk lamp"));
        let tag = office.get("id-at-office").unwrap();
        assert_eq!(tag.follow(), Some(Follow { places: 1, basis: Basis::Name }));
        assert_eq!(office.level(tag), Some(Level::Medium));
        assert_eq!(office.get("other").unwrap().follow(), None);
        assert_eq!(follow_text(tag.follow().unwrap()), "seen at 1 other place(s), same name");
    }

    #[test]
    fn stable_payload_matches_after_an_id_change_at_low_level() {
        let payload = |id: &str| {
            let mut advert = advert(id, -50);
            advert.manufacturer_data.insert(0x0075, vec![0x42, 4, 1, 0x80, 0x60, 0xCC, 0x6E]);
            advert
        };
        let start = Instant::now();
        let later = start + PAYLOAD_STABLE_AFTER + Duration::from_secs(1);

        let mut home = Session::new(db(), Some(Store::in_memory().unwrap()), "home".into());
        home.ingest_at(payload("id-1"), start);
        home.ingest_at(payload("id-1"), later);
        let store = home.store.take().unwrap();

        let mut office = Session::new(db(), Some(store), "office".into());
        office.ingest_at(payload("id-2"), start);
        // The payload is too new to be an identifier.
        assert_eq!(office.get("id-2").unwrap().follow(), None);
        office.ingest_at(payload("id-2"), later);
        let device = office.get("id-2").unwrap();
        assert_eq!(device.follow(), Some(Follow { places: 1, basis: Basis::Data }));
        assert_eq!(office.level(device), Some(Level::Low));
    }

    #[test]
    fn payload_that_changes_never_becomes_a_key() {
        let payload = |counter: u8| {
            let mut advert = advert("sensor", -50);
            advert.manufacturer_data.insert(0x0075, vec![1, 2, 3, 4, 5, counter]);
            advert
        };
        let start = Instant::now();
        let mut session = session();
        for step in 0..5u8 {
            let at = start + Duration::from_secs(40 * step as u64);
            session.ingest_at(payload(step), at);
        }
        let store = session.store.take().unwrap();
        assert_eq!(store.other_places("data:0075:010203040504", "elsewhere").unwrap(), 0);
        assert_eq!(store.other_places("id:sensor", "elsewhere").unwrap(), 1);
    }

    #[test]
    fn known_mark_follows_the_name_to_a_new_id() {
        let mut session = session();
        session.ingest(named("id-1", "My watch"));
        session.toggle_known("id-1");
        // The watch changed its address and has a new platform ID.
        session.ingest(named("id-2", "My watch"));
        assert!(session.get("id-2").unwrap().known);
        // The new ID is now known too, also without the name.
        assert!(session.known.contains("id:id-2"));
        let store = session.store.take().unwrap();
        assert!(store.known_keys().unwrap().contains("id:id-2"));
    }

    #[test]
    fn known_device_is_not_a_follower() {
        let store = Store::in_memory().unwrap();
        store.record("name:My watch", "home", None, None, None).unwrap();
        store.set_known("name:My watch", None, true).unwrap();
        let mut session = Session::new(db(), Some(store), "office".into());
        session.ingest(named("id-9", "My watch"));
        let watch = session.get("id-9").unwrap();
        assert!(watch.known);
        assert_eq!(watch.follow(), None);
        assert!(!session.is_flagged(watch));
    }

    #[test]
    fn session_without_log_still_marks_known() {
        let mut session = Session::new(db(), None, "office".into());
        session.ingest(tile("tile", -50));
        assert_eq!(session.toggle_known("tile"), Some(true));
        assert!(!session.is_flagged(session.get("tile").unwrap()));
        assert!(session.followers().is_empty());
    }

    #[test]
    fn distance_grows_when_signal_drops() {
        let mut session = session();
        session.ingest(advert("near", -45));
        session.ingest(advert("far", -85));
        let near = session.get("near").unwrap().distance_m().unwrap();
        let far = session.get("far").unwrap().distance_m().unwrap();
        assert!(near < 1.0 && far > 10.0);
    }
}

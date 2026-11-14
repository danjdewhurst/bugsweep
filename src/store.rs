//! Local SQLite log. It holds where each device was seen and which devices
//! the user marked as known. Nothing leaves the machine.
//!
//! A device has one or more identity keys (see `identity`). Each key has its
//! own rows, so a device that changed its Bluetooth address can still match
//! through its name, its tracker key or its payload.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, params};

use crate::identity::Basis;
use crate::place::UNKNOWN;

const SCHEMA_VERSION: i64 = 1;
/// Sightings older than this are deleted when the log opens.
const RETENTION_DAYS: i64 = 90;
/// Counts the `device_id` column of schema version 0.
const OLD_LAYOUT_QUERY: &str = "SELECT COUNT(*) FROM pragma_table_info('sightings') WHERE name = 'device_id'";

pub struct Store {
    conn: Connection,
}

#[derive(Debug, Clone)]
pub struct Follower {
    pub key: String,
    pub basis: Basis,
    pub title: Option<String>,
    pub signature: Option<String>,
    pub places: Vec<String>,
    pub first_seen: i64,
    pub last_seen: i64,
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub fn default_path() -> Option<PathBuf> {
    Some(dirs::data_dir()?.join("bugsweep").join("bugsweep.db"))
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| format!("cannot create {}", parent.display()))?;
        }
        let conn =
            Connection::open(path).with_context(|| format!("cannot open database {}", path.display()))?;
        // The log gets many small writes. WAL keeps them cheap.
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
        let store = Self::init(conn).with_context(|| format!("database {}", path.display()))?;
        store.prune()?;
        Ok(store)
    }

    pub fn in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > SCHEMA_VERSION {
            bail!("the log comes from a newer version of bugsweep (schema {version})");
        }
        if version == 0 {
            // Version 0 used the platform ID in a `device_id` column.
            let old_layout: i64 = conn.query_row(OLD_LAYOUT_QUERY, [], |row| row.get(0))?;
            if old_layout > 0 {
                conn.execute_batch(
                    "BEGIN;
                     ALTER TABLE sightings RENAME COLUMN device_id TO key;
                     UPDATE sightings SET key = 'id:' || key;
                     ALTER TABLE known RENAME COLUMN device_id TO key;
                     UPDATE known SET key = 'id:' || key;
                     COMMIT;",
                )
                .context("cannot upgrade the log")?;
            }
        }
        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS sightings (
                 key        TEXT NOT NULL,
                 place      TEXT NOT NULL,
                 first_seen INTEGER NOT NULL,
                 last_seen  INTEGER NOT NULL,
                 hits       INTEGER NOT NULL DEFAULT 1,
                 max_rssi   INTEGER,
                 title      TEXT,
                 signature  TEXT,
                 PRIMARY KEY (key, place)
             );
             CREATE TABLE IF NOT EXISTS known (
                 key   TEXT PRIMARY KEY,
                 title TEXT,
                 added INTEGER NOT NULL
             );
             PRAGMA user_version = {SCHEMA_VERSION};"
        ))?;
        Ok(Store { conn })
    }

    /// Drop the tables, so that each later call fails. For tests of the
    /// error paths.
    #[cfg(test)]
    pub(crate) fn break_for_tests(&self) {
        self.conn.execute_batch("DROP TABLE sightings; DROP TABLE known;").unwrap();
    }

    fn prune(&self) -> Result<()> {
        let limit = now() - RETENTION_DAYS * 86_400;
        self.conn.execute("DELETE FROM sightings WHERE last_seen < ?1", params![limit])?;
        Ok(())
    }

    /// Record that a key is at a place now.
    pub fn record(
        &self,
        key: &str,
        place: &str,
        rssi: Option<i16>,
        title: Option<&str>,
        signature: Option<&str>,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sightings (key, place, first_seen, last_seen, max_rssi, title, signature)
             VALUES (?1, ?2, ?3, ?3, ?4, ?5, ?6)
             ON CONFLICT (key, place) DO UPDATE SET
                 last_seen = excluded.last_seen,
                 hits      = hits + 1,
                 max_rssi  = CASE
                     WHEN excluded.max_rssi IS NULL THEN max_rssi
                     WHEN max_rssi IS NULL OR excluded.max_rssi > max_rssi THEN excluded.max_rssi
                     ELSE max_rssi END,
                 title     = COALESCE(excluded.title, title),
                 signature = COALESCE(excluded.signature, signature)",
            params![key, place, now(), rssi, title, signature],
        )?;
        Ok(())
    }

    /// Number of other named places where this key was seen before.
    pub fn other_places(&self, key: &str, place: &str) -> Result<u32> {
        let count = self.conn.query_row(
            "SELECT COUNT(DISTINCT place) FROM sightings
             WHERE key = ?1 AND place != ?2 AND place != ?3",
            params![key, place, UNKNOWN],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    pub fn set_known(&self, key: &str, title: Option<&str>, known: bool) -> Result<()> {
        if known {
            self.conn.execute(
                "INSERT INTO known (key, title, added) VALUES (?1, ?2, ?3)
                 ON CONFLICT (key) DO UPDATE SET title = COALESCE(excluded.title, title)",
                params![key, title, now()],
            )?;
        } else {
            self.conn.execute("DELETE FROM known WHERE key = ?1", params![key])?;
        }
        Ok(())
    }

    pub fn known_keys(&self) -> Result<HashSet<String>> {
        let mut stmt = self.conn.prepare("SELECT key FROM known")?;
        let keys = stmt.query_map([], |row| row.get(0))?.collect::<rusqlite::Result<_>>()?;
        Ok(keys)
    }

    /// Keys that are not marked as known and were seen at two or more places.
    /// The strongest key of a device comes first, and a weaker key with the
    /// same title and places is left out.
    pub fn followers(&self) -> Result<Vec<Follower>> {
        let mut stmt = self.conn.prepare(
            "SELECT s.key, MAX(s.title), MAX(s.signature),
                    GROUP_CONCAT(DISTINCT s.place), MIN(s.first_seen), MAX(s.last_seen)
             FROM sightings s
             LEFT JOIN known k ON k.key = s.key
             WHERE k.key IS NULL AND s.place != ?1
             GROUP BY s.key
             HAVING COUNT(DISTINCT s.place) >= 2
             ORDER BY COUNT(DISTINCT s.place) DESC, MAX(s.last_seen) DESC",
        )?;
        let rows = stmt.query_map(params![UNKNOWN], follower_from_row)?;
        let mut all: Vec<Follower> = rows.collect::<rusqlite::Result<_>>()?;
        // The sort is stable, so rows of one basis keep the order of the query.
        all.sort_by_key(|f| std::cmp::Reverse(f.basis));
        let mut kept: Vec<Follower> = Vec::new();
        for follower in all {
            let duplicate = follower.title.is_some()
                && kept.iter().any(|k| k.title == follower.title && k.places == follower.places);
            if !duplicate {
                kept.push(follower);
            }
        }
        Ok(kept)
    }
}

/// One row of the follower query in `Store::followers`.
fn follower_from_row(row: &rusqlite::Row) -> rusqlite::Result<Follower> {
    let key: String = row.get(0)?;
    let places: String = row.get(3)?;
    let mut places: Vec<String> = places.split(',').map(str::to_string).collect();
    places.sort();
    Ok(Follower {
        basis: Basis::of_key(&key),
        key,
        title: row.get(1)?,
        signature: row.get(2)?,
        places,
        first_seen: row.get(4)?,
        last_seen: row.get(5)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follower_needs_two_named_places() {
        let store = Store::in_memory().unwrap();
        store.record("id:tag", "home", Some(-60), Some("Tag"), Some("tile-tracker")).unwrap();
        store.record("id:tag", UNKNOWN, Some(-60), None, None).unwrap();
        store.record("id:tv", "home", Some(-40), Some("TV"), None).unwrap();
        assert!(store.followers().unwrap().is_empty());
        assert_eq!(store.other_places("id:tag", "office").unwrap(), 1);
        assert_eq!(store.other_places("id:tag", "home").unwrap(), 0);

        store.record("id:tag", "office", Some(-50), None, None).unwrap();
        let followers = store.followers().unwrap();
        assert_eq!(followers.len(), 1);
        assert_eq!(followers[0].key, "id:tag");
        assert_eq!(followers[0].basis, Basis::Id);
        assert_eq!(followers[0].title.as_deref(), Some("Tag"));
        assert_eq!(followers[0].places, ["home", "office"]);
    }

    #[test]
    fn known_keys_are_not_followers() {
        let store = Store::in_memory().unwrap();
        store.record("id:watch", "home", None, Some("Watch"), None).unwrap();
        store.record("id:watch", "office", None, None, None).unwrap();
        assert_eq!(store.followers().unwrap().len(), 1);

        store.set_known("id:watch", Some("Watch"), true).unwrap();
        assert!(store.known_keys().unwrap().contains("id:watch"));
        assert!(store.followers().unwrap().is_empty());

        store.set_known("id:watch", None, false).unwrap();
        assert_eq!(store.followers().unwrap().len(), 1);
    }

    #[test]
    fn one_device_with_two_keys_shows_once() {
        let store = Store::in_memory().unwrap();
        for place in ["home", "office"] {
            store.record("id:abc", place, None, Some("Key tag"), None).unwrap();
            store.record("name:Key tag", place, None, Some("Key tag"), None).unwrap();
        }
        // A different device of the same name at other places stays.
        store.record("name:Speaker", "home", None, Some("Speaker"), None).unwrap();
        store.record("name:Speaker", "gym", None, Some("Speaker"), None).unwrap();

        let followers = store.followers().unwrap();
        let keys: Vec<&str> = followers.iter().map(|f| f.key.as_str()).collect();
        assert_eq!(keys, ["id:abc", "name:Speaker"]);
    }

    #[test]
    fn repeat_sighting_keeps_the_best_signal() {
        let store = Store::in_memory().unwrap();
        store.record("id:tag", "home", Some(-70), None, None).unwrap();
        store.record("id:tag", "home", Some(-40), None, None).unwrap();
        store.record("id:tag", "home", None, None, None).unwrap();
        let (hits, rssi): (i64, i64) = store
            .conn
            .query_row("SELECT hits, max_rssi FROM sightings", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!((hits, rssi), (3, -40));
    }

    #[test]
    fn old_sightings_are_pruned() {
        let store = Store::in_memory().unwrap();
        store.record("id:old", "home", None, None, None).unwrap();
        store.record("id:new", "home", None, None, None).unwrap();
        let long_ago = now() - (RETENTION_DAYS + 1) * 86_400;
        store
            .conn
            .execute("UPDATE sightings SET last_seen = ?1 WHERE key = 'id:old'", params![long_ago])
            .unwrap();
        store.prune().unwrap();
        let left: Vec<String> = store
            .conn
            .prepare("SELECT key FROM sightings")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(left, ["id:new"]);
    }

    #[test]
    fn version_0_log_is_upgraded() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE sightings (
                 device_id TEXT NOT NULL, place TEXT NOT NULL,
                 first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
                 hits INTEGER NOT NULL DEFAULT 1, max_rssi INTEGER, title TEXT, signature TEXT,
                 PRIMARY KEY (device_id, place));
             CREATE TABLE known (device_id TEXT PRIMARY KEY, title TEXT, added INTEGER NOT NULL);
             INSERT INTO sightings (device_id, place, first_seen, last_seen) VALUES ('abc', 'home', 1, 2);
             INSERT INTO known (device_id, added) VALUES ('abc', 3);",
        )
        .unwrap();
        let store = Store::init(conn).unwrap();
        assert_eq!(store.other_places("id:abc", "office").unwrap(), 1);
        assert!(store.known_keys().unwrap().contains("id:abc"));
        let version: i64 = store.conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        // A second open of an upgraded log changes nothing.
        let store = Store::init(store.conn).unwrap();
        assert_eq!(store.other_places("id:abc", "office").unwrap(), 1);
    }

    #[test]
    fn default_path_is_in_the_data_directory() {
        let path = default_path().unwrap();
        assert!(path.ends_with(Path::new("bugsweep").join("bugsweep.db")), "{}", path.display());
    }

    #[test]
    fn open_creates_the_directory_and_keeps_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a").join("b").join("log.db");
        Store::open(&path).unwrap().record("id:tag", "home", None, None, None).unwrap();
        let store = Store::open(&path).unwrap();
        assert_eq!(store.other_places("id:tag", "office").unwrap(), 1);
    }

    #[test]
    fn open_reports_a_path_that_cannot_hold_a_log() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, "x").unwrap();
        let error = Store::open(&file.join("log.db")).err().unwrap();
        assert!(format!("{error:#}").contains("cannot create"), "{error:#}");
        // The root directory has no parent, and it is not a database.
        let error = Store::open(Path::new("/")).err().unwrap();
        assert!(format!("{error:#}").contains("database"), "{error:#}");
        // A log from a newer version names its path.
        let newer = dir.path().join("newer.db");
        Connection::open(&newer).unwrap().execute_batch("PRAGMA user_version = 99;").unwrap();
        let error = format!("{:#}", Store::open(&newer).err().unwrap());
        assert!(error.contains("newer.db") && error.contains("newer version"), "{error}");
    }

    #[test]
    fn calls_on_a_broken_log_fail() {
        let store = Store::in_memory().unwrap();
        store.break_for_tests();
        assert!(store.record("id:tag", "home", None, None, None).is_err());
        assert!(store.other_places("id:tag", "home").is_err());
        assert!(store.set_known("id:tag", None, true).is_err());
        assert!(store.set_known("id:tag", None, false).is_err());
        assert!(store.known_keys().is_err());
        assert!(store.followers().is_err());
        assert!(store.prune().is_err());
    }

    #[test]
    fn read_only_new_log_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.db");
        std::fs::write(&path, "").unwrap();
        let conn = Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let error = format!("{:#}", Store::init(conn).err().unwrap());
        assert!(error.contains("readonly"), "{error}");
    }

    #[test]
    fn newer_log_is_refused() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA user_version = 99;").unwrap();
        assert!(Store::init(conn).is_err());
    }
}

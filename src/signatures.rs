//! The signature database and the matcher.
//! The format is described at the top of `data/signatures.toml`.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model::{Advert, parse_uuid};

const EMBEDDED: &str = include_str!("../data/signatures.toml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Tracker,
    Glasses,
    Recorder,
    Camera,
    Bodycam,
    Tool,
    Generic,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::Tracker => "tracker",
            Category::Glasses => "glasses",
            Category::Recorder => "recorder",
            Category::Camera => "camera",
            Category::Bodycam => "bodycam",
            Category::Tool => "tool",
            Category::Generic => "generic",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Info,
    Low,
    Medium,
    High,
}

impl Level {
    pub fn label(self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Low => "low",
            Level::Medium => "medium",
            Level::High => "high",
        }
    }
}

/// Where a signature comes from, strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Evidence {
    /// Official specification, or the vendor's own source code or firmware.
    Spec,
    /// Research paper or published capture from a real device.
    Research,
    /// Source code of a third-party client or detector.
    Code,
    /// The ID is registered to the vendor. Use in advertisements is not proven.
    Registry,
    /// Name pattern or assumption.
    Guess,
}

impl Evidence {
    pub fn label(self) -> &'static str {
        match self {
            Evidence::Spec => "spec",
            Evidence::Research => "research",
            Evidence::Code => "code",
            Evidence::Registry => "registry",
            Evidence::Guess => "guess",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Evidence::Spec => "from a specification or vendor source",
            Evidence::Research => "from a paper or a published capture",
            Evidence::Code => "from the source code of another tool",
            Evidence::Registry => "registered ID, use not proven",
            Evidence::Guess => "a guess, not confirmed",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    signature: Vec<RawSignature>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSignature {
    id: String,
    name: String,
    category: Category,
    severity: Level,
    confidence: Level,
    evidence: Evidence,
    source: String,
    notes: Option<String>,
    /// IDs of less specific signatures that this one replaces when both match.
    #[serde(default)]
    overrides: Vec<String>,
    #[serde(rename = "match")]
    rules: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    company_id: Option<u16>,
    manufacturer_data_prefix: Option<String>,
    manufacturer_data_byte: Option<ByteTest>,
    service_uuid: Option<String>,
    service_data_uuid: Option<String>,
    service_data_prefix: Option<String>,
    service_data_byte: Option<ByteTest>,
    name_regex: Option<String>,
    address_prefix: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct ByteTest {
    offset: usize,
    mask: u8,
    value: u8,
}

#[derive(Debug)]
struct Rule {
    company_id: Option<u16>,
    manufacturer_data_prefix: Option<Vec<u8>>,
    manufacturer_data_byte: Option<ByteTest>,
    service_uuid: Option<Uuid>,
    service_data_uuid: Option<Uuid>,
    service_data_prefix: Option<Vec<u8>>,
    service_data_byte: Option<ByteTest>,
    name_regex: Option<Regex>,
    address_prefix: Option<String>,
}

#[derive(Debug)]
pub struct Signature {
    pub id: String,
    pub name: String,
    pub category: Category,
    pub severity: Level,
    pub confidence: Level,
    pub evidence: Evidence,
    pub source: String,
    pub notes: Option<String>,
    /// Indexes of the signatures that this one replaces when both match.
    overrides: Vec<usize>,
    rules: Vec<Rule>,
}

impl ByteTest {
    fn matches(self, data: &[u8]) -> bool {
        data.get(self.offset).is_some_and(|byte| byte & self.mask == self.value)
    }
}

#[derive(Debug)]
pub struct SignatureDb {
    signatures: Vec<Signature>,
}

fn parse_hex(text: &str) -> Result<Vec<u8>> {
    let clean: String = text.chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
    hex::decode(&clean).with_context(|| format!("bad hex string {text:?}"))
}

fn parse_rule_uuid(text: &str) -> Result<Uuid> {
    parse_uuid(text).with_context(|| format!("bad UUID {text:?}"))
}

impl Rule {
    fn compile(raw: RawRule) -> Result<Self> {
        let rule = Rule {
            company_id: raw.company_id,
            manufacturer_data_prefix: raw.manufacturer_data_prefix.as_deref().map(parse_hex).transpose()?,
            manufacturer_data_byte: raw.manufacturer_data_byte,
            service_uuid: raw.service_uuid.as_deref().map(parse_rule_uuid).transpose()?,
            service_data_uuid: raw.service_data_uuid.as_deref().map(parse_rule_uuid).transpose()?,
            service_data_prefix: raw.service_data_prefix.as_deref().map(parse_hex).transpose()?,
            service_data_byte: raw.service_data_byte,
            name_regex: raw
                .name_regex
                .as_deref()
                .map(|r| Regex::new(r).with_context(|| format!("bad name_regex {r:?}")))
                .transpose()?,
            address_prefix: raw.address_prefix.map(|p| p.to_ascii_uppercase()),
        };

        let needs_company = rule.manufacturer_data_prefix.is_some() || rule.manufacturer_data_byte.is_some();
        if needs_company && rule.company_id.is_none() {
            bail!("manufacturer_data conditions need company_id");
        }
        let needs_service_data = rule.service_data_prefix.is_some() || rule.service_data_byte.is_some();
        if needs_service_data && rule.service_data_uuid.is_none() {
            bail!("service_data conditions need service_data_uuid");
        }
        let has_condition = rule.company_id.is_some()
            || rule.service_uuid.is_some()
            || rule.service_data_uuid.is_some()
            || rule.name_regex.is_some()
            || rule.address_prefix.is_some();
        if !has_condition {
            bail!("a match rule has no conditions");
        }
        Ok(rule)
    }

    fn matches(&self, advert: &Advert) -> bool {
        if let Some(company_id) = self.company_id {
            let Some(data) = advert.manufacturer_data.get(&company_id) else {
                return false;
            };
            if let Some(prefix) = &self.manufacturer_data_prefix
                && !data.starts_with(prefix)
            {
                return false;
            }
            if let Some(test) = self.manufacturer_data_byte
                && !test.matches(data)
            {
                return false;
            }
        }
        if let Some(uuid) = &self.service_uuid
            && !advert.services.contains(uuid)
        {
            return false;
        }
        if let Some(uuid) = &self.service_data_uuid {
            let Some(data) = advert.service_data.get(uuid) else {
                return false;
            };
            if let Some(prefix) = &self.service_data_prefix
                && !data.starts_with(prefix)
            {
                return false;
            }
            if let Some(test) = self.service_data_byte
                && !test.matches(data)
            {
                return false;
            }
        }
        if let Some(regex) = &self.name_regex {
            match &advert.name {
                Some(name) if regex.is_match(name) => {}
                _ => return false,
            }
        }
        if let Some(prefix) = &self.address_prefix {
            match &advert.address {
                Some(address) if address.to_ascii_uppercase().starts_with(prefix) => {}
                _ => return false,
            }
        }
        true
    }
}

impl SignatureDb {
    /// The database that is built into the program.
    pub fn embedded() -> Result<Self> {
        Self::parse(EMBEDDED).context("embedded signature database")
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("signature file {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let raw: RawFile = toml::from_str(text)?;
        let mut seen = HashSet::new();
        for sig in &raw.signature {
            if !seen.insert(sig.id.as_str()) {
                bail!("duplicate signature id {:?}", sig.id);
            }
        }
        let index_of = |id: &str| raw.signature.iter().position(|sig| sig.id == id);
        let mut all_overrides = Vec::with_capacity(raw.signature.len());
        for sig in &raw.signature {
            let mut indexes = Vec::new();
            for other in &sig.overrides {
                match index_of(other) {
                    Some(_) if *other == sig.id => bail!("signature {:?} overrides itself", sig.id),
                    Some(index) => indexes.push(index),
                    None => bail!("signature {:?} overrides unknown id {other:?}", sig.id),
                }
            }
            all_overrides.push(indexes);
        }

        let mut signatures = Vec::with_capacity(raw.signature.len());
        for (sig, overrides) in raw.signature.into_iter().zip(all_overrides) {
            if sig.rules.is_empty() {
                bail!("signature {:?} has no match rules", sig.id);
            }
            let rules = sig
                .rules
                .into_iter()
                .map(Rule::compile)
                .collect::<Result<Vec<_>>>()
                .with_context(|| format!("signature {:?}", sig.id))?;
            signatures.push(Signature {
                id: sig.id,
                name: sig.name,
                category: sig.category,
                severity: sig.severity,
                confidence: sig.confidence,
                evidence: sig.evidence,
                source: sig.source,
                notes: sig.notes,
                overrides,
                rules,
            });
        }
        Ok(SignatureDb { signatures })
    }

    pub fn all(&self) -> &[Signature] {
        &self.signatures
    }

    pub fn get(&self, index: usize) -> &Signature {
        &self.signatures[index]
    }

    /// Indexes of all signatures that match, most severe first. A signature
    /// that another matching signature overrides is left out.
    pub fn classify(&self, advert: &Advert) -> Vec<usize> {
        let matched: Vec<usize> = self
            .signatures
            .iter()
            .enumerate()
            .filter(|(_, sig)| sig.rules.iter().any(|rule| rule.matches(advert)))
            .map(|(index, _)| index)
            .collect();
        let mut hits: Vec<usize> = matched
            .iter()
            .copied()
            .filter(|index| !matched.iter().any(|m| self.signatures[*m].overrides.contains(index)))
            .collect();
        hits.sort_by_key(|&index| {
            let sig = &self.signatures[index];
            std::cmp::Reverse((sig.severity, sig.confidence))
        });
        hits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(db: &SignatureDb, advert: &Advert) -> Vec<String> {
        db.classify(advert).into_iter().map(|i| db.get(i).id.clone()).collect()
    }

    fn find_my(status: u8) -> Advert {
        let mut data = vec![0x12, 0x19, status];
        data.extend([0u8; 24]);
        let mut advert = Advert::default();
        advert.manufacturer_data.insert(0x004C, data);
        advert
    }

    fn service_data(uuid: &str, data: &[u8]) -> Advert {
        let mut advert = Advert::default();
        advert.service_data.insert(parse_uuid(uuid).unwrap(), data.to_vec());
        advert
    }

    #[test]
    fn embedded_database_loads() {
        let db = SignatureDb::embedded().unwrap();
        assert!(db.all().len() > 40);
    }

    #[test]
    fn airtag_and_other_find_my_types() {
        let db = SignatureDb::embedded().unwrap();
        assert_eq!(ids(&db, &find_my(0x10)), ["apple-airtag-separated"]);
        assert_eq!(ids(&db, &find_my(0x24)), ["apple-findmy-accessory-separated"]);
        assert_eq!(ids(&db, &find_my(0x30)), ["apple-airpods-separated"]);
        assert_eq!(ids(&db, &find_my(0x00)), ["apple-device-offline-finding"]);
    }

    #[test]
    fn find_my_near_owner_frame_is_only_info() {
        let db = SignatureDb::embedded().unwrap();
        let mut advert = Advert::default();
        advert.manufacturer_data.insert(0x004C, vec![0x12, 0x02, 0x24, 0x01]);
        assert_eq!(ids(&db, &advert), ["apple-findmy-near-owner"]);
        assert_eq!(db.get(db.classify(&advert)[0]).severity, Level::Info);
    }

    #[test]
    fn ordinary_apple_advert_does_not_match() {
        let db = SignatureDb::embedded().unwrap();
        let mut advert = Advert::default();
        // Nearby Info (type 0x10), sent by every iPhone.
        advert.manufacturer_data.insert(0x004C, vec![0x10, 0x05, 0x01, 0x18, 0x00]);
        assert!(ids(&db, &advert).is_empty());
    }

    #[test]
    fn google_tracker_frame_types() {
        let db = SignatureDb::embedded().unwrap();
        assert_eq!(ids(&db, &service_data("feaa", &[0x41, 1, 2, 3])), ["google-fmdn-unwanted-tracking-mode"]);
        assert_eq!(ids(&db, &service_data("feaa", &[0x40, 1, 2, 3])), ["google-fmdn-tracker"]);
        // An Eddystone URL beacon uses the same UUID and must not match.
        assert!(ids(&db, &service_data("feaa", &[0x10, 1, 2, 3])).is_empty());
    }

    #[test]
    fn dult_near_owner_bit() {
        let db = SignatureDb::embedded().unwrap();
        assert_eq!(ids(&db, &service_data("fcb2", &[0x01, 0x00])), ["dult-separated-tracker"]);
        assert_eq!(ids(&db, &service_data("fcb2", &[0x02, 0x01])), ["dult-near-owner-tracker"]);
        // Too short for the bit: the fallback reports an unknown state.
        assert_eq!(ids(&db, &service_data("fcb2", &[0x01])), ["dult-tracker-unknown-state"]);
    }

    #[test]
    fn samsung_states_replace_the_generic_rule() {
        let db = SignatureDb::embedded().unwrap();
        let state = |byte0: u8| ids(&db, &service_data("fd5a", &[byte0, 0, 0, 0, 1, 2, 3, 4]));
        assert_eq!(state(0x13), ["samsung-smarttag-lost-24h"]);
        assert_eq!(state(0x12), ["samsung-smarttag-lost"]);
        assert_eq!(state(0x11), ["samsung-smarttag-just-disconnected"]);
        assert_eq!(state(0x15), ["samsung-smarttag-near-owner"]);
        // A frame version that is not known falls back to the generic rule.
        assert_eq!(state(0x23), ["samsung-smarttag"]);
    }

    #[test]
    fn glasses_recorders_and_tools() {
        let db = SignatureDb::embedded().unwrap();

        let mut glasses = Advert::default();
        glasses.manufacturer_data.insert(0x01AB, vec![0x02, 0x01, 0x02]);
        glasses.services.push(parse_uuid("fd5f").unwrap());
        assert_eq!(ids(&db, &glasses), ["meta-smart-glasses"]);

        let mut quest = Advert::default();
        quest.manufacturer_data.insert(0x058E, vec![1, 2]);
        assert_eq!(ids(&db, &quest), ["meta-device-generic"]);

        let named = |name: &str| Advert { name: Some(name.into()), ..Default::default() };
        assert_eq!(ids(&db, &named("PLAUD_NOTE")), ["plaud-recorder"]);
        assert_eq!(ids(&db, &named("Flipper Dolphin")), ["flipper-zero"]);
        assert_eq!(ids(&db, &named("Even G1_12_L_AB12CD")), ["even-realities-glasses"]);
        assert_eq!(ids(&db, &named("Frame 4F")), ["brilliant-labs-glasses"]);
        assert_eq!(ids(&db, &named("Penguin-0123456789")), ["flock-penguin-battery"]);
        assert_eq!(ids(&db, &named("GoPro 1234")), ["gopro-camera"]);
        assert_eq!(ids(&db, &named("Friend")), ["omi-wearable"]);
        assert_eq!(ids(&db, &named("friend_ab12")), ["friend-pendant"]);
        // Names that only look similar must not match.
        for name in ["Flipperoo", "Framework 13", "Omicron", "Friendly speaker", "0123456789"] {
            assert!(ids(&db, &named(name)).is_empty(), "{name}");
        }

        let mut notepin = Advert::default();
        notepin.manufacturer_data.insert(0x005D, vec![0x04, 0x56, 0xCF, 0x00, 0x11]);
        assert_eq!(ids(&db, &notepin), ["plaud-recorder"]);
        // Other Realtek products use the same company ID.
        let mut realtek = Advert::default();
        realtek.manufacturer_data.insert(0x005D, vec![0x01, 0x02, 0x03, 0x04]);
        assert!(ids(&db, &realtek).is_empty());

        let mut flipper = Advert::default();
        flipper.services.push(parse_uuid("3082").unwrap());
        assert_eq!(ids(&db, &flipper), ["flipper-zero"]);
    }

    #[test]
    fn axon_rules() {
        let db = SignatureDb::embedded().unwrap();
        let mut advert = Advert::default();
        assert!(ids(&db, &advert).is_empty());
        advert.address = Some("00:25:df:12:34:56".into());
        assert_eq!(ids(&db, &advert), ["axon-equipment"]);

        // The body-camera tag spells AXJANUSBWCDEVICE and replaces the vendor rule.
        let uuid = Uuid::from_bytes(*b"AXJANUSBWCDEVICE");
        assert_eq!(uuid.to_string(), "41584a41-4e55-5342-5743-444556494345");
        advert.service_data.insert(uuid, vec![1, 2, 3]);
        assert_eq!(ids(&db, &advert), ["axon-body-camera"]);
    }

    #[test]
    fn most_severe_match_comes_first() {
        let db = SignatureDb::embedded().unwrap();
        let mut advert = Advert { name: Some("ESP32-cam".into()), ..Default::default() };
        advert.service_data.insert(parse_uuid("fcb2").unwrap(), vec![0x01, 0x00]);
        assert_eq!(ids(&db, &advert), ["dult-separated-tracker", "espressif-board"]);
    }

    const BASE: &str = r#"
        [[signature]]
        id = "x"
        name = "x"
        category = "tool"
        severity = "low"
        confidence = "low"
        evidence = "guess"
        source = "test"
    "#;

    #[test]
    fn bad_rules_are_rejected() {
        let good = format!("{BASE}\n[[signature.match]]\ncompany_id = 1\n");
        assert!(SignatureDb::parse(&good).is_ok());

        let empty_rule = format!("{BASE}\n[[signature.match]]\n");
        assert!(SignatureDb::parse(&empty_rule).is_err());
        let prefix_without_company =
            format!("{BASE}\n[[signature.match]]\nmanufacturer_data_prefix = \"12\"\n");
        assert!(SignatureDb::parse(&prefix_without_company).is_err());
        let byte_without_uuid = format!(
            "{BASE}\n[[signature.match]]\nname_regex = \"x\"\nservice_data_byte = {{ offset = 0, mask = 1, value = 1 }}\n"
        );
        assert!(SignatureDb::parse(&byte_without_uuid).is_err());
        assert!(SignatureDb::parse(BASE).is_err(), "a signature needs a match rule");
        let no_rules = format!("{BASE}match = []\n");
        let error = SignatureDb::parse(&no_rules).err().unwrap();
        assert!(error.to_string().contains("has no match rules"), "{error:#}");
        let twice = format!("{good}{good}");
        assert!(SignatureDb::parse(&twice).is_err(), "duplicate ID");

        for (rule, message) in [
            ("company_id = 1\nmanufacturer_data_prefix = \"zz\"", "bad hex string \"zz\""),
            ("service_uuid = \"nope\"", "bad UUID \"nope\""),
            ("name_regex = \"(\"", "bad name_regex \"(\""),
        ] {
            let text = format!("{BASE}\n[[signature.match]]\n{rule}\n");
            let error = format!("{:#}", SignatureDb::parse(&text).err().unwrap());
            assert!(error.contains("signature \"x\"") && error.contains(message), "{error}");
        }
    }

    #[test]
    fn overrides_must_name_another_signature() {
        let rule = "\n[[signature.match]]\ncompany_id = 1\n";
        let unknown = format!("{BASE}overrides = [\"nope\"]{rule}");
        assert!(SignatureDb::parse(&unknown).is_err());
        let own = format!("{BASE}overrides = [\"x\"]{rule}");
        let error = SignatureDb::parse(&own).err().unwrap();
        assert!(error.to_string().contains("overrides itself"), "{error:#}");
    }

    #[test]
    fn labels_match_the_file_format() {
        use Category::*;
        let categories: Vec<&str> = [Tracker, Glasses, Recorder, Camera, Bodycam, Tool, Generic]
            .into_iter()
            .map(Category::label)
            .collect();
        assert_eq!(categories, ["tracker", "glasses", "recorder", "camera", "bodycam", "tool", "generic"]);
        let levels: Vec<&str> =
            [Level::Info, Level::Low, Level::Medium, Level::High].into_iter().map(Level::label).collect();
        assert_eq!(levels, ["info", "low", "medium", "high"]);
        let evidence: Vec<&str> =
            [Evidence::Spec, Evidence::Research, Evidence::Code, Evidence::Registry, Evidence::Guess]
                .into_iter()
                .map(Evidence::label)
                .collect();
        assert_eq!(evidence, ["spec", "research", "code", "registry", "guess"]);
    }

    #[test]
    fn signature_files_load_or_name_the_problem() {
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("good.toml");
        std::fs::write(&good, format!("{BASE}\n[[signature.match]]\ncompany_id = 1\n")).unwrap();
        assert_eq!(SignatureDb::from_file(&good).unwrap().all().len(), 1);

        let missing = dir.path().join("missing.toml");
        let error = format!("{:#}", SignatureDb::from_file(&missing).err().unwrap());
        assert!(error.starts_with("cannot read") && error.contains("missing.toml"), "{error}");

        let bad = dir.path().join("bad.toml");
        std::fs::write(&bad, "not toml [").unwrap();
        let error = format!("{:#}", SignatureDb::from_file(&bad).err().unwrap());
        assert!(error.starts_with("signature file") && error.contains("bad.toml"), "{error}");
    }

    #[test]
    fn each_evidence_kind_has_a_description() {
        let all = [Evidence::Spec, Evidence::Research, Evidence::Code, Evidence::Registry, Evidence::Guess];
        let texts: std::collections::HashSet<&str> = all.iter().map(|e| e.describe()).collect();
        assert_eq!(texts.len(), all.len());
        assert_eq!(Evidence::Guess.describe(), "a guess, not confirmed");
    }
}

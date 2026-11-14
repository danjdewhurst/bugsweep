//! Style checks for `data/signatures.toml`. The loader already rejects bad
//! syntax, duplicate IDs and unknown overrides; these tests keep the
//! database consistent for contributors.

use bugsweep::signatures::SignatureDb;

#[test]
fn every_signature_is_documented() {
    let db = SignatureDb::embedded().expect("the built-in database loads");
    for sig in db.all() {
        assert!(
            !sig.id.is_empty()
                && sig.id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                && !sig.id.starts_with('-')
                && !sig.id.ends_with('-'),
            "signature id {:?} must be lowercase kebab-case",
            sig.id
        );
        assert!(!sig.name.trim().is_empty(), "signature {} has no name", sig.id);
        assert!(!sig.source.trim().is_empty(), "signature {} has no source", sig.id);
    }
}

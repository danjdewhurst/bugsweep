---
name: bugsweep-signatures
description: Write, test and contribute bugsweep device signatures in TOML (Bluetooth company IDs, service UUIDs, manufacturer or service data bytes, name patterns, MAC prefixes). Use when the user wants bugsweep to detect a new tracker, camera, recorder or pair of smart glasses, has a Bluetooth capture (nRF Connect, btmon, Wireshark) of a device, wants to fix a false positive, or edits data/signatures.toml.
---

# bugsweep signatures

bugsweep classifies each Bluetooth LE advertisement with a TOML signature
database. The built-in file is `data/signatures.toml` in the
[bugsweep repo](https://github.com/danjdewhurst/bugsweep). Its header is the
format reference; read it before you write a rule.

## Format

```toml
[[signature]]
id = "acme-tag-separated"          # unique, lowercase kebab-case
name = "Acme Tag, away from its owner"
category = "tracker"               # tracker | glasses | recorder | camera | bodycam | tool | generic
severity = "high"                  # info | low | medium | high: how much the user should care
confidence = "medium"              # low | medium | high: how sure the rule is
evidence = "research"              # spec | research | code | registry | guess (strongest first)
source = "Capture of two Acme Tags, firmware 1.2, in separated state."
notes = "Optional text for the details pane."
overrides = ["acme-device-generic"]  # optional: less specific IDs to hide when both match
[[signature.match]]                  # ANY rule matches the signature
company_id = 0x0ABC                  # ALL conditions in a rule must match
manufacturer_data_prefix = "0201"
manufacturer_data_byte = { offset = 2, mask = 0x30, value = 0x10 }
```

Rule conditions:

| Condition | Matches |
|---|---|
| `company_id` | Bluetooth SIG company ID of the manufacturer data |
| `manufacturer_data_prefix` | hex bytes at the start of the manufacturer data, after the company ID. Needs `company_id`. |
| `manufacturer_data_byte` | `{ offset, mask, value }`: `data[offset] & mask == value`. Needs `company_id`. |
| `service_uuid` | an advertised service UUID, `"fd5a"` or a full UUID |
| `service_data_uuid` | the UUID that carries service data |
| `service_data_prefix`, `service_data_byte` | as above, on the service data. Need `service_data_uuid`. |
| `name_regex` | Rust regex on the advertised name. Anchor it (`^…$`) |
| `address_prefix` | MAC prefix such as `"00:25:DF"`. Does not work on macOS, which hides addresses |

Unknown fields are an error, so a typo fails loudly.

## How to write a good rule

1. Start from evidence. Prefer a published spec, vendor source, or a capture of
   a real device. Set `evidence` and `source` honestly; `guess` is allowed but
   must say what it guesses.
2. Make the rule as narrow as the evidence allows. A company ID alone matches
   every product of that company; add a data prefix or a byte test for the
   frame type. Phones, laptops and headphones from the same vendor must not
   match.
3. Anchor name patterns: `^PLAUD[_ ]` not `PLAUD`. Add negative cases for
   names that only look similar.
4. Use `severity` for the risk to the user, and `confidence` for how sure the
   rule is. A tracker near its owner is `info`; one away from its owner is
   `high`.
5. If a specific rule refines a generic one (a state of a tracker, a body-camera
   tag on a vendor's MAC prefix), list the generic ID in `overrides`.
6. Put the signature in the right section of the file (trackers, smart
   glasses, audio recorders, cameras, body cams, tools, generic).

## Test it

Without a rebuild, against real devices nearby:

```sh
bugsweep --signatures my-signatures.toml signatures   # the file loads
bugsweep --signatures my-signatures.toml scan --json --seconds 30
```

`--signatures` replaces the built-in database, so copy `data/signatures.toml`
and add the new rule to the copy when you want both.

In the repo, add a unit test to the `tests` module of `src/signatures.rs`. Build
an `Advert` with the captured bytes and assert the IDs that match, and also an
advert that must NOT match:

```rust
#[test]
fn acme_tag_states() {
    let db = SignatureDb::embedded().unwrap();
    let mut advert = Advert::default();
    advert.manufacturer_data.insert(0x0ABC, vec![0x02, 0x01, 0x10, 0xAA]);
    assert_eq!(ids(&db, &advert), ["acme-tag-separated"]);

    let mut other = Advert::default();
    other.manufacturer_data.insert(0x0ABC, vec![0x07, 0x00]);
    assert!(ids(&db, &other).is_empty());
}
```

Then run `cargo test`, `cargo clippy --all-targets` and `cargo fmt --check`.

## Read a capture

- Manufacturer data starts with the company ID in little-endian order. In
  `4C 00 12 19 10 …`, the company is `0x004C` (Apple) and the data after it is
  `12 19 10 …`. bugsweep rules never include the company ID bytes.
- A 16-bit service UUID `0xFD5A` appears as `5A FD` in raw bytes. Write it as
  `"fd5a"`.
- `bugsweep scan --json` lists `company_ids`, `services` and `service_data`
  UUIDs for each device, which helps you find the right condition.

## Contribute

Open a pull request on `danjdewhurst/bugsweep` with the signature, the test,
and in the description: the device model, how you got the bytes, and whether
you checked the rule against a real device. Rules confirmed against a real
device are the most welcome.

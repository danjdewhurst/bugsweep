# bugsweep

A radio check for things that can track, film or record you: location
trackers, smart glasses, AI recorder pendants, cameras and body cameras.
It runs on an ordinary laptop, with no extra hardware.

bugsweep does four jobs with one signature database:

1. **Room sweep.** It scans Bluetooth LE and classifies each device. A finder
   screen shows the signal of one device so you can walk towards it.
2. **Recorder alert.** Smart glasses, voice recorders and trackers that are
   away from their owner show at the top of the list.
3. **Follower check.** A local log records where each device was seen. A
   device that turns up at two or more places is flagged.
4. **Network camera sweep.** It looks for IP cameras and video recorders on
   the local network (ONVIF discovery, RTSP, vendor ports, and the maker of
   each network adapter).

## What it cannot do

**This is a radio check, not proof that a room is clean.** bugsweep cannot see:

- a recorder or camera that only saves to a memory card,
- a wired camera, or a camera on a different network,
- a GSM/LTE bug,
- a device whose Bluetooth is off,
- smart glasses that are already connected to their phone. Meta glasses
  advertise only at power-on, pairing or reconnect.

Many signatures are heuristics. The details pane shows the confidence, the
kind of evidence and the source of each finding. A finding means "look at
this", not "this is a bug".

## Use

```sh
cargo run --release              # terminal interface
cargo run --release -- scan      # scan for 15 s and print a table
cargo run --release -- scan --json --seconds 30
cargo run --release -- lan       # network camera sweep
cargo run --release -- lan --all # also list hosts without camera evidence
cargo run --release -- followers # devices seen at two or more places
cargo run --release -- signatures
```

Global options: `--place NAME`, `--signatures FILE`, `--db FILE`, `--no-log`.

Keys in the terminal interface:

| Key | Action |
|---|---|
| `↑` `↓` / `j` `k` | select a device |
| `f` or `Enter` | finder for the selected device |
| `m` | mark the device as known (yours), or remove the mark |
| `a` | show all devices, or only flagged devices (Bluetooth view); show all hosts (network view) |
| `Tab`, `1` `2` `3` | change the view |
| `l` | start the network sweep (network view only) |
| `q` | quit |

The network sweep sends connection attempts to each address of the local
network. Run it only on a network where you are allowed to do that.

The sweep reports a host as a camera when it answers ONVIF discovery, answers
RTSP, has a camera-specific port open, or has a network adapter from a camera
maker. The last test also finds cloud cameras, which have no open ports. It
cannot find a camera that uses a general-purpose Wi-Fi chip and opens no
ports; `lan --all` lists every host with its vendor so you can check by hand.

## Places and the follower check

A laptop has no GPS. By default the place is a key made from the MAC address
of the default gateway, so each network is one place. Give a name with
`--place hotel-rome` when you want a readable one, or when there is no network.

The log is a SQLite file in the user data directory
(`~/Library/Application Support/bugsweep/bugsweep.db` on macOS). It never
leaves the machine. Sightings older than 90 days are deleted. Mark your own
devices with `m`, or they show as followers.

Most devices change their Bluetooth address every few minutes, and the
platform ID changes with it. bugsweep therefore keeps more than one identity
key for each device and reports which kind of key matched:

| Match | Key | Strength |
|---|---|---|
| same ID | the platform ID | Exact, but it changes with the address. |
| same tracker key | the public key or ID in a Find My, Find Hub or SmartTag frame | Exact. Stays for about 24 hours while the tracker is away from its owner. |
| same name | the advertised name | Two devices of the same model can have the same name. |
| same data | a payload that did not change for 60 seconds | Weakest. Two devices of the same model can send the same data. Shown at level "low". |

Limits: a tracker changes its key about once a day, by design, so no tool can
link it from one day to the next. A device that sends no name and changes its
payload cannot be followed across an address change.

## Signatures

The database is `data/signatures.toml`. The format is described at the top of
that file. Each signature has a severity, a confidence, a source and a kind of
evidence:

| Evidence | Meaning |
|---|---|
| `spec` | official specification, or the vendor's own source code or firmware |
| `research` | paper or published capture from a real device |
| `code` | source code of another client or detector |
| `registry` | the ID is registered to the vendor, but its use in advertisements is not proven |
| `guess` | name pattern or assumption |

A specific signature can list less specific ones in `overrides`. When both
match, only the specific one is reported. Additions are welcome, most of all
rules that were confirmed against a real device.

Test a signature file without a rebuild:

```sh
cargo run -- --signatures my-signatures.toml scan
```

Vendor names come from the public Bluetooth SIG assigned numbers and the IEEE
registry of MAC address prefixes. Refresh them with `scripts/update-vendors.sh`.

## Platform notes

- **macOS**: the terminal app needs the Bluetooth permission (System Settings
  → Privacy & Security → Bluetooth). macOS hides MAC addresses, so rules with
  `address_prefix` do not work there.
- **Linux**: needs BlueZ. Gives MAC addresses.
- **Windows**: should work through WinRT. Not tested yet.

## Code map

| File | Job |
|---|---|
| `src/ble.rs` | Bluetooth LE scan (btleplug) |
| `src/signatures.rs` | signature database and matcher |
| `src/session.rs` | live device list, levels, link to the log |
| `src/identity.rs` | identity keys that survive an address change |
| `src/store.rs` | SQLite log, known devices, followers |
| `src/place.rs` | place key from the default gateway |
| `src/lan.rs` | network camera sweep |
| `src/tui.rs` | terminal interface (ratatui) |
| `src/vendors.rs` | company, service-UUID and MAC-prefix owner names |

# Contributing to bugsweep

Thank you for your help. The most useful contributions are new or better
signatures, most of all rules that were checked against a real device.

## Set up

1. Install Rust 1.89 or later from <https://rustup.rs>.
2. On Linux, install the D-Bus headers: `sudo apt install libdbus-1-dev pkg-config`
   (Debian and Ubuntu) or `sudo dnf install dbus-devel pkgconf-pkg-config` (Fedora).
3. Build and test:

   ```sh
   cargo test
   ```

The tests need no Bluetooth adapter and no network.

## Before you open a pull request

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
bash tests/install.sh   # only if you changed install.sh
```

CI runs clippy and the tests on Linux, macOS and Windows, the format check on
Linux, and the install-script test on Linux and macOS.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/). The release
tooling reads them to pick the next version and to write the changelog.

| Prefix | Use for | Version bump |
|---|---|---|
| `feat:` | a new feature or a new signature | minor |
| `fix:` | a bug fix, or a fix to a wrong signature | patch |
| `docs:`, `test:`, `refactor:`, `ci:`, `chore:` | other changes | none |
| `feat!:` or a `BREAKING CHANGE:` footer | a change that breaks the CLI or the JSON output | major (minor before 1.0) |

Pull requests are squash-merged, so the PR title becomes the commit message.
Give the PR a Conventional Commit title.

## Signatures

Signatures live in `data/signatures.toml`. The header of that file describes
the format. The [`bugsweep-signatures` skill](skills/bugsweep-signatures/SKILL.md)
has a step-by-step guide.

For each new signature:

- Set `evidence` and `source` honestly. A guess is welcome when it says that
  it is a guess.
- Make the rule as narrow as the evidence allows, so that phones, laptops and
  headphones of the same vendor do not match.
- Add a unit test in `src/signatures.rs` with an advert that matches and one
  that must not match.
- In the PR, say how you got the bytes (a spec, a capture, another project)
  and whether you tested the rule against a real device.

You can test a signature file without a rebuild:

```sh
cargo run -- --signatures my-signatures.toml scan
```

## Vendor tables

`data/company_ids.tsv`, `data/member_uuids.tsv` and `data/oui.tsv` come from
public registries. Refresh them with `scripts/update-vendors.sh`; do not edit
them by hand.

## Code of conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).

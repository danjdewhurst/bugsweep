# Security policy

## Supported versions

Only the latest release gets security fixes.

## Report a vulnerability

Please do not open a public issue. Use
[GitHub private vulnerability reporting](https://github.com/danjdewhurst/bugsweep/security/advisories/new)
instead. Include the version (`bugsweep --version`), your platform, and the
steps to reproduce.

You can expect an answer within 7 days.

## Scope

In scope:

- a flaw in bugsweep that exposes the local sighting log or other data,
- a crafted Bluetooth advertisement, network answer or signature file that
  makes bugsweep crash, hang or run code,
- a problem in `install.sh` or the release pipeline.

Out of scope: a tracker or camera that bugsweep does not detect. That is a
missing signature; please open a normal issue or a pull request.

#!/usr/bin/env bash
# Test install.sh against a fake release on the local disk. Needs no network.
set -euo pipefail
cd "$(dirname "$0")/.."

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# Use the target that install.sh detects, so the detection runs too.
target="$(bash -c 'source <(sed "s/^main \"\$@\"$//" install.sh); detect_target')"
echo "detected target: $target"

release="$work/releases"
make_release() { # $1 = directory below $release
  local name="bugsweep-$target" stage="$work/stage"
  rm -rf "$stage" && mkdir -p "$stage/$name" "$release/$1"
  printf '#!/bin/sh\necho "bugsweep 9.9.9"\n' > "$stage/$name/bugsweep"
  chmod +x "$stage/$name/bugsweep"
  tar -C "$stage" -czf "$release/$1/$name.tar.gz" "$name"
  (
    cd "$release/$1"
    if command -v sha256sum > /dev/null; then
      sha256sum "$name.tar.gz" > "$name.tar.gz.sha256"
    else
      shasum -a 256 "$name.tar.gz" > "$name.tar.gz.sha256"
    fi
  )
}
make_release latest/download
make_release download/v9.9.9
export BUGSWEEP_DOWNLOAD_URL="file://$release"

echo "case: latest"
BUGSWEEP_INSTALL_DIR="$work/bin1" bash install.sh
[[ "$("$work/bin1/bugsweep" --version)" == "bugsweep 9.9.9" ]] || fail "latest install"

echo "case: pinned version from a pipe"
bash -s -- --version 9.9.9 --dir "$work/bin2" < install.sh
[[ -x "$work/bin2/bugsweep" ]] || fail "pinned install"

echo "case: reinstall over an existing binary"
bash install.sh --version v9.9.9 --dir "$work/bin2"
[[ -x "$work/bin2/bugsweep" ]] || fail "reinstall"

echo "case: missing version"
if bash install.sh --version v0.0.1 --dir "$work/bin3" 2> /dev/null; then fail "missing version installed"; fi
[[ ! -e "$work/bin3/bugsweep" ]] || fail "missing version left a binary"

echo "case: bad version string"
if bash install.sh --version 'v1;rm' --dir "$work/bin4" 2> /dev/null; then fail "bad version accepted"; fi

echo "case: checksum mismatch"
echo "0000000000000000000000000000000000000000000000000000000000000000  x" \
  > "$release/latest/download/bugsweep-$target.tar.gz.sha256"
if bash install.sh --dir "$work/bin5" 2> /dev/null; then fail "bad checksum accepted"; fi
[[ ! -e "$work/bin5/bugsweep" ]] || fail "bad checksum left a binary"

echo "case: help from a pipe"
bash -s -- --help < install.sh | grep -q -- "--version TAG" || fail "help"

echo "case: unknown option"
if bash install.sh --frobnicate 2> /dev/null; then fail "unknown option accepted"; fi

echo "all install.sh tests passed"

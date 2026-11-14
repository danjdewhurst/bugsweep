#!/usr/bin/env bash
# Test install.sh against a fake release on the local disk. Needs no network.
set -euo pipefail
cd "$(dirname "$0")/.."

# Run every case with the shell that runs this file (bash 3.2 on stock macOS).
sh="${BASH:-bash}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# Use the target that install.sh detects, so the detection runs too.
# bash 3.2 cannot `source <(...)`, so load the functions with eval.
functions="$(sed 's/^main "\$@"$//' install.sh)"
target="$("$sh" -c "$functions"$'\n''detect_target')"
echo "detected target: $target"

release="$work/releases"
make_release() { # $1 = directory below $release, $2 = exit status of the fake binary
  local name="bugsweep-$target" stage="$work/stage"
  rm -rf "$stage" && mkdir -p "$stage/$name" "$release/$1"
  printf '#!/bin/sh\necho "bugsweep 9.9.9"\nexit %s\n' "${2:-0}" > "$stage/$name/bugsweep"
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
make_release download/v9.9.8 1
export BUGSWEEP_DOWNLOAD_URL="file://$release"

echo "case: latest"
BUGSWEEP_INSTALL_DIR="$work/bin1" "$sh" install.sh
[[ "$("$work/bin1/bugsweep" --version)" == "bugsweep 9.9.9" ]] || fail "latest install"

echo "case: pinned version from a pipe"
"$sh" -s -- --version 9.9.9 --dir "$work/bin2" < install.sh
[[ -x "$work/bin2/bugsweep" ]] || fail "pinned install"

echo "case: reinstall over an existing binary"
"$sh" install.sh --version v9.9.9 --dir "$work/bin2"
[[ -x "$work/bin2/bugsweep" ]] || fail "reinstall"

echo "case: missing version"
if "$sh" install.sh --version v0.0.1 --dir "$work/bin3" 2> /dev/null; then fail "missing version installed"; fi
[[ ! -e "$work/bin3/bugsweep" ]] || fail "missing version left a binary"

echo "case: bad version string"
if "$sh" install.sh --version 'v1;rm' --dir "$work/bin4" 2> /dev/null; then fail "bad version accepted"; fi

echo "case: a binary that does not run is not installed"
if "$sh" install.sh --version v9.9.8 --dir "$work/bin6" 2> /dev/null; then fail "broken binary accepted"; fi
[[ ! -e "$work/bin6/bugsweep" ]] || fail "broken binary was installed"

echo "case: an explicit --target skips the run check"
"$sh" install.sh --version v9.9.8 --target "$target" --dir "$work/bin9" 2> /dev/null
[[ -x "$work/bin9/bugsweep" ]] || fail "explicit target"
[[ -z "$(find "$work/bin6" "$work/bin9" -name '.bugsweep.*' 2> /dev/null)" ]] || fail "temporary file left behind"

echo "case: plain http is refused"
out="$(BUGSWEEP_DOWNLOAD_URL="http://example.invalid" "$sh" install.sh --dir "$work/bin7" 2>&1 || true)"
[[ "$out" == *"must start with https://"* ]] || fail "http accepted"

if [[ "$(uname -s)" == "Linux" ]]; then
  echo "case: musl is refused"
  mkdir -p "$work/fakebin"
  # musl's ldd prints its banner to stderr and exits 1.
  printf '#!/bin/sh\necho "musl libc (x86_64)" >&2\nexit 1\n' > "$work/fakebin/ldd"
  chmod +x "$work/fakebin/ldd"
  if PATH="$work/fakebin:$PATH" "$sh" install.sh --dir "$work/bin8" 2> /dev/null; then fail "musl accepted"; fi
  [[ ! -e "$work/bin8/bugsweep" ]] || fail "musl install left a binary"
fi

echo "case: checksum mismatch"
echo "0000000000000000000000000000000000000000000000000000000000000000  x" \
  > "$release/latest/download/bugsweep-$target.tar.gz.sha256"
if "$sh" install.sh --dir "$work/bin5" 2> /dev/null; then fail "bad checksum accepted"; fi
[[ ! -e "$work/bin5/bugsweep" ]] || fail "bad checksum left a binary"

echo "case: help from a pipe"
"$sh" -s -- --help < install.sh | grep -q -- "--version TAG" || fail "help"

echo "case: unknown option"
if "$sh" install.sh --frobnicate 2> /dev/null; then fail "unknown option accepted"; fi

echo "all install.sh tests passed"

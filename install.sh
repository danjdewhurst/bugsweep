#!/usr/bin/env bash
# Install bugsweep from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/danjdewhurst/bugsweep/main/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/danjdewhurst/bugsweep/main/install.sh | bash -s -- --version v0.1.0
#
# Options (or environment variables):
#   --version TAG   BUGSWEEP_VERSION       release tag to install (default: latest)
#   --dir DIR       BUGSWEEP_INSTALL_DIR   install directory (default: ~/.local/bin)
#   --target T      BUGSWEEP_TARGET        Rust target triple (default: detected)
#
# BUGSWEEP_DOWNLOAD_URL replaces https://github.com/danjdewhurst/bugsweep/releases
# (for mirrors and tests).

set -euo pipefail

REPO="danjdewhurst/bugsweep"

say() { printf 'bugsweep-install: %s\n' "$*" >&2; }
die() {
  say "error: $*"
  exit 1
}

usage() {
  cat << 'USAGE'
Install bugsweep from a GitHub release.

Usage: install.sh [--version TAG] [--dir DIR] [--target TRIPLE]

  --version TAG   release tag to install, default latest  (BUGSWEEP_VERSION)
  --dir DIR       install directory, default ~/.local/bin (BUGSWEEP_INSTALL_DIR)
  --target T      Rust target triple, default detected    (BUGSWEEP_TARGET)
  -h, --help      show this help
USAGE
  exit 0
}

need() { command -v "$1" > /dev/null 2>&1 || die "this script needs '$1'"; }

download() { # $1 = URL, $2 = output file
  if command -v curl > /dev/null 2>&1; then
    curl --proto '=https,file' --tlsv1.2 -fsSL --retry 3 -o "$2" "$1"
  elif command -v wget > /dev/null 2>&1; then
    wget -q -O "$2" "$1"
  else
    die "this script needs curl or wget"
  fi
}

sha256() {
  if command -v sha256sum > /dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum > /dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "this script needs sha256sum or shasum"
  fi
}

detect_target() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$arch" in
    x86_64 | amd64) arch="x86_64" ;;
    arm64 | aarch64) arch="aarch64" ;;
    *) die "no prebuilt binary for CPU '$arch'. Build from source: cargo install --git https://github.com/$REPO" ;;
  esac

  case "$os" in
    Linux)
      if ldd --version 2>&1 | grep -qi musl; then
        die "no prebuilt binary for musl libc (Alpine). Build from source: cargo install --git https://github.com/$REPO"
      fi
      printf '%s-unknown-linux-gnu\n' "$arch"
      ;;
    Darwin)
      # A shell under Rosetta reports x86_64 on Apple silicon. Install the native binary.
      if [[ "$arch" == "x86_64" ]] && [[ "$(sysctl -n sysctl.proc_translated 2> /dev/null || true)" == "1" ]]; then
        arch="aarch64"
      fi
      printf '%s-apple-darwin\n' "$arch"
      ;;
    MINGW* | MSYS* | CYGWIN* | Windows_NT)
      die "on Windows, download bugsweep-x86_64-pc-windows-msvc.zip from https://github.com/$REPO/releases"
      ;;
    *) die "no prebuilt binary for '$os'. Build from source: cargo install --git https://github.com/$REPO" ;;
  esac
}

main() {
  local version="${BUGSWEEP_VERSION:-latest}"
  local dir="${BUGSWEEP_INSTALL_DIR:-${HOME:?HOME is not set}/.local/bin}"
  local target="${BUGSWEEP_TARGET:-}"
  local base="${BUGSWEEP_DOWNLOAD_URL:-https://github.com/$REPO/releases}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version) version="${2:?--version needs a value}"; shift 2 ;;
      --version=*) version="${1#*=}"; shift ;;
      --dir) dir="${2:?--dir needs a value}"; shift 2 ;;
      --dir=*) dir="${1#*=}"; shift ;;
      --target) target="${2:?--target needs a value}"; shift 2 ;;
      --target=*) target="${1#*=}"; shift ;;
      -h | --help) usage ;;
      *) die "unknown option '$1' (try --help)" ;;
    esac
  done

  need uname
  need tar
  need mktemp
  [[ -n "$target" ]] || target="$(detect_target)"

  local url
  if [[ "$version" == "latest" ]]; then
    url="$base/latest/download"
  else
    [[ "$version" == v* ]] || version="v$version"
    [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "bad version '$version'"
    url="$base/download/$version"
  fi

  local name="bugsweep-$target"
  local tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064 # expand $tmp now, while it is set
  trap "rm -rf '$tmp'" EXIT

  say "downloading $name ($version)"
  download "$url/$name.tar.gz" "$tmp/$name.tar.gz" ||
    die "download failed: $url/$name.tar.gz"
  download "$url/$name.tar.gz.sha256" "$tmp/$name.tar.gz.sha256" ||
    die "download failed: $url/$name.tar.gz.sha256"

  local expected actual
  expected="$(awk '{print $1; exit}' "$tmp/$name.tar.gz.sha256")"
  actual="$(sha256 "$tmp/$name.tar.gz")"
  [[ -n "$expected" && "$expected" == "$actual" ]] ||
    die "checksum mismatch for $name.tar.gz (expected $expected, got $actual)"

  tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
  [[ -f "$tmp/$name/bugsweep" ]] || die "the archive has no $name/bugsweep"

  mkdir -p "$dir" || die "cannot create $dir"
  [[ -w "$dir" ]] || die "cannot write to $dir. Use --dir, or run with sudo"
  # Install by rename, so a running bugsweep keeps its old file.
  cp "$tmp/$name/bugsweep" "$dir/.bugsweep.new"
  chmod 755 "$dir/.bugsweep.new"
  mv -f "$dir/.bugsweep.new" "$dir/bugsweep"

  local installed
  installed="$("$dir/bugsweep" --version 2> /dev/null || true)"
  say "installed ${installed:-bugsweep} to $dir/bugsweep"

  case ":$PATH:" in
    *":$dir:"*) ;;
    *) say "$dir is not on your PATH. Add it, for example: export PATH=\"$dir:\$PATH\"" ;;
  esac
  case "$target" in
    *linux*) say "bugsweep uses BlueZ for Bluetooth. Make sure the bluetooth service runs." ;;
    *darwin*) say "macOS asks for the Bluetooth permission for your terminal app on the first scan." ;;
  esac
}

main "$@"

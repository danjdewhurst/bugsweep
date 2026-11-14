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
    wget -q --https-only -O "$2" "$1"
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
    *) die "no prebuilt binary for CPU '$arch'. Build from source: cargo install --locked --git https://github.com/$REPO" ;;
  esac

  case "$os" in
    Linux)
      # musl's ldd exits 1 after its banner, so do not test the exit status.
      local libc
      libc="$(ldd --version 2>&1 || true)"
      if [[ "$libc" == *musl* ]]; then
        die "no prebuilt binary for musl libc (Alpine). Build from source: cargo install --locked --git https://github.com/$REPO"
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
    *) die "no prebuilt binary for '$os'. Build from source: cargo install --locked --git https://github.com/$REPO" ;;
  esac
}

# Global, so that the EXIT trap can see them after main returns.
tmp=""
new=""
cleanup() {
  [[ -z "$tmp" ]] || rm -rf "$tmp"
  [[ -z "$new" ]] || rm -f "$new"
}

main() {
  local version="${BUGSWEEP_VERSION:-latest}"
  local dir="${BUGSWEEP_INSTALL_DIR:-${HOME:?HOME is not set}/.local/bin}"
  local target="${BUGSWEEP_TARGET:-}"
  local check_run=1
  local base="${BUGSWEEP_DOWNLOAD_URL:-https://github.com/$REPO/releases}"
  case "$base" in
    https://* | file://*) ;;
    *) die "BUGSWEEP_DOWNLOAD_URL must start with https:// or file://" ;;
  esac

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
  # A target that the user picks may be for another machine, so do not run it here.
  if [[ -n "$target" ]]; then check_run=0; else target="$(detect_target)"; fi

  local url
  if [[ "$version" == "latest" ]]; then
    url="$base/latest/download"
  else
    [[ "$version" == v* ]] || version="v$version"
    [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "bad version '$version'"
    url="$base/download/$version"
  fi

  local name="bugsweep-$target"
  tmp="$(mktemp -d)"
  trap cleanup EXIT

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

  mkdir -p "$dir" 2> /dev/null || die "cannot create $dir. Choose another --dir, or pipe the script to 'sudo bash'"
  [[ -w "$dir" ]] || die "cannot write to $dir. Choose another --dir, or pipe the script to 'sudo bash'"
  # Copy to a temporary file next to the target, then rename, so a running
  # bugsweep keeps its old file. /tmp can be noexec, so the check runs here.
  new="$(mktemp "$dir/.bugsweep.XXXXXX")" || die "cannot write to $dir"
  cp "$tmp/$name/bugsweep" "$new"
  chmod 755 "$new"

  # Run the new binary before it replaces anything. A missing library or a
  # glibc that is too old fails here, not after the install.
  local installed="bugsweep"
  if [[ "$check_run" == 1 ]] && ! installed="$("$new" --version 2>&1)"; then
    say "the $target build does not run on this system:"
    printf '%s\n' "$installed" >&2
    case "$target" in
      *linux*) say "the Linux builds need glibc 2.35 or later and libdbus-1 (package libdbus-1-3 or dbus-libs)." ;;
    esac
    die "nothing was installed. Build from source: cargo install --locked --git https://github.com/$REPO"
  fi
  mv -f "$new" "$dir/bugsweep"
  new=""

  say "installed $installed to $dir/bugsweep"

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

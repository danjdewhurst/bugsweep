#!/usr/bin/env bash
# Refresh the vendor tables:
#   data/company_ids.tsv, data/member_uuids.tsv  Bluetooth SIG assigned numbers
#   data/oui.tsv                                 IEEE MA-L (24-bit MAC prefixes)
# Needs curl, awk and python3.
set -euo pipefail
cd "$(dirname "$0")/.."
base="https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/company.yaml" "$base/company_identifiers/company_identifiers.yaml"
curl -fsSL -o "$tmp/uuids.yaml" "$base/uuids/member_uuids.yaml"

# Both files are flat lists of (hex value, name) pairs.
convert() { # $1 = key of the hex field, $2 = input file
  awk -v key="$1" '
    function clean(s) {
      sub(/^[ \t]+/, "", s); sub(/[ \t\r]+$/, "", s)
      if (s ~ /^'\''.*'\''$/) { s = substr(s, 2, length(s) - 2); gsub(/'\'''\''/, "'\''", s) }
      else if (s ~ /^".*"$/) { s = substr(s, 2, length(s) - 2); gsub(/\\"/, "\"", s) }
      return s
    }
    $0 ~ "^[ \t]*-[ \t]*" key ":" { v = $NF; sub(/^0[xX]/, "", v); id = tolower(v); next }
    /^[ \t]*name:/ { n = $0; sub(/^[ \t]*name:/, "", n); if (id != "") print id "\t" clean(n); id = "" }
  ' "$2" | sort
}

convert value "$tmp/company.yaml" > data/company_ids.tsv
convert uuid "$tmp/uuids.yaml" > data/member_uuids.tsv

# IEEE MA-L registry: "MA-L,286FB9,Organization Name,Address".
curl -fsSL -o "$tmp/oui.csv" "https://standards-oui.ieee.org/oui/oui.csv"
python3 - "$tmp/oui.csv" > data/oui.tsv <<'PY'
import csv, sys
rows = {}
with open(sys.argv[1], newline="", encoding="utf-8") as handle:
    for row in csv.DictReader(handle):
        prefix = row["Assignment"].strip().lower()
        name = " ".join(row["Organization Name"].split())
        if len(prefix) == 6 and name:
            rows[prefix] = name
for prefix in sorted(rows):
    print(f"{prefix}\t{rows[prefix]}")
PY

wc -l data/company_ids.tsv data/member_uuids.tsv data/oui.tsv

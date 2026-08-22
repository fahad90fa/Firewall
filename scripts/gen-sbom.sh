#!/bin/sh
# Generate a CycloneDX 1.5 SBOM from Cargo.lock — no external tools, no network.
#
# A firewall is exactly the kind of software whose supply chain people need to
# audit, so ship a machine-readable bill of materials. This reads the committed
# Cargo.lock (the source of truth for what actually gets built) and emits
# CycloneDX JSON to stdout.
#
#   scripts/gen-sbom.sh > sbom.cdx.json
#
# Note: the DEFAULT build of this project uses zero external crates. External
# entries here (ring, rustls, …) are pulled in only by opt-in features such as
# `--features tls`; each component records its source so auditors can tell the
# workspace crates from third-party ones.

set -eu

HERE="$(cd "$(dirname "$0")/.." && pwd)"
LOCK="$HERE/Cargo.lock"
[ -f "$LOCK" ] || { echo "gen-sbom: $LOCK not found" >&2; exit 1; }

# A stable, content-derived serial number so the SBOM is reproducible: same
# lockfile in, same document out (no timestamps, no random UUID).
serial="$(cksum "$LOCK" | awk '{printf "urn:uuid:00000000-0000-0000-0000-%012d", $1 % 1000000000000}')"

awk -v serial="$serial" '
function esc(s){ gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); return s }
function val(line){ sub(/^[a-z_]+ = "/,"",line); sub(/"$/,"",line); return line }
function flush(){
  if (name=="") return
  if (started) printf ",\n"
  started=1
  purl="pkg:cargo/" name "@" version
  # A component with no `source` is a workspace member (first-party).
  type=(source=="") ? "application" : "library"
  printf "    {\n"
  printf "      \"type\": \"%s\",\n", type
  printf "      \"name\": \"%s\",\n", esc(name)
  printf "      \"version\": \"%s\",\n", esc(version)
  printf "      \"purl\": \"%s\"", esc(purl)
  if (source!="") { printf ",\n      \"externalReferences\": [ { \"type\": \"distribution\", \"url\": \"%s\" } ]", esc(source) }
  if (checksum!="") { printf ",\n      \"hashes\": [ { \"alg\": \"SHA-256\", \"content\": \"%s\" } ]", esc(checksum) }
  printf "\n    }"
  name=""; version=""; source=""; checksum=""
}
BEGIN{
  print "{"
  print "  \"bomFormat\": \"CycloneDX\","
  print "  \"specVersion\": \"1.5\","
  print "  \"serialNumber\": \"" serial "\","
  print "  \"version\": 1,"
  print "  \"metadata\": { \"component\": { \"type\": \"application\", \"name\": \"unified-firewall\" } },"
  print "  \"components\": ["
  started=0
}
/^\[\[package\]\]/ { flush() }
/^name = /     { name=val($0) }
/^version = /  { version=val($0) }
/^source = /   { source=val($0) }
/^checksum = / { checksum=val($0) }
END{
  flush()
  print "\n  ]"
  print "}"
}
' "$LOCK"

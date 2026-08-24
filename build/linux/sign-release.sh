#!/bin/sh
# Build a SIGNED, flat apt repository from the built .deb(s), so that `apt`
# verifies the package cryptographically. This is what fixes the "unsigned /
# untrusted third party" provenance flag a software centre shows for a bare
# .deb: apt trusts a repo whose Release file is signed by a key the user has
# explicitly added.
#
# You hold the private key. This script NEVER embeds or commits one — it signs
# with a key already in your gpg keyring and exports only the PUBLIC key for
# customers to trust.
#
# Usage:
#   GPG_KEY="you@example.com" build/linux/sign-release.sh [file.deb ...]
#     (no args → signs every dist/*.deb)
#
# Env:
#   GPG_KEY       (required) signing key id/email in your gpg keyring
#   OUT_DIR       output repo dir            (default: dist/apt)
#   ORIGIN LABEL SUITE CODENAME   repo metadata
#   RELEASE_DATE  RFC-2822 date, for reproducible Release files (default: now)
#   GNUPGHOME     use a specific keyring
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
: "${GPG_KEY:?set GPG_KEY to the signing key id/email in your gpg keyring}"
OUT_DIR="${OUT_DIR:-$ROOT/dist/apt}"
ORIGIN="${ORIGIN:-Unified Firewall}"
LABEL="${LABEL:-Unified Firewall}"
SUITE="${SUITE:-stable}"
CODENAME="${CODENAME:-stable}"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"

# Collect the .debs to publish.
if [ "$#" -eq 0 ]; then
    set -- "$ROOT"/dist/*.deb
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
for d in "$@"; do
    [ -f "$d" ] || { echo "no such .deb: $d" >&2; exit 1; }
    cp "$d" "$OUT_DIR/"
done
# Ship the SBOM alongside if CI (or scripts/gen-sbom.sh) produced one.
[ -f "$ROOT/sbom.cdx.json" ] && cp "$ROOT/sbom.cdx.json" "$OUT_DIR/" || true

cd "$OUT_DIR"

# Package index for a flat repo.
dpkg-scanpackages -m . /dev/null > Packages 2>/dev/null
gzip -9c Packages > Packages.gz

# Release file (hand-built; apt-ftparchive is not required). Lists each index
# file with its size and MD5/SHA256 so apt can detect tampering, then the whole
# thing is signed below.
hash_block() {
    printf '%s:\n' "$1"
    for f in Packages Packages.gz; do
        printf ' %s %s %s\n' "$($2 "$f" | cut -d' ' -f1)" "$(wc -c < "$f")" "$f"
    done
}
{
    printf 'Origin: %s\n' "$ORIGIN"
    printf 'Label: %s\n' "$LABEL"
    printf 'Suite: %s\n' "$SUITE"
    printf 'Codename: %s\n' "$CODENAME"
    printf 'Architectures: %s\n' "$ARCH"
    printf 'Components: main\n'
    printf 'Date: %s\n' "${RELEASE_DATE:-$(date -Ru)}"
    hash_block MD5Sum md5sum
    hash_block SHA256 sha256sum
} > Release

# Sign: InRelease (inline, preferred by modern apt) + detached Release.gpg, and
# export the public key customers add to trust the repo.
gpg --batch --yes --default-key "$GPG_KEY" --clearsign -o InRelease Release
gpg --batch --yes --default-key "$GPG_KEY" -abs -o Release.gpg Release
gpg --armor --export "$GPG_KEY" > unified-firewall-archive-keyring.asc

# Per-.deb checksums for out-of-band verification.
for d in *.deb; do sha256sum "$d" > "$d.sha256"; done

# Prove the signature verifies before anyone ships it.
if gpg --verify InRelease >/dev/null 2>&1; then
    echo "OK: InRelease signature verifies"
else
    echo "ERROR: InRelease did not verify" >&2
    exit 1
fi
echo "Signed flat apt repo written to: $OUT_DIR"
echo "Publish its contents at your repo URL (e.g. website/public/apt/) and see docs/apt-repo.md."

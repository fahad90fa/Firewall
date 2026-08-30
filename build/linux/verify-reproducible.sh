#!/bin/sh
# Prove the .deb is reproducible: build it twice and assert the two packages are
# byte-identical.
#
# "Reproducible" is the property that lets a third party rebuild the shipped
# package from source and confirm it matches, byte for byte — so a tampered
# build cannot hide behind "builds are just different every time". This is the
# check that keeps `build-deb.sh` honest.
#
# The two builds run seconds apart and (by default) reuse the same release
# binaries, so the only thing that could differ is the packaging itself — the
# file mtimes, ordering and metadata that `build-deb.sh` pins to
# SOURCE_DATE_EPOCH. Pre-build the binaries once (or let the first pass build
# them) and this isolates the wrapper's determinism.
#
# Usage:
#   build/linux/verify-reproducible.sh
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> build 1"
OUT_DIR="$TMP/a" sh "$ROOT/build/linux/build-deb.sh" >/dev/null
echo "==> build 2 (reusing the same binaries)"
UFW_DEB_SKIP_BUILD=1 OUT_DIR="$TMP/b" sh "$ROOT/build/linux/build-deb.sh" >/dev/null

A="$(sha256sum "$TMP"/a/*.deb | cut -d' ' -f1)"
B="$(sha256sum "$TMP"/b/*.deb | cut -d' ' -f1)"

if [ "$A" = "$B" ]; then
    echo "reproducible: $A"
    exit 0
else
    echo "NOT reproducible:" >&2
    echo "  build 1: $A" >&2
    echo "  build 2: $B" >&2
    # Show what differs, if `diffoscope` happens to be present.
    if command -v diffoscope >/dev/null 2>&1; then
        diffoscope "$TMP"/a/*.deb "$TMP"/b/*.deb || true
    fi
    exit 1
fi

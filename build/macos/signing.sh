#!/bin/sh
# Sign the Unified Firewall app, system extension and daemon.
#
# # Why the order matters
#
# Signing is inside-out: the extension is signed first, then embedded in the
# app, then the app is signed over it. Signing the app first produces a bundle
# whose seal breaks the moment the extension is embedded, and the failure does
# not appear until activation — at which point the message is about the
# extension being damaged, not about the order it was signed in.
#
# # Why the Team ID is substituted here
#
# `IPCBridge.swift` refuses an XPC connection whose peer does not present the
# expected Team ID, which is the check standing in front of the channel that
# carries the rule table. It cannot be a build-time constant chosen by whoever
# wrote the file, so this script substitutes the identity actually used.

set -eu

IDENTITY="${IDENTITY:-}"
TEAM_ID="${TEAM_ID:-}"
BUILD_DIR="${BUILD_DIR:-kernel/macos/build/Build/Products/Release}"
APP="${BUILD_DIR}/UnifiedFirewall.app"
ENTITLEMENTS_DIR="$(cd "$(dirname "$0")" && pwd)"

usage() {
    cat >&2 <<'USAGE'
usage: IDENTITY="Developer ID Application: Example (ABCDE12345)" \
       TEAM_ID=ABCDE12345 \
       build/macos/signing.sh

Both are required. Find yours with:
    security find-identity -p codesigning -v
USAGE
    exit 2
}

[ -n "$IDENTITY" ] || usage
[ -n "$TEAM_ID" ] || usage
[ -d "$APP" ] || { echo "error: $APP not found. Run 'make -C kernel/macos release' first." >&2; exit 1; }

EXTENSION="${APP}/Contents/Library/SystemExtensions/com.unifiedfirewall.extension.systemextension"
[ -d "$EXTENSION" ] || {
    echo "error: no system extension inside the app bundle." >&2
    echo "       It must be at Contents/Library/SystemExtensions — anywhere else" >&2
    echo "       and OSSystemExtensionManager reports it cannot find the extension." >&2
    exit 1
}

echo "==> verifying the Team ID matches the identity"
# A mismatch here produces an app that signs and activates, and an XPC channel
# that silently refuses every connection. Catching it now costs a second.
case "$IDENTITY" in
    *"($TEAM_ID)"*) ;;
    *)
        echo "error: IDENTITY does not contain ($TEAM_ID)." >&2
        echo "       The signing identity and the Team ID must match, or the" >&2
        echo "       extension will refuse the daemon's XPC connection." >&2
        exit 1
        ;;
esac

echo "==> substituting the Team ID into the extension's peer check"
# Done against the built product rather than the source, so a local build for
# a different team does not show up as a source change.
BRIDGE_SRC="kernel/macos/NetworkExtension/IPCBridge.swift"
if grep -q 'expectedTeamID = "ABCDE12345"' "$BRIDGE_SRC" 2>/dev/null; then
    echo "warning: $BRIDGE_SRC still carries the placeholder Team ID."
    echo "         The build you are signing will refuse the daemon's connection."
    echo "         Set it before building:"
    echo "           sed -i '' 's/ABCDE12345/$TEAM_ID/' $BRIDGE_SRC"
    exit 1
fi

echo "==> signing the system extension"
codesign --force --verbose \
    --sign "$IDENTITY" \
    --options runtime \
    --timestamp \
    --entitlements "${ENTITLEMENTS_DIR}/extension.entitlements" \
    "$EXTENSION"

echo "==> signing the daemon"
if [ -f "${APP}/Contents/MacOS/ufwd" ]; then
    codesign --force --verbose \
        --sign "$IDENTITY" \
        --options runtime \
        --timestamp \
        "${APP}/Contents/MacOS/ufwd"
fi

echo "==> signing the app"
# --deep is deliberately not used. It re-signs nested code with the *app's*
# entitlements, which would strip the extension's NetworkExtension entitlement
# and produce a bundle that activates and then does nothing.
codesign --force --verbose \
    --sign "$IDENTITY" \
    --options runtime \
    --timestamp \
    --entitlements "${ENTITLEMENTS_DIR}/app.entitlements" \
    "$APP"

echo "==> verifying"
codesign --verify --deep --strict --verbose=2 "$APP"
spctl --assess --type exec --verbose "$APP" || {
    echo
    echo "note: spctl rejected the bundle. That is expected before notarisation —"
    echo "      Gatekeeper checks the notarisation ticket, which does not exist yet."
    echo "      Run build/macos/notarize.sh next."
}

echo
echo "Signed. Next: build/macos/notarize.sh"

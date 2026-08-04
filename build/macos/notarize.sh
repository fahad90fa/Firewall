#!/bin/sh
# Submit the Unified Firewall to Apple for notarisation, and staple the ticket.
#
# # Why this is not optional
#
# An unnotarised system extension will not activate on a machine with default
# Gatekeeper settings. Not "shows a warning" — will not activate. Skipping this
# step produces a build that works on the developer's machine, where Gatekeeper
# has been relaxed, and fails everywhere else with a message about the extension
# being blocked.
#
# # Why stapling matters
#
# Notarisation puts a ticket on Apple's servers; stapling attaches it to the
# bundle. Without stapling, a machine installing the app must reach Apple to
# check — so an air-gapped or restricted-network install fails, which is
# precisely the environment this firewall is most likely to be deployed in.

set -eu

APPLE_ID="${APPLE_ID:-}"
TEAM_ID="${TEAM_ID:-}"
# An app-specific password, not the account password. Generate one at
# appleid.apple.com; a real password will be rejected and, if 2FA is on, will
# lock the submission out entirely.
APP_PASSWORD="${APP_PASSWORD:-}"
BUILD_DIR="${BUILD_DIR:-kernel/macos/build/Build/Products/Release}"
APP="${BUILD_DIR}/UnifiedFirewall.app"
ARCHIVE="${BUILD_DIR}/UnifiedFirewall.zip"

usage() {
    cat >&2 <<'USAGE'
usage: APPLE_ID=you@example.com \
       TEAM_ID=ABCDE12345 \
       APP_PASSWORD=abcd-efgh-ijkl-mnop \
       build/macos/notarize.sh

APP_PASSWORD must be an app-specific password from appleid.apple.com, not the
account password.

Alternatively, store the credentials once and skip the environment variables:
    xcrun notarytool store-credentials unified-firewall \
        --apple-id you@example.com --team-id ABCDE12345
    KEYCHAIN_PROFILE=unified-firewall build/macos/notarize.sh
USAGE
    exit 2
}

KEYCHAIN_PROFILE="${KEYCHAIN_PROFILE:-}"
if [ -z "$KEYCHAIN_PROFILE" ]; then
    [ -n "$APPLE_ID" ] || usage
    [ -n "$TEAM_ID" ] || usage
    [ -n "$APP_PASSWORD" ] || usage
fi

[ -d "$APP" ] || { echo "error: $APP not found. Sign it first." >&2; exit 1; }

echo "==> confirming the bundle is signed with a hardened runtime"
# Notarisation rejects a bundle without the hardened runtime, and the rejection
# arrives minutes later in a log file. Checking locally turns a five-minute
# round trip into an immediate error.
if ! codesign --display --verbose=2 "$APP" 2>&1 | grep -q 'flags=.*runtime'; then
    echo "error: the app is not signed with --options runtime." >&2
    echo "       Notarisation will reject it. Run build/macos/signing.sh." >&2
    exit 1
fi

echo "==> archiving"
rm -f "$ARCHIVE"
# ditto, not zip: zip does not preserve the extended attributes a signature
# lives in, so a zip-archived bundle arrives at Apple unsigned.
/usr/bin/ditto -c -k --keepParent "$APP" "$ARCHIVE"

echo "==> submitting"
if [ -n "$KEYCHAIN_PROFILE" ]; then
    xcrun notarytool submit "$ARCHIVE" \
        --keychain-profile "$KEYCHAIN_PROFILE" \
        --wait
else
    xcrun notarytool submit "$ARCHIVE" \
        --apple-id "$APPLE_ID" \
        --team-id "$TEAM_ID" \
        --password "$APP_PASSWORD" \
        --wait
fi

echo "==> stapling"
# Stapling attaches the ticket to the bundle, so an install on a machine with
# no route to Apple still validates. Without it, this firewall cannot be
# installed in the restricted networks it is most useful in.
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"

echo "==> final Gatekeeper assessment"
spctl --assess --type exec --verbose "$APP"

echo
echo "Notarised and stapled: $APP"
echo
echo "Install with:"
echo "  cp -R \"$APP\" /Applications/"
echo "  open /Applications/UnifiedFirewall.app --args --activate"
echo
echo "On an unmanaged Mac the user must approve the extension in"
echo "System Settings > Privacy & Security. For a fleet, pre-approve it with an"
echo "MDM profile keyed on Team ID ${TEAM_ID:-<your team id>} — a host firewall a"
echo "user can decline is not much of a control."

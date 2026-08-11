#!/bin/sh
# Unified Firewall — one-command install of the real nftables enforcement
# path, for Debian-family hosts (Parrot, Kali, Ubuntu, Debian).
#
#   git clone https://github.com/fahad90fa/Firewall && cd Firewall
#   sudo ./install.sh
#   firewall                # ← the whole project, running
#
# What it does, and nothing more:
#   1. builds the workspace CLI (cargo, release profile, zero dependencies)
#   2. installs `ufw-nft`, `ufwctl`, and the `firewall` command to PREFIX/bin
#   3. copies the shipped policies to /etc/unified-firewall/policies so
#      `firewall apply default_allow` works from any directory
#
# It does NOT load any firewall rule. Enforcement starts only when you run
# `firewall apply <policy>` — choosing a policy is your call, not an
# installer's. Remove everything with: sudo ./install.sh --uninstall

set -eu

PREFIX="${PREFIX:-/usr/local}"
BIN="$PREFIX/bin"
POLICY_DST="/etc/unified-firewall/policies"
HERE="$(cd "$(dirname "$0")" && pwd)"

if [ "${1:-}" = "--uninstall" ]; then
    rm -f "$BIN/firewall" "$BIN/ufw-nft" "$BIN/ufwctl"
    echo "removed $BIN/firewall, $BIN/ufw-nft, $BIN/ufwctl"
    echo "left $POLICY_DST in place: it may hold policy you edited."
    echo "if rules are still loaded: sudo nft delete table inet ufw"
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh writes to $BIN and /etc — run it with sudo" >&2
    exit 1
fi

command -v cargo >/dev/null 2>&1 || {
    echo "cargo was not found. Install Rust first: https://rustup.rs (or apt install cargo)" >&2
    exit 1
}
command -v nft >/dev/null 2>&1 || {
    echo "note: nft not found; installing rules will need it (apt install nftables)"
}

echo "==> building (cargo build --release; first build takes a minute)"
# Build as the invoking user when possible so ~/.cargo stays theirs.
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    su - "$SUDO_USER" -c "cd '$HERE' && cargo build --release -p ufw-cli"
else
    (cd "$HERE" && cargo build --release -p ufw-cli)
fi

echo "==> installing to $BIN"
install -d "$BIN"
install -m 0755 "$HERE/target/release/ufw-nft" "$BIN/ufw-nft"
install -m 0755 "$HERE/target/release/ufwctl" "$BIN/ufwctl"
install -m 0755 "$HERE/build/linux/firewall.sh" "$BIN/firewall"

echo "==> installing policies to $POLICY_DST"
install -d "$POLICY_DST"
cp -R "$HERE/policies/." "$POLICY_DST/"

echo
echo "installed. Nothing is enforced yet — that part is deliberately manual:"
echo
echo "  firewall                          live dashboard (what is happening on this host)"
echo "  firewall apply default_allow      phase-one policy: deny the indefensible, log the rest"
echo "  firewall trial default_deny 60    default-deny with a 60s auto-revert safety net"
echo "  firewall status                   the loaded rules, with live packet counters"
echo "  firewall revert                   back out completely"

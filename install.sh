#!/bin/sh
# Unified Firewall — one-command install of the whole enforcement + telemetry
# stack, for Debian-family hosts (Parrot, Kali, Ubuntu, Debian).
#
#   git clone https://github.com/fahad90fa/Firewall && cd Firewall
#   sudo ./install.sh
#   sudo firewall           # ← the whole project, running, every layer live
#
# What it does:
#   1. builds the CLI and the daemon (cargo, release profile, offline)
#   2. installs ufw-nft, ufwctl, firewall, ufw-daemon and ufw-waf to PREFIX/bin
#   3. installs the policies and the DPI/WAF signatures under /etc/unified-firewall
#   4. writes a monitor-mode daemon config and installs systemd units for the
#      firewall policy, the daemon, the WAF and the dashboard, then enables and
#      starts them — so everything comes back automatically on every boot
#   5. loads a safe activation policy (default-ALLOW with a rate cap), so the
#      packet-filter, rate-limiting and attack-surface layers are live too. The
#      policy is reloaded at boot by firewall-policy.service (nftables rules do
#      not survive a reboot on their own), and it tracks whatever you last apply.
#
# Safety: the daemon starts in MONITOR mode (it observes and logs, it does not
# block), the WAF binds LOOPBACK only, and the loaded policy permits by default
# — denying only the never-legitimate protocols (telnet/FTP, SMB egress, bogons,
# inbound RDP). Nothing here can lock you out of your own machine. Going to real
# enforcement is one deliberate step, printed at the end.
#
# Remove everything with:  sudo ./install.sh --uninstall

set -eu

PREFIX="${PREFIX:-/usr/local}"
BIN="$PREFIX/bin"
ETC="/etc/unified-firewall"
POLICY_DST="$ETC/policies"
SIG_DST="$ETC/sig-rules"
DAEMON_POLICY="$ETC/daemon-policy"
CONFIG="$ETC/daemon.toml"
UNIT_DIR="/etc/systemd/system"
STATE_DIR="/var/lib/unified-firewall"
HERE="$(cd "$(dirname "$0")" && pwd)"

have_systemd() { [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

if [ "${1:-}" = "--uninstall" ]; then
    if have_systemd; then
        systemctl disable --now ufw-daemon.service ufw-waf.service ufw-nft.service firewall-policy.service 2>/dev/null || true
        rm -f "$UNIT_DIR/ufw-daemon.service" "$UNIT_DIR/ufw-waf.service" \
              "$UNIT_DIR/ufw-nft.service" "$UNIT_DIR/firewall-policy.service"
        systemctl daemon-reload 2>/dev/null || true
    fi
    rm -f "$BIN/firewall" "$BIN/ufw-nft" "$BIN/ufwctl" "$BIN/ufw-daemon" "$BIN/ufw-waf"
    echo "removed binaries and systemd units."
    echo "left $ETC and $STATE_DIR in place (they may hold config/policy you edited)."
    echo "if rules are still loaded: sudo nft delete table inet ufw"
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh writes to $BIN and /etc and starts services — run it with sudo" >&2
    exit 1
fi

command -v cargo >/dev/null 2>&1 || {
    echo "cargo was not found. Install Rust first: https://rustup.rs (or apt install cargo)" >&2
    exit 1
}
command -v nft >/dev/null 2>&1 || {
    echo "note: nft not found; the packet-filter layers need it (apt install nftables)"
}

echo "==> building CLI and daemon (cargo build --release; first build takes a minute)"
# Build offline and without the optional tls feature, keeping the project's
# zero-dependency guarantee. Build as the invoking user so ~/.cargo stays theirs.
BUILD="cd '$HERE' && cargo build --release -p ufw-cli && cargo build --release -p ufw-daemon"
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    su - "$SUDO_USER" -c "$BUILD"
else
    sh -c "$BUILD"
fi

echo "==> installing binaries to $BIN"
install -d "$BIN"
install -m 0755 "$HERE/target/release/ufw-nft"    "$BIN/ufw-nft"
install -m 0755 "$HERE/target/release/ufwctl"     "$BIN/ufwctl"
install -m 0755 "$HERE/target/release/ufwd"       "$BIN/ufw-daemon"
install -m 0755 "$HERE/target/release/ufw-waf"    "$BIN/ufw-waf"
install -m 0755 "$HERE/build/linux/firewall.sh"   "$BIN/firewall"

echo "==> installing policies and signatures under $ETC"
install -d "$POLICY_DST" "$SIG_DST" "$DAEMON_POLICY" "$STATE_DIR"
cp -R "$HERE/policies/." "$POLICY_DST/"
cp -R "$HERE/sig-rules/." "$SIG_DST/"
# The daemon loads exactly one policy from its own directory (no ambiguity with
# the full policy tree the CLI browses).
install -m 0644 "$HERE/policies/base/monitor_baseline.yaml" "$DAEMON_POLICY/monitor_baseline.yaml"

echo "==> writing monitor-mode daemon config to $CONFIG"
cat > "$CONFIG" <<EOF
# Installed by install.sh. Observe everything, block nothing — graduate to
# enforce only after reading the logs and writing your allow rules.
[daemon]
mode = "monitor"
# No ufw kernel module is built here (that is a separate DKMS step), so the
# daemon runs in user space: it still classifies, logs, detects egress
# anomalies, correlates and publishes telemetry — it just cannot block until
# the module is installed and mode is switched to "enforce".
require_kernel_module = false

[policy]
dir = "$DAEMON_POLICY"
files = ["monitor_baseline.yaml"]
signature_dir = "$SIG_DST"
hot_reload = true

[logging]
stdout = false
level = "info"
anomaly = true
correlation = true

[api]
rest_bind = "127.0.0.1:9600"
# A fleet key (>=32 chars) turns on the fleet-rollout plane. Replace this with a
# real shared secret before distributing policy across hosts.
fleet_secret = "CHANGE-ME-before-fleet-use-0000000000000000"
EOF
chmod 0600 "$CONFIG"

if have_systemd; then
    echo "==> installing systemd services (firewall policy, daemon, WAF, dashboard)"
    install -m 0644 "$HERE/build/linux/firewall-policy.service" "$UNIT_DIR/firewall-policy.service"
    install -m 0644 "$HERE/build/linux/ufw-daemon.service"      "$UNIT_DIR/ufw-daemon.service"
    install -m 0644 "$HERE/build/linux/ufw-waf.service"         "$UNIT_DIR/ufw-waf.service"
    install -m 0644 "$HERE/build/linux/ufw-nft.service"         "$UNIT_DIR/ufw-nft.service"
    systemctl daemon-reload || true
    # Order matters: load the ruleset first (records state for the dashboard and
    # for future boots), then the observers, then the console. `enable --now`
    # arms each for boot AND starts it right now, so nothing needs a reboot.
    echo "==> enabling everything on boot and starting it now"
    systemctl enable --now firewall-policy.service || echo "   (firewall-policy did not apply — is nftables installed? journalctl -u firewall-policy)"
    systemctl enable --now ufw-daemon.service      || echo "   (ufw-daemon did not start — check: journalctl -u ufw-daemon)"
    systemctl enable --now ufw-waf.service         || echo "   (ufw-waf did not start — check: journalctl -u ufw-waf)"
    systemctl enable --now ufw-nft.service         || echo "   (dashboard did not start — check: journalctl -u ufw-nft)"
    echo "   on every boot from now on: the firewall policy reloads and the daemon, WAF and dashboard start automatically"
else
    echo "==> no systemd detected — starting daemon + WAF in the background"
    ( "$BIN/ufw-daemon" --config "$CONFIG" >/dev/null 2>&1 & ) || true
    ( "$BIN/ufw-waf" --listen 127.0.0.1:8443 --backend 127.0.0.1:80 --sig-dir "$SIG_DST" >/dev/null 2>&1 & ) || true
    echo "==> loading the activation policy (default-allow + a rate cap; nothing legitimate is blocked)"
    if "$BIN/ufw-nft" apply "$POLICY_DST/base/monitor_baseline.yaml" >/dev/null 2>&1; then
        echo "   loaded: packet-filter, rate-limiting and attack-surface layers are now live"
    else
        echo "   (could not load rules — is nftables installed? try: sudo firewall apply base/monitor_baseline)"
    fi
    echo "   note: without systemd these do NOT survive a reboot — re-run this after booting, or add your own init hook"
fi

# Give the services a moment to publish their first telemetry, then report.
sleep 4
echo
echo "installed and running. Layer status:"
if nft list table inet ufw >/dev/null 2>&1; then echo "  [live]  packet filter (nftables table inet ufw)"; else echo "  [down]  packet filter — is nftables installed?"; fi
for f in "$STATE_DIR/ufw-daemon-status.json:daemon (DPI, egress anomaly, correlation, fleet)" \
         "$STATE_DIR/ufw-waf-status.json:WAF"; do
    path="${f%%:*}"; label="${f#*:}"
    if [ -f "$path" ]; then echo "  [live]  $label"; else echo "  [down]  $label — check its service logs"; fi
done
if have_systemd; then
    if systemctl is-active --quiet ufw-nft.service; then echo "  [live]  dashboard — http://127.0.0.1:8787 (already running)"; else echo "  [down]  dashboard — check: journalctl -u ufw-nft"; fi
fi
echo
if have_systemd; then
    echo "  it all starts automatically on every boot — nothing to launch by hand."
    echo "  open the dashboard:  http://127.0.0.1:8787   (it's already up)"
else
    echo "  sudo firewall                       open the dashboard — every layer should read ACTIVE"
fi
echo "  sudo firewall status                the loaded rules, with live counters"
echo
echo "when you are ready to actually BLOCK (not just observe):"
echo "  edit $CONFIG  → set  mode = \"enforce\"   then  sudo systemctl restart ufw-daemon"
echo "  and graduate the policy:  sudo firewall apply base/default_deny"
echo "  (whatever you 'apply' becomes what reloads on the next boot)"
echo
if have_systemd; then
    echo "turn auto-start off for one piece:  sudo systemctl disable --now ufw-nft.service   (the dashboard)"
    echo "                                    sudo systemctl disable --now firewall-policy.service   (the whole packet filter)"
    echo
fi
echo "uninstall everything:  sudo ./install.sh --uninstall"

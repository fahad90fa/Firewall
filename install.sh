#!/bin/sh
# Unified Firewall — one-command install of the whole enforcement + telemetry
# stack, for Debian-family hosts (Parrot, Kali, Ubuntu, Debian).
#
#   git clone https://github.com/fahad90fa/Firewall && cd Firewall
#   sudo ./install.sh
#   sudo firewall           # ← the whole project, running, every layer live
#
# What it does:
#   1. builds the CLI (with the `tls` feature: Ed25519 license verification +
#      console mTLS) and the daemon (cargo, release profile). Set UFW_NO_TLS=1
#      for the pure zero-dependency, fully-offline build instead.
#   2. installs ufw-nft, ufwctl, firewall, ufw-daemon and ufw-waf to PREFIX/bin
#   3. installs the policies and the DPI/WAF signatures under /etc/unified-firewall
#   4. writes a monitor-mode daemon config (with the behavioral-detection suite
#      on: egress-anomaly, port-scan/sweep, C2-beaconing, credential brute-force,
#      DNS-tunnel — all alert-only) and installs systemd units for the firewall
#      policy, the daemon, the WAF and the dashboard, then enables and starts
#      them — so everything comes back automatically on every boot
#   5. loads a safe activation policy (default-ALLOW with a rate cap), so the
#      packet-filter, rate-limiting and attack-surface layers are live too. The
#      policy is reloaded at boot by firewall-policy.service (nftables rules do
#      not survive a reboot on their own), and it tracks whatever you last apply.
#   6. best-effort builds the DKMS kernel module (identity-aware + DPI ENFORCEMENT)
#      when dkms + kernel headers are present — the packet layer works without it.
#   7. licensing is OFF by default (frictionless from-source install). Turn it on
#      with UFW_ENABLE_LICENSING=1: installs license.conf + the periodic re-check
#      timer so enforcement then requires an activated, node-locked key.
#
# The dashboard carries a "What's new" page (http://127.0.0.1:8787/#features)
# that lists every one of these capabilities and its LIVE status on this host.
#
# Safety: the daemon starts in MONITOR mode (it observes and logs, it does not
# block), the WAF binds LOOPBACK only, and the loaded policy permits by default
# — denying only the never-legitimate protocols (telnet/FTP, SMB egress, bogons,
# inbound RDP). Nothing here can lock you out of your own machine. Going to real
# enforcement is one deliberate step, printed at the end.
#
# Remove everything with:  sudo ./install.sh --uninstall

set -eu

VERSION="${VERSION:-0.1.0}"
PREFIX="${PREFIX:-/usr/local}"
BIN="$PREFIX/bin"
ETC="/etc/unified-firewall"
POLICY_DST="$ETC/policies"
SIG_DST="$ETC/sig-rules"
DAEMON_POLICY="$ETC/daemon-policy"
CONFIG="$ETC/daemon.toml"
LICENSE_CONF="$ETC/license.conf"
UNIT_DIR="/etc/systemd/system"
STATE_DIR="/var/lib/unified-firewall"
KSRC="/usr/src/unified-firewall-$VERSION"
HERE="$(cd "$(dirname "$0")" && pwd)"

have_systemd() { [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

if [ "${1:-}" = "--uninstall" ]; then
    if have_systemd; then
        systemctl disable --now ufw-license-check.timer 2>/dev/null || true
        systemctl disable --now ufw-daemon.service ufw-waf.service ufw-nft.service firewall-policy.service 2>/dev/null || true
        rm -f "$UNIT_DIR/ufw-daemon.service" "$UNIT_DIR/ufw-waf.service" \
              "$UNIT_DIR/ufw-nft.service" "$UNIT_DIR/firewall-policy.service" \
              "$UNIT_DIR/ufw-license-check.service" "$UNIT_DIR/ufw-license-check.timer"
        systemctl daemon-reload 2>/dev/null || true
    fi
    # Best-effort: remove the DKMS kernel module and its staged source.
    if command -v dkms >/dev/null 2>&1; then
        dkms remove -m unified-firewall -v "$VERSION" --all >/dev/null 2>&1 || true
    fi
    rm -rf "$KSRC"
    rm -f "$BIN/firewall" "$BIN/ufw-nft" "$BIN/ufwctl" "$BIN/ufw-daemon" "$BIN/ufw-waf"
    echo "removed binaries, systemd units and the DKMS module."
    echo "left $ETC and $STATE_DIR in place (they may hold config/policy/license you edited)."
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
# The CLI ships with the `tls` feature so the installed firewall VERIFIES the
# Ed25519 license signature (not just the HMAC deterrent) and the console
# supports mTLS. rustls/ring are pinned in Cargo.lock, so once fetched this
# builds offline; on a first build they are pulled from crates.io. Set
# UFW_NO_TLS=1 for the pure zero-dependency, hand-rolled-only offline build
# (Ed25519 verify + console mTLS are then unavailable). Build as the invoking
# user so ~/.cargo stays theirs.
if [ "${UFW_NO_TLS:-0}" = "1" ]; then
    CLI_FEATURES=""
    echo "    (UFW_NO_TLS=1 — zero-dependency build; Ed25519 verify + mTLS disabled)"
else
    CLI_FEATURES="--features tls"
    echo "    (ufw-cli +tls: Ed25519 license verify + console mTLS)"
fi
BUILD="cd '$HERE' && cargo build --release -p ufw-cli $CLI_FEATURES && cargo build --release -p ufw-daemon"
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
# The daemon starts in user space regardless of the kernel module: it classifies,
# logs, detects egress anomalies, correlates and publishes telemetry. Even if the
# DKMS module built during install, blocking stays off until you switch mode to
# "enforce" (and, for identity/DPI enforcement, set require_kernel_module = true).
require_kernel_module = false

[policy]
dir = "$DAEMON_POLICY"
files = ["monitor_baseline.yaml"]
signature_dir = "$SIG_DST"
hot_reload = true

[logging]
stdout = false
level = "info"
# `anomaly = true` turns on the whole behavioral-detection suite that reads the
# flow stream: the egress baseline (novel-destination / exfil shape), the
# port-scan & network-sweep detector, the C2-beaconing (periodic-callback)
# detector, and the credential brute-force detector. Each emits alert events
# through the same sinks; none of them blocks (they are triage alerts).
anomaly = true
correlation = true

[api]
rest_bind = "127.0.0.1:9600"
# A fleet key (>=32 chars) turns on the fleet-rollout plane. Replace this with a
# real shared secret before distributing policy across hosts.
fleet_secret = "CHANGE-ME-before-fleet-use-0000000000000000"
EOF
chmod 0600 "$CONFIG"

# --- Kernel module (identity-aware + DPI ENFORCEMENT) via DKMS -------------
# The packet layer (nftables) works without this; the module only adds the
# ring-0 identity/DPI enforcement path. Best-effort: it needs dkms and the
# kernel headers, and a host without them keeps the packet layer and just skips
# the module. Never fails the install. Set UFW_NO_KMOD=1 to skip staging it.
if [ "${UFW_NO_KMOD:-0}" != "1" ] && [ -d "$HERE/kernel/linux/src" ]; then
    echo "==> staging kernel module source to $KSRC (for DKMS)"
    install -d "$KSRC/src" "$KSRC/inc"
    install -m 0644 "$HERE/kernel/linux/Kbuild" "$HERE/kernel/linux/Makefile" "$KSRC/"
    install -m 0644 "$HERE/kernel/linux/src/"*.c "$KSRC/src/"
    install -m 0644 "$HERE/kernel/linux/inc/"*.h "$KSRC/inc/"
    # dkms.conf with PACKAGE_VERSION pinned to this build's version.
    sed "s/^PACKAGE_VERSION=.*/PACKAGE_VERSION=\"$VERSION\"/" \
        "$HERE/kernel/linux/dkms.conf" > "$KSRC/dkms.conf"
    chmod 0644 "$KSRC/dkms.conf"
    if command -v dkms >/dev/null 2>&1; then
        echo "==> building the kernel module with DKMS (best-effort)"
        dkms add -m unified-firewall -v "$VERSION" >/dev/null 2>&1 || true
        if dkms build -m unified-firewall -v "$VERSION" >/dev/null 2>&1 \
           && dkms install --force -m unified-firewall -v "$VERSION" >/dev/null 2>&1; then
            echo "   module built — identity/DPI enforcement is available"
            echo "   (hardened build; its C decoders are CI-gated equal to a memory-safe Rust core)"
            echo "   (to use it: set mode=\"enforce\" + require_kernel_module=true in $CONFIG)"
            if command -v mokutil >/dev/null 2>&1 && mokutil --sb-state 2>/dev/null | grep -qi enabled; then
                echo "   Secure Boot is ON: the module must be MOK-signed + enrolled before it will load"
            fi
        else
            echo "   (module not built — needs linux-headers-\$(uname -r); packet layer works without it)"
            echo "    build it later:  sudo dkms autoinstall"
        fi
    else
        echo "   (dkms not installed — module source staged but not built; the packet layer works)"
        echo "    enable it later:  sudo apt install dkms linux-headers-\$(uname -r) && sudo dkms autoinstall"
    fi
fi

# --- Licensing (opt-in) ----------------------------------------------------
# Installing license.conf turns licensing ON: `firewall apply` (enforcement)
# then requires an activated, node-locked key. Monitor mode still runs unlicensed.
# Kept OFF by default so a from-source install stays frictionless and can never
# lock you out. Enable with UFW_ENABLE_LICENSING=1.
if [ "${UFW_ENABLE_LICENSING:-0}" = "1" ]; then
    echo "==> enabling licensing (installing $LICENSE_CONF)"
    install -m 0644 "$HERE/build/linux/license.conf" "$LICENSE_CONF"
    echo "   licensing is ON — activate this machine before enforcing:"
    echo "     sudo firewall license activate <YOUR-KEY>"
else
    echo "==> licensing left OFF (run with UFW_ENABLE_LICENSING=1 to require a key for enforcement)"
fi

if have_systemd; then
    echo "==> installing systemd services (firewall policy, daemon, WAF, dashboard)"
    install -m 0644 "$HERE/build/linux/firewall-policy.service" "$UNIT_DIR/firewall-policy.service"
    install -m 0644 "$HERE/build/linux/ufw-daemon.service"      "$UNIT_DIR/ufw-daemon.service"
    install -m 0644 "$HERE/build/linux/ufw-waf.service"         "$UNIT_DIR/ufw-waf.service"
    install -m 0644 "$HERE/build/linux/ufw-nft.service"         "$UNIT_DIR/ufw-nft.service"
    # License re-check unit + timer (inert until licensing is enabled; the timer
    # is only armed below when $LICENSE_CONF exists).
    install -m 0644 "$HERE/build/linux/ufw-license-check.service" "$UNIT_DIR/ufw-license-check.service"
    install -m 0644 "$HERE/build/linux/ufw-license-check.timer"   "$UNIT_DIR/ufw-license-check.timer"
    systemctl daemon-reload || true
    # Order matters: load the ruleset first (records state for the dashboard and
    # for future boots), then the observers, then the console. `enable --now`
    # arms each for boot AND starts it right now, so nothing needs a reboot.
    echo "==> enabling everything on boot and starting it now"
    systemctl enable --now firewall-policy.service || echo "   (firewall-policy did not apply — is nftables installed? journalctl -u firewall-policy)"
    systemctl enable --now ufw-daemon.service      || echo "   (ufw-daemon did not start — check: journalctl -u ufw-daemon)"
    systemctl enable --now ufw-waf.service         || echo "   (ufw-waf did not start — check: journalctl -u ufw-waf)"
    systemctl enable --now ufw-nft.service         || echo "   (dashboard did not start — check: journalctl -u ufw-nft)"
    # Arm the periodic license re-check only when licensing is enabled. It caches
    # a signed verdict with an offline grace window and reverts enforcement if the
    # key lapses — pointless (and noisy) when there is no license to check.
    if [ -f "$LICENSE_CONF" ]; then
        systemctl enable --now ufw-license-check.timer || echo "   (license-check timer did not start — check: journalctl -u ufw-license-check)"
        echo "   licensing re-check armed (every 6h; reverts enforcement if the key lapses)"
    fi
    echo "   on every boot from now on: the firewall policy reloads and the daemon, WAF and dashboard start automatically"
else
    echo "==> no systemd detected — starting daemon + WAF in the background"
    ( "$BIN/ufw-daemon" --config "$CONFIG" >/dev/null 2>&1 & ) || true
    ( "$BIN/ufw-waf" --listen 127.0.0.1:8443 --backend 127.0.0.1:80 --sig-dir "$SIG_DST" >/dev/null 2>&1 & ) || true
    echo "==> loading the activation policy (default-allow + a rate cap; nothing legitimate is blocked)"
    if "$BIN/ufw-nft" apply "$POLICY_DST/base/monitor_baseline.yaml" >/dev/null 2>&1; then
        echo "   loaded: packet-filter, rate-limiting and attack-surface layers are now live"
    else
        echo "   (could not load rules — is nftables installed? try: sudo firewall apply monitor_baseline)"
    fi
    echo "   note: without systemd these do NOT survive a reboot — re-run this after booting, or add your own init hook"
fi

# Give the services a moment to publish their first telemetry, then report.
sleep 4
echo
echo "installed and running. Layer status:"
if nft list table inet ufw >/dev/null 2>&1; then echo "  [live]  packet filter (nftables table inet ufw)"; else echo "  [down]  packet filter — is nftables installed?"; fi
for f in "$STATE_DIR/ufw-daemon-status.json:daemon (DPI, egress anomaly, port-scan, C2 beaconing, brute-force, DNS-tunnel, correlation, fleet)" \
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
echo "  what's new / feature status:  http://127.0.0.1:8787/#features"
echo "                                (live status of the module, rate-limiting, licensing, mTLS, …)"
echo "  honeypot / deception traps:   http://127.0.0.1:8787/#traps"
echo "                                (decoy routes + canary; add passive net decoys with:"
echo "                                 sudo firewall apply policies/base/honeypot_decoys.yaml)"
echo "  sudo firewall status                the loaded rules, with live counters"
echo
if [ -f "$LICENSE_CONF" ]; then
    echo "licensing is ON — enforcement needs an activated key, hardware-bound to this machine:"
    echo "  sudo firewall license activate <YOUR-KEY>       activate (binds to this host's hardware)"
    echo "  firewall license status                         show state + hardware match (--refresh to re-check)"
    echo "  (copying the license to other hardware is refused; to run ungated: sudo rm $LICENSE_CONF)"
    echo
fi
echo "when you are ready to actually BLOCK (not just observe):"
echo "  edit $CONFIG  → set  mode = \"enforce\"   then  sudo systemctl restart ufw-daemon"
echo "  and graduate the policy:  sudo firewall apply default_deny"
echo "  (whatever you 'apply' becomes what reloads on the next boot)"
if [ -d "$KSRC" ]; then
    echo "  for identity/DPI enforcement also set require_kernel_module = true (needs the DKMS module)"
fi
echo
if have_systemd; then
    echo "turn auto-start off for one piece:  sudo systemctl disable --now ufw-nft.service   (the dashboard)"
    echo "                                    sudo systemctl disable --now firewall-policy.service   (the whole packet filter)"
    echo
fi
echo
echo "prefer a cryptographically-verified package instead of a source build?"
echo "  released .debs carry keyless build provenance (SLSA + Rekor transparency log):"
echo "    gh attestation verify <the .deb> --repo fahad90fa/Firewall     (see docs/apt-repo.md)"
echo
echo "security scope (what enforces, what detects, what is NOT yet third-party audited):"
echo "  SECURITY.md  and  docs/security/audit-brief.md"
echo
echo "uninstall everything:  sudo ./install.sh --uninstall"

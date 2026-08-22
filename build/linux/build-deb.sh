#!/bin/sh
# Build a self-contained Debian package of the Unified Firewall's Linux
# user-space stack — the packet-layer enforcement that runs today with no
# kernel module. Uses only `dpkg-deb` (no fpm/ruby), so it works on any
# Debian-family host with dpkg.
#
#   sh build/linux/build-deb.sh            # -> dist/unified-firewall_<ver>_<arch>.deb
#   VERSION=0.1.0 sh build/linux/build-deb.sh
#
# What it installs on the target (mirrors install.sh, adapted to /usr):
#   /usr/bin/{ufw-nft,ufwctl,ufw-daemon,ufw-waf,firewall}
#   /lib/systemd/system/{firewall-policy,ufw-daemon,ufw-waf,ufw-nft}.service
#   /usr/share/unified-firewall/{policies,sig-rules}      (package-managed refs)
#   /etc/unified-firewall/daemon.toml                     (monitor-mode conffile)
# postinst seeds /etc, enables the services (monitor mode — observes, does not
# block) and starts them. Nothing here can lock you out of your own machine.
set -eu

VERSION="${VERSION:-0.1.0}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
BIN="$ROOT/target/release"
STAGE="$ROOT/build/deb/pkgroot"
OUT_DIR="${OUT_DIR:-$ROOT/dist}"
DEB="$OUT_DIR/unified-firewall_${VERSION}_${ARCH}.deb"

# 1. Binaries (build if missing) --------------------------------------------
if [ ! -x "$BIN/ufw-nft" ] || [ ! -x "$BIN/ufwd" ]; then
    echo "==> building release binaries"
    ( cd "$ROOT" && cargo build --release -p ufw-cli -p ufw-daemon )
fi

# 2. Stage the file tree -----------------------------------------------------
echo "==> staging under $STAGE"
rm -rf "$ROOT/build/deb"
install -d "$STAGE/usr/bin" "$STAGE/lib/systemd/system" \
    "$STAGE/usr/share/unified-firewall" "$STAGE/etc/unified-firewall" \
    "$STAGE/usr/share/doc/unified-firewall" "$STAGE/DEBIAN"

install -m 0755 "$BIN/ufw-nft" "$STAGE/usr/bin/ufw-nft"
install -m 0755 "$BIN/ufwctl"  "$STAGE/usr/bin/ufwctl"
install -m 0755 "$BIN/ufwd"    "$STAGE/usr/bin/ufw-daemon"
install -m 0755 "$BIN/ufw-waf" "$STAGE/usr/bin/ufw-waf"

# The `firewall` wrapper, with its default binary path moved off /usr/local.
sed 's#/usr/local/bin/ufw-nft#/usr/bin/ufw-nft#g' "$ROOT/build/linux/firewall.sh" \
    > "$STAGE/usr/bin/firewall"
chmod 0755 "$STAGE/usr/bin/firewall"

# systemd units, with ExecStart paths moved to /usr/bin.
for u in firewall-policy ufw-daemon ufw-waf ufw-nft; do
    sed 's#/usr/local/bin/#/usr/bin/#g' "$ROOT/build/linux/$u.service" \
        > "$STAGE/lib/systemd/system/$u.service"
    chmod 0644 "$STAGE/lib/systemd/system/$u.service"
done

# Reference policies + signatures (package-managed, read-only).
cp -R "$ROOT/policies" "$STAGE/usr/share/unified-firewall/policies"
cp -R "$ROOT/sig-rules" "$STAGE/usr/share/unified-firewall/sig-rules"

# Monitor-mode daemon config as a conffile.
cat > "$STAGE/etc/unified-firewall/daemon.toml" <<'CONF'
# Unified Firewall daemon — installed in MONITOR mode: it classifies, logs,
# detects egress anomalies and publishes telemetry, but does not block until you
# graduate to enforce. Nothing here can take you off the network.
[daemon]
mode = "monitor"
# No ufw kernel module is installed by this package, so the daemon runs in user
# space. The packet-layer policy still enforces through nftables (ufw-nft);
# identity/DPI blocking needs the module (a separate DKMS step).
require_kernel_module = false

[policy]
dir = "/etc/unified-firewall/daemon-policy"
files = ["monitor_baseline.yaml"]
signature_dir = "/etc/unified-firewall/sig-rules"
hot_reload = true

[logging]
stdout = false
level = "info"
anomaly = true
correlation = true

[api]
rest_bind = "127.0.0.1:9600"
# Replace before distributing policy across hosts (>=32 chars).
fleet_secret = "CHANGE-ME-before-fleet-use-0000000000000000"
CONF
chmod 0644 "$STAGE/etc/unified-firewall/daemon.toml"

cp "$ROOT/LICENSE" "$STAGE/usr/share/doc/unified-firewall/copyright" 2>/dev/null || true
cat > "$STAGE/usr/share/doc/unified-firewall/README.Debian" <<'DOC'
Unified Firewall (Linux packet-layer stack)
===========================================

Installed and started in MONITOR mode (observes, does not block). Open the live
console at http://127.0.0.1:8787 .

Enforce the packet policy (safe: denies only never-legitimate protocols):
    sudo firewall apply base/default_allow

Go to real deny-by-default once you have catalogued egress:
    sudo firewall apply base/default_deny

Turn the daemon to blocking (needs the kernel module, a separate DKMS step):
    edit /etc/unified-firewall/daemon.toml -> mode = "enforce"
    sudo systemctl restart ufw-daemon

Everything auto-starts on boot. Remove with: apt remove unified-firewall
DOC

# 3. Control metadata --------------------------------------------------------
INSTALLED_KB="$(du -ks "$STAGE" | cut -f1)"
cat > "$STAGE/DEBIAN/control" <<CONTROL
Package: unified-firewall
Version: $VERSION
Architecture: $ARCH
Maintainer: Unified Firewall <support@unifiedfirewall.dev>
Installed-Size: $INSTALLED_KB
Depends: nftables
Recommends: sudo
Section: admin
Priority: optional
Homepage: https://github.com/fahad90fa/Firewall
Description: Kernel-level host firewall that filters by signed application identity
 Unified Firewall compiles one policy file into kernel-level packet filtering
 and enforces it on Linux through a single nftables table (inet ufw) — no kernel
 module required for the packet layer. It ships identity-aware policy, an
 intrusion-prevention signature set, egress-anomaly and beaconing detection, an
 adaptive auto-response engine, and a live loopback web console.
 .
 Installs in monitor mode; graduate to enforcement with a single command.
CONTROL

cat > "$STAGE/DEBIAN/conffiles" <<'CONFF'
/etc/unified-firewall/daemon.toml
CONFF

# postinst: seed /etc, enable + start services (monitor-safe).
cat > "$STAGE/DEBIAN/postinst" <<'POST'
#!/bin/sh
set -e
ETC=/etc/unified-firewall
SHARE=/usr/share/unified-firewall
install -d -m 0755 "$ETC/policies" "$ETC/sig-rules" "$ETC/daemon-policy"
install -d -m 0750 /var/lib/unified-firewall

# Seed config trees from the package-managed reference copies if empty.
[ -z "$(ls -A "$ETC/policies" 2>/dev/null)" ] && cp -R "$SHARE/policies/." "$ETC/policies/" || true
[ -z "$(ls -A "$ETC/sig-rules" 2>/dev/null)" ] && cp -R "$SHARE/sig-rules/." "$ETC/sig-rules/" || true
[ -f "$ETC/daemon-policy/monitor_baseline.yaml" ] || \
    cp "$SHARE/policies/base/monitor_baseline.yaml" "$ETC/daemon-policy/monitor_baseline.yaml" 2>/dev/null || true

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    for s in firewall-policy ufw-daemon ufw-waf ufw-nft; do
        systemctl enable --now "$s.service" >/dev/null 2>&1 || \
            echo "note: $s.service did not start — check: journalctl -u $s"
    done
    echo "Unified Firewall is running in MONITOR mode. Console: http://127.0.0.1:8787"
else
    echo "Unified Firewall installed (no systemd detected — start services manually)."
fi
echo "Enforce the packet policy when ready:  sudo firewall apply base/default_allow"
exit 0
POST
chmod 0755 "$STAGE/DEBIAN/postinst"

# prerm: stop + disable services before files are removed.
cat > "$STAGE/DEBIAN/prerm" <<'PRE'
#!/bin/sh
set -e
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    for s in ufw-nft ufw-waf ufw-daemon firewall-policy; do
        systemctl disable --now "$s.service" >/dev/null 2>&1 || true
    done
    systemctl daemon-reload || true
fi
# Best-effort: drop the nftables table this package loaded.
command -v nft >/dev/null 2>&1 && nft delete table inet ufw >/dev/null 2>&1 || true
exit 0
PRE
chmod 0755 "$STAGE/DEBIAN/prerm"

# postrm: on purge, remove the config and state we seeded.
cat > "$STAGE/DEBIAN/postrm" <<'PRM'
#!/bin/sh
set -e
if [ "$1" = "purge" ]; then
    rm -rf /etc/unified-firewall /var/lib/unified-firewall
fi
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
exit 0
PRM
chmod 0755 "$STAGE/DEBIAN/postrm"

# 4. Build -------------------------------------------------------------------
install -d "$OUT_DIR"
echo "==> building $DEB"
dpkg-deb --root-owner-group --build "$STAGE" "$DEB" >/dev/null
echo "==> done"
dpkg-deb --info "$DEB" | sed 's/^/    /'
echo
echo "size: $(du -h "$DEB" | cut -f1)   path: $DEB"

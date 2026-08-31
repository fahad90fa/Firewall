#!/bin/sh
# Build a self-contained Debian package of the Unified Firewall's Linux
# user-space stack — the packet-layer enforcement that runs today with no
# kernel module. Uses only `dpkg-deb` (no fpm/ruby), so it works on any
# Debian-family host with dpkg.
#
#   sh build/linux/build-deb.sh            # -> dist/unified-firewall_<ver>_<arch>.deb
#   VERSION=0.1.2 sh build/linux/build-deb.sh
#
# What it installs on the target (mirrors install.sh, adapted to /usr):
#   /usr/bin/{ufw-nft,ufwctl,ufw-daemon,ufw-waf,firewall}
#   /lib/systemd/system/{firewall-policy,ufw-daemon,ufw-waf,ufw-nft}.service
#   /lib/systemd/system/ufw-license-check.{service,timer}  (periodic re-check)
#   /usr/share/unified-firewall/{policies,sig-rules}      (package-managed refs)
#   /usr/src/unified-firewall-<version>/                  (kernel module source; DKMS)
#   /etc/unified-firewall/daemon.toml                     (monitor-mode conffile)
#   /etc/unified-firewall/license.conf                    (turns licensing on)
# postinst seeds /etc, enables the services (monitor mode — observes, does not
# block) and starts them. Nothing here can lock you out of your own machine.
set -eu

VERSION="${VERSION:-0.1.2}"
RELEASE_DATE="${RELEASE_DATE:-2026-08-31}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"

# Reproducible builds: the same source must produce a byte-identical .deb.
# The metadata dates are already fixed (RELEASE_DATE, changelog, `gzip -9n`),
# but every file `install`/`cp` stages carries its build-time mtime, and
# dpkg-deb packs those into data.tar — so two builds a second apart differ. Pin
# a single timestamp for the whole package: honor an externally-supplied
# SOURCE_DATE_EPOCH (a CI reproducibility harness sets this from the commit),
# else derive it from the fixed RELEASE_DATE so a plain `build-deb.sh` is
# reproducible on its own. Every staged mtime is normalized to it below, and
# dpkg-deb (>= 1.18.11) additionally clamps to it, so old and new dpkg agree.
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH="$(date -u -d "$RELEASE_DATE" +%s 2>/dev/null || echo 1756425600)"
fi
export SOURCE_DATE_EPOCH
BIN="$ROOT/target/release"
STAGE="$ROOT/build/deb/pkgroot"
OUT_DIR="${OUT_DIR:-$ROOT/dist}"
DEB="$OUT_DIR/unified-firewall_${VERSION}_${ARCH}.deb"

# 1. Binaries ---------------------------------------------------------------
# Always let cargo decide: it is incremental (a no-op when nothing changed) and
# this avoids silently packaging a stale binary that predates a source change.
# Set UFW_DEB_SKIP_BUILD=1 to reuse whatever is already in target/release.
if [ "${UFW_DEB_SKIP_BUILD:-0}" != "1" ]; then
    # Both ufw-cli AND ufw-daemon ship with `tls`. This is the production
    # package, not the zero-dependency source build (`cargo build`, which stays
    # dep-free). With tls the daemon actually enforces the Ed25519 signature on
    # fleet bundles (api.fleet_ed25519_pubkey) and can terminate TLS on the
    # management API — otherwise those controls ship dormant, and a public key an
    # operator configures would be stored but never checked. The cli's tls buys
    # the Ed25519 license verify and console mTLS. rustls/ring are already pinned
    # in Cargo.lock, so this stays offline.
    echo "==> building release binaries (ufw-cli + ufw-daemon, +tls: Ed25519 fleet/license verify, mTLS)"
    # Remap the absolute build path out of the binaries so they do not embed the
    # checkout location (in a panic message or an assertion) — the same source
    # built under /home/a and /build/b then yields identical bytes. Combined with
    # the pinned Cargo.lock and the release profile's `strip`, this is what makes
    # the packaged binaries reproducible, not just the .deb wrapper around them.
    REMAP="--remap-path-prefix=$ROOT=/build/unified-firewall"
    ( cd "$ROOT" && RUSTFLAGS="${RUSTFLAGS:-} $REMAP" cargo build --release -p ufw-cli --features tls )
    ( cd "$ROOT" && RUSTFLAGS="${RUSTFLAGS:-} $REMAP" cargo build --release -p ufw-daemon --features tls )
fi
if [ ! -x "$BIN/ufw-nft" ] || [ ! -x "$BIN/ufwd" ]; then
    echo "error: release binaries missing under $BIN (build failed or was skipped)" >&2
    exit 1
fi

# 2. Stage the file tree -----------------------------------------------------
echo "==> staging under $STAGE"
rm -rf "$ROOT/build/deb"
install -d "$STAGE/usr/bin" "$STAGE/lib/systemd/system" \
    "$STAGE/usr/share/unified-firewall" "$STAGE/etc/unified-firewall" \
    "$STAGE/usr/share/doc/unified-firewall" "$STAGE/usr/share/metainfo" \
    "$STAGE/DEBIAN"

install -m 0755 "$BIN/ufw-nft" "$STAGE/usr/bin/ufw-nft"
install -m 0755 "$BIN/ufwctl"  "$STAGE/usr/bin/ufwctl"
install -m 0755 "$BIN/ufwd"    "$STAGE/usr/bin/ufw-daemon"
install -m 0755 "$BIN/ufw-waf" "$STAGE/usr/bin/ufw-waf"

# The `firewall` wrapper, with its default binary path moved off /usr/local.
sed 's#/usr/local/bin/ufw-nft#/usr/bin/ufw-nft#g' "$ROOT/build/linux/firewall.sh" \
    > "$STAGE/usr/bin/firewall"
chmod 0755 "$STAGE/usr/bin/firewall"

# systemd units, with ExecStart paths moved to /usr/bin.
for u in firewall-policy ufw-daemon ufw-waf ufw-nft ufw-license-check; do
    sed 's#/usr/local/bin/#/usr/bin/#g' "$ROOT/build/linux/$u.service" \
        > "$STAGE/lib/systemd/system/$u.service"
    chmod 0644 "$STAGE/lib/systemd/system/$u.service"
done
# The license re-check timer (no ExecStart to rewrite).
cp "$ROOT/build/linux/ufw-license-check.timer" "$STAGE/lib/systemd/system/ufw-license-check.timer"
chmod 0644 "$STAGE/lib/systemd/system/ufw-license-check.timer"

# Kernel module source for DKMS. The package ships the C module source under
# /usr/src/unified-firewall-<version>/; postinst runs `dkms` to build+install
# it against the running kernel (and again on kernel upgrades). This is what
# makes the identity-aware and DPI *enforcement* layers available — without it
# the package still enforces the L3/L4 packet layer via nftables. The build is
# best-effort: a host without kernel headers (or on an unsupported kernel) keeps
# the packet layer and just skips the module.
KSRC="$STAGE/usr/src/unified-firewall-$VERSION"
install -d "$KSRC/src" "$KSRC/inc"
install -m 0644 "$ROOT/kernel/linux/Kbuild" "$ROOT/kernel/linux/Makefile" "$KSRC/"
install -m 0644 "$ROOT/kernel/linux/src/"*.c "$KSRC/src/"
install -m 0644 "$ROOT/kernel/linux/inc/"*.h "$KSRC/inc/"
# dkms.conf with its PACKAGE_VERSION pinned to this build's version.
sed "s/^PACKAGE_VERSION=.*/PACKAGE_VERSION=\"$VERSION\"/" \
    "$ROOT/kernel/linux/dkms.conf" > "$KSRC/dkms.conf"
chmod 0644 "$KSRC/dkms.conf"

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

[edge]
# Opt-in on-host flood layer. When true, the daemon installs an nftables table
# (inet ufw_edge) ahead of the policy table that drops connection-rate floods in
# the kernel conntrack path: a SYN-flood cap, a per-source concurrent-connection
# cap, and an ICMP echo cap. It never changes what the policy permits.
#
# It does NOT absorb a volumetric DDoS — packets that saturate the link have
# already spent the bandwidth before they reach this host. That needs capacity
# upstream (a scrubbing service, a CDN, the provider's edge). This buys
# resistance to state/connection-rate floods, not immunity to a bandwidth flood.
flood_protection = false
# Defaults (shown commented) are generous; each has a floor of 1 so 0 can't self-DoS.
# syn_rate_per_sec = 200
# syn_burst = 50
# conns_per_source = 100
# icmp_rate_per_sec = 20
# icmp_burst = 10

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

# Licensing config as a conffile. Installing it turns licensing ON: `ufw-nft
# apply` (enforcement) then requires an activated key on this machine. Monitor
# mode still runs unlicensed — it observes, it does not block.
cp "$ROOT/build/linux/license.conf" "$STAGE/etc/unified-firewall/license.conf"
chmod 0644 "$STAGE/etc/unified-firewall/license.conf"

# AppStream metadata, so a software centre (GNOME Software, KDE Discover) shows
# a proper name, the Apache-2.0 license, and release notes instead of "Unknown
# License / No details for this release".
cat > "$STAGE/usr/share/metainfo/dev.unifiedfirewall.UnifiedFirewall.metainfo.xml" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<component type="console-application">
  <id>dev.unifiedfirewall.UnifiedFirewall</id>
  <metadata_license>CC0-1.0</metadata_license>
  <project_license>Apache-2.0</project_license>
  <name>Unified Firewall</name>
  <summary>Kernel-level host firewall that filters by signed application identity</summary>
  <description>
    <p>
      Unified Firewall compiles one policy file into kernel-level packet
      filtering and enforces it on Linux through a single nftables table
      (inet ufw) — no kernel module is required for the packet layer.
    </p>
    <p>It includes:</p>
    <ul>
      <li>Identity-aware policy that filters by signed application, not just port</li>
      <li>An intrusion-prevention signature set (IDS/IPS)</li>
      <li>Egress-anomaly and beaconing (command-and-control) detection</li>
      <li>An adaptive, opt-in auto-response engine</li>
      <li>A live, loopback-only web console</li>
    </ul>
    <p>
      Installs in monitor mode (it observes and logs, it does not block);
      graduate to enforcement with a single command.
    </p>
  </description>
  <categories>
    <category>System</category>
    <category>Security</category>
  </categories>
  <url type="homepage">https://github.com/fahad90fa/Firewall</url>
  <url type="bugtracker">https://github.com/fahad90fa/Firewall/issues</url>
  <developer_name>Unified Firewall</developer_name>
  <provides>
    <binary>ufw-nft</binary>
    <binary>ufwctl</binary>
    <binary>firewall</binary>
  </provides>
  <keywords>
    <keyword>firewall</keyword>
    <keyword>nftables</keyword>
    <keyword>security</keyword>
    <keyword>network</keyword>
    <keyword>ids</keyword>
  </keywords>
  <content_rating type="oars-1.1"/>
  <releases>
    <release version="$VERSION" date="$RELEASE_DATE">
      <description>
        <p>
          First public Linux release: nftables packet enforcement, identity-aware
          policy, IDS/IPS signatures, egress-anomaly and beaconing detection, an
          adaptive auto-response engine, and the live console. Installs in monitor
          mode.
        </p>
      </description>
    </release>
  </releases>
</component>
XML

# Machine-readable DEP-5 copyright declaring Apache-2.0.
cat > "$STAGE/usr/share/doc/unified-firewall/copyright" <<'COPY'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: unified-firewall
Upstream-Contact: Unified Firewall <support@unifiedfirewall.dev>
Source: https://github.com/fahad90fa/Firewall

Files: *
Copyright: 2026 Unified Firewall
License: Apache-2.0

License: Apache-2.0
 Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 this file except in compliance with the License. You may obtain a copy of the
 License at
 .
     https://www.apache.org/licenses/LICENSE-2.0
 .
 Unless required by applicable law or agreed to in writing, software distributed
 under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 CONDITIONS OF ANY KIND, either express or implied.
 .
 On Debian systems, the full text of the Apache License version 2.0 can be found
 in the file /usr/share/common-licenses/Apache-2.0.
COPY

# Debian changelog (compressed), so "No details for this release" is filled.
CHANGELOG_DATE="$(date -uR -d "$RELEASE_DATE" 2>/dev/null || echo 'Sat, 22 Aug 2026 00:00:00 +0000')"
cat > "$STAGE/usr/share/doc/unified-firewall/changelog.Debian" <<CHG
unified-firewall ($VERSION) unstable; urgency=medium

  * First public Linux release: kernel-level packet enforcement via nftables,
    identity-aware policy, IDS/IPS signatures, egress-anomaly and beaconing
    detection, an adaptive auto-response engine, and the live web console.
    Installs in monitor mode.

 -- Unified Firewall <support@unifiedfirewall.dev>  $CHANGELOG_DATE
CHG
gzip -9n "$STAGE/usr/share/doc/unified-firewall/changelog.Debian"

cat > "$STAGE/usr/share/doc/unified-firewall/README.Debian" <<'DOC'
Unified Firewall (Linux packet-layer stack)
===========================================

Installed and started in MONITOR mode (observes, does not block). Open the live
console at http://127.0.0.1:8787 .

Activation (required before enforcing):
    This build is licensed. Monitor mode runs unlicensed, but ENFORCEMENT
    (`firewall apply`) needs an activated key, node-locked to this machine:
        sudo firewall license activate <YOUR-KEY>
        firewall license status
    A timer re-checks periodically; if the key expires or is suspended/blocked
    by the vendor, enforcement is reverted automatically (you drop back to
    monitor-only). To run ungated, remove /etc/unified-firewall/license.conf .

Enforce the packet policy (safe: denies only never-legitimate protocols):
    sudo firewall apply default_allow

Go to real deny-by-default once you have catalogued egress:
    sudo firewall apply default_deny

Kernel module (identity-aware + DPI enforcement):
    The package ships the module source under /usr/src/unified-firewall-VERSION/
    and DKMS builds it for your kernel at install (and after kernel upgrades). It
    needs `dkms` and linux-headers-$(uname -r); without them the packet layer
    still works and the module is simply skipped — build it later with:
        sudo apt install dkms linux-headers-$(uname -r)
        sudo dkms autoinstall
    Then turn the daemon to blocking with the module:
        edit /etc/unified-firewall/daemon.toml -> mode = "enforce"
        and set require_kernel_module = true
        sudo systemctl restart ufw-daemon

    Secure Boot: an unsigned out-of-tree module will not load under Secure Boot.
    Either sign ufw.ko with a MOK you enrol (mokutil --import), or disable Secure
    Boot. The packet-layer firewall does not need the module or Secure Boot changes.

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
Depends: nftables, curl
Recommends: sudo, dkms, linux-headers-amd64 | linux-headers-generic
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
/etc/unified-firewall/license.conf
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
    # Periodic license re-check (reverts enforcement if the key lapses).
    systemctl enable --now ufw-license-check.timer >/dev/null 2>&1 || \
        echo "note: ufw-license-check.timer did not start — check: journalctl -u ufw-license-check"
    echo "Unified Firewall is running in MONITOR mode. Console: http://127.0.0.1:8787"
else
    echo "Unified Firewall installed (no systemd detected — start services manually)."
fi

# Kernel module (identity-aware + DPI *enforcement*) via DKMS — best-effort.
# The packet layer works without it; this only adds the ring-0 capabilities.
PKGVER="@PKGVER@"
if command -v dkms >/dev/null 2>&1; then
    dkms add -m unified-firewall -v "$PKGVER" >/dev/null 2>&1 || true
    if dkms build -m unified-firewall -v "$PKGVER" >/dev/null 2>&1 \
       && dkms install --force -m unified-firewall -v "$PKGVER" >/dev/null 2>&1; then
        echo "Kernel module built and installed — identity/DPI enforcement is available."
        echo "  (to use it, set mode=\"enforce\" + require_kernel_module=true in daemon.toml)"
        if command -v mokutil >/dev/null 2>&1 && mokutil --sb-state 2>/dev/null | grep -qi enabled; then
            echo "  Secure Boot is ON: the module must be MOK-signed + enrolled before it will load"
            echo "  — see /usr/share/doc/unified-firewall/README.Debian"
        fi
    else
        echo "note: kernel module not built (needs linux-headers-\$(uname -r) and a supported kernel);"
        echo "      the packet-layer firewall works without it. Build later: sudo dkms autoinstall"
    fi
else
    echo "note: dkms not installed — the kernel module (identity/DPI) was not built; the packet layer works."
    echo "      enable it with: sudo apt install dkms linux-headers-\$(uname -r) && sudo dkms autoinstall"
fi

echo "Activate this machine (required before enforcing):  sudo firewall license activate <KEY>"
echo "Then enforce the packet policy:                     sudo firewall apply default_allow"
exit 0
POST
sed -i "s/@PKGVER@/$VERSION/g" "$STAGE/DEBIAN/postinst"
chmod 0755 "$STAGE/DEBIAN/postinst"

# prerm: stop + disable services before files are removed.
cat > "$STAGE/DEBIAN/prerm" <<'PRE'
#!/bin/sh
set -e
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now ufw-license-check.timer >/dev/null 2>&1 || true
    for s in ufw-nft ufw-waf ufw-daemon firewall-policy; do
        systemctl disable --now "$s.service" >/dev/null 2>&1 || true
    done
    systemctl daemon-reload || true
fi
# Best-effort: drop the nftables table this package loaded.
command -v nft >/dev/null 2>&1 && nft delete table inet ufw >/dev/null 2>&1 || true
# Remove the DKMS module for this version (best-effort).
PKGVER="@PKGVER@"
if command -v dkms >/dev/null 2>&1; then
    dkms remove -m unified-firewall -v "$PKGVER" --all >/dev/null 2>&1 || true
fi
exit 0
PRE
sed -i "s/@PKGVER@/$VERSION/g" "$STAGE/DEBIAN/prerm"
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

# Normalize every staged file's mtime (and symlinks, with -h) to the pinned
# epoch so data.tar is byte-identical across builds. Done last, after the
# changelog gzip and every generated file, so nothing re-stamps them afterward.
find "$STAGE" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} + 2>/dev/null \
    || find "$STAGE" -exec touch -h -t "$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y%m%d%H%M.%S)" {} +

echo "==> building $DEB (reproducible; SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"
dpkg-deb --root-owner-group --build "$STAGE" "$DEB" >/dev/null
echo "==> done"
dpkg-deb --info "$DEB" | sed 's/^/    /'
echo
echo "size: $(du -h "$DEB" | cut -f1)   path: $DEB"

#!/bin/sh
# Build a DEB or RPM of the Unified Firewall.
#
# Usage:
#   build/linux/package.sh deb
#   build/linux/package.sh rpm
#
# What this packages, and what it deliberately does not:
#
#   Packaged:  the daemon, the CLI, the signature rules, the systemd units,
#              the module sources for DKMS.
#   Not packaged: a policy.
#
# The omission is the important part. A firewall package that installs a policy
# starts enforcing something the operator did not choose the moment it is
# installed — either a permissive one, which is security theatre, or a
# restrictive one, which takes the machine off the network during a routine
# `apt install`. Neither is acceptable, so the package installs the machinery
# and the daemon refuses to start until a policy is named.

set -eu

FORMAT="${1:-}"
VERSION="${VERSION:-0.1.0}"
ARCH="$(uname -m)"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STAGE="${ROOT}/build/stage"

case "$FORMAT" in
    deb|rpm) ;;
    *)
        echo "usage: $0 {deb|rpm}" >&2
        exit 2
        ;;
esac

command -v fpm >/dev/null 2>&1 || {
    echo "error: fpm is required to build packages." >&2
    echo "       gem install --no-document fpm" >&2
    exit 1
}

echo "==> building release binaries"
cargo build --release --workspace --locked

echo "==> staging"
rm -rf "$STAGE"
install -d "$STAGE/usr/sbin" "$STAGE/usr/bin"
install -d "$STAGE/etc/unified-firewall/policies"
install -d "$STAGE/etc/unified-firewall/sig-rules"
install -d "$STAGE/usr/lib/systemd/system"
install -d "$STAGE/usr/src/unified-firewall-${VERSION}"

install -m 0755 "${ROOT}/target/release/ufwd" "$STAGE/usr/sbin/ufwd"
install -m 0755 "${ROOT}/target/release/ufwctl" "$STAGE/usr/bin/ufwctl"
cp -R "${ROOT}/sig-rules/." "$STAGE/etc/unified-firewall/sig-rules/"

# Module sources for DKMS to rebuild against each kernel.
cp -R "${ROOT}/kernel/linux/." "$STAGE/usr/src/unified-firewall-${VERSION}/"
cp "${ROOT}/build/linux/dkms.conf" "$STAGE/usr/src/unified-firewall-${VERSION}/dkms.conf"

# --- systemd units -------------------------------------------------------

# Two units, because loading the eBPF programs and running the daemon fail
# differently and should be diagnosable separately. A daemon that will not
# start because the fast path failed to load is a confusing symptom; a
# `ufw-ebpf.service` in a failed state is not.
cat > "$STAGE/usr/lib/systemd/system/ufw-ebpf.service" <<'UNIT'
[Unit]
Description=Unified Firewall eBPF fast path
Documentation=man:ufwd(8)
Before=unified-firewall.service
# The BPF filesystem is where the maps are pinned so they survive a daemon
# restart — without it an operator restarting the daemon would flush the flow
# table and re-decide every established connection.
RequiresMountsFor=/sys/fs/bpf

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/ufwd --load-ebpf
ExecStop=/usr/sbin/ufwd --unload-ebpf
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN

[Install]
WantedBy=multi-user.target
UNIT

cat > "$STAGE/usr/lib/systemd/system/unified-firewall.service" <<'UNIT'
[Unit]
Description=Unified Firewall control daemon
Documentation=man:ufwd(8)
# Ordered after the network is up but before anything that uses it, so a
# machine does not spend its first seconds online unfiltered.
After=network-pre.target
Wants=network-pre.target
Before=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/ufwd --config /etc/unified-firewall/ufwd.toml
# ExecStop rather than a signal: the daemon has no SIGTERM handler, because
# installing one needs libc and this workspace takes no dependencies. Shutdown
# goes through the control socket instead. A SIGTERM with no handler still
# terminates the process; the sockets are cleaned up by the kernel and the next
# start clears any stale socket file itself.
ExecStop=/usr/bin/ufwctl shutdown
Restart=on-failure
RestartSec=2

# The daemon needs to install policy into the kernel module and to read
# /proc/<pid>/exe for identity resolution. It does not need anything else, and
# the sandbox below is what says so.
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_PTRACE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/log/unified-firewall /run/unified-firewall
# Not ProtectKernelModules: the daemon talks to one.
ProtectKernelTunables=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
UNIT

# --- default configuration ----------------------------------------------

# Config, but no policy. See the header for why.
cat > "$STAGE/etc/unified-firewall/ufwd.toml" <<'CONF'
# Unified Firewall daemon configuration.
#
# `policy.path` is deliberately left pointing at a file that does not exist.
# The daemon will refuse to start until you put a policy there, which is the
# intended behaviour: a firewall package must not choose your policy for you.
#
# To get started, copy one of the shipped examples:
#
#   # A rollout, in the order that does not cause an outage:
#   cp /usr/share/unified-firewall/policies/base/default_allow.yaml \
#      /etc/unified-firewall/policies/active.yaml
#   # ... collect the inventory, write the allow rules, then:
#   cp /usr/share/unified-firewall/policies/base/default_deny.yaml \
#      /etc/unified-firewall/policies/active.yaml

[daemon]
host_id = ""            # empty means "use the system hostname"
mode = "enforce"
require_kernel_module = true

[policy]
path = "/etc/unified-firewall/policies/active.yaml"
signature_dir = "/etc/unified-firewall/sig-rules"
watch = true

[ipc]
endpoint = "netlink:ufw_ctrl"
connect_timeout_ms = 5000

[logging]
level = "info"
file = "/var/log/unified-firewall/events.log"

[api]
# Loopback only by default. Binding this to a routable address without an
# auth_token is refused at startup, because a management API that can install
# policy is a remote code path into the kernel.
bind = "127.0.0.1:9443"
CONF

install -d "$STAGE/usr/share/unified-firewall"
cp -R "${ROOT}/policies" "$STAGE/usr/share/unified-firewall/"

# --- post-install --------------------------------------------------------

cat > "${ROOT}/build/stage-postinstall.sh" <<'POST'
#!/bin/sh
set -e
dkms add     -m unified-firewall -v VERSION_PLACEHOLDER || true
dkms build   -m unified-firewall -v VERSION_PLACEHOLDER || true
dkms install -m unified-firewall -v VERSION_PLACEHOLDER || true
install -d -m 0750 /var/log/unified-firewall /run/unified-firewall
systemctl daemon-reload

echo
echo "Unified Firewall installed. It is not running: no policy is configured."
echo
echo "  1. Choose a policy and copy it to"
echo "     /etc/unified-firewall/policies/active.yaml"
echo "     Examples are in /usr/share/unified-firewall/policies/"
echo "  2. ufwctl policy validate /etc/unified-firewall/policies/active.yaml"
echo "  3. systemctl enable --now ufw-ebpf unified-firewall"
echo
echo "If this machine has never had its egress catalogued, start with"
echo "base/default_allow.yaml in monitor mode. Switching straight to"
echo "default-deny on an uncatalogued fleet produces an outage and a rollback."
POST
sed -i "s/VERSION_PLACEHOLDER/${VERSION}/g" "${ROOT}/build/stage-postinstall.sh"
chmod +x "${ROOT}/build/stage-postinstall.sh"

echo "==> building ${FORMAT}"
fpm -s dir -t "$FORMAT" \
    -n unified-firewall \
    -v "$VERSION" \
    -a "$ARCH" \
    --description "Unified cross-platform kernel-level firewall" \
    --url "https://github.com/fahad90fa/Firewall" \
    --license "Apache-2.0" \
    --depends dkms \
    --config-files /etc/unified-firewall/ufwd.toml \
    --after-install "${ROOT}/build/stage-postinstall.sh" \
    -C "$STAGE" \
    .

echo "==> done"
ls -1 unified-firewall*."$FORMAT" 2>/dev/null || true

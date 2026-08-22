#!/bin/sh
# A repeatable live-kernel enforcement run of the nftables path.
#
# Applies a compiled policy into the LIVE kernel and drives real traffic through
# it, then reports the kernel's own per-rule counters. This is the smoke-scale
# slice of the runtime question documented in docs/design/soak_testing.md — it
# proves the enforcement path is real on a live kernel, and is explicitly NOT the
# 30-day soak, not the kernel module (ufw.ko), and not Windows/macOS.
#
# It runs inside a fresh network namespace so it can never cost the host its own
# connectivity — the watchdog's governing rule applied to the test itself.
#
# Usage:  sudo sh scripts/live-run.sh [window_seconds] [policy.yaml]
# Needs:  root, nftables, python3, curl; a release build of ufw-nft.
set -eu

WINDOW="${1:-90}"
POLICY="${2:-policies/base/default_allow.yaml}"
BIN="${UFW_NFT_BIN:-target/release/ufw-nft}"
NFT="$(command -v nft)"

[ -x "$BIN" ] || { echo "build first: cargo build --release --bin ufw-nft" >&2; exit 1; }
[ -n "$NFT" ] || { echo "nftables (nft) not found" >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root (loads a ruleset into the kernel)" >&2; exit 1; }

ABS_BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
ABS_POLICY="$(cd "$(dirname "$POLICY")" && pwd)/$(basename "$POLICY")"

exec unshare --net sh -s "$WINDOW" "$ABS_BIN" "$ABS_POLICY" "$NFT" <<'INNER'
set -eu
WINDOW="$1"; BIN="$2"; POLICY="$3"; NFT="$4"

# Bring loopback up in the fresh namespace (no `ip` dependency).
python3 - <<'PY'
import fcntl, socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
fcntl.ioctl(s, 0x8914, struct.pack('16sh', b'lo', 0x1 | 0x40))  # SIOCSIFFLAGS, IFF_UP|IFF_RUNNING
PY

"$BIN" apply "$POLICY" >/dev/null 2>&1
"$NFT" list table inet ufw >/dev/null 2>&1 || { echo "policy did not load into the kernel" >&2; exit 1; }

python3 -m http.server 8080 --bind 127.0.0.1 >/dev/null 2>&1 &
LPID=$!
trap 'kill $LPID 2>/dev/null || true' EXIT

echo "policy: $(basename "$POLICY")  window: ${WINDOW}s  kernel: $(uname -r)"
start=$(date +%s); end=$((start + WINDOW)); http=0; ok=0
while [ "$(date +%s)" -lt "$end" ]; do
    i=0; while [ "$i" -lt 40 ]; do
        code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 1 http://127.0.0.1:8080/ 2>/dev/null || echo 000)
        http=$((http + 1)); [ "$code" = 200 ] && ok=$((ok + 1)); i=$((i + 1))
    done
    python3 - <<'PY'
import socket
for _ in range(500):
    for p in (23, 3389):            # cleartext + RDP: ports default_allow drops inbound
        s = socket.socket(); s.setblocking(False)
        try: s.connect_ex(('127.0.0.1', p))
        except OSError: pass
        s.close()
PY
done
dur=$(( $(date +%s) - start ))

echo "duration_s: $dur   http_200: $ok/$http"
echo "--- kernel per-rule counters that matched real packets ---"
"$NFT" list table inet ufw 2>/dev/null | grep -E 'counter packets [1-9]' \
    | sed -E 's/.*counter (packets [0-9]+ bytes [0-9]+) (drop|accept).*comment "([^"]+)".*/  \3: \1 \2/'
acc=$("$NFT" list table inet ufw 2>/dev/null | grep accept | grep -oE 'packets [0-9]+' | grep -oE '[0-9]+' | awk '{s+=$1} END{print s+0}')
drp=$("$NFT" list table inet ufw 2>/dev/null | grep drop   | grep -oE 'packets [0-9]+' | grep -oE '[0-9]+' | awk '{s+=$1} END{print s+0}')
echo "accepted_total: $acc   dropped_total: $drp   through_hook_per_s: $(( (acc + drp) / (dur > 0 ? dur : 1) ))"
INNER

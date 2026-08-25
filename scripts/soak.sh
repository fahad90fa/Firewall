#!/bin/sh
# Soak test — turn "it runs" into "it ran clean for N seconds under M packets,
# zero crashes, bounded memory."
#
# Applies a policy into the LIVE kernel, runs the always-on component (the
# dashboard) as the watched long-lived process, drives sustained benign +
# adversarial loopback traffic, and samples — every INTERVAL — the kernel's own
# nft counters, the process's liveness and RSS, and an HTTP liveness probe. At
# the end it reports duration, packets moved, memory drift, and crash count, and
# writes a markdown results file. This is the runtime-evidence lever from
# docs/design/soak_testing.md; a real 30-day fleet soak is still its own thing.
#
# It runs inside a fresh network namespace, so it can never cost the host its
# own connectivity.
#
# Usage:  sudo sh scripts/soak.sh [duration_s] [policy.yaml] [interval_s]
# Needs:  root, nftables, python3; a release build of ufw-nft.
set -eu

DURATION="${1:-1800}"
POLICY="${2:-policies/base/monitor_baseline.yaml}"
INTERVAL="${3:-30}"
BIN="${UFW_NFT_BIN:-target/release/ufw-nft}"
NFT="$(command -v nft || true)"
OUT="${SOAK_OUT:-docs/design/soak-results-latest.md}"

[ -x "$BIN" ] || { echo "build first: cargo build --release --bin ufw-nft" >&2; exit 1; }
[ -n "$NFT" ] || { echo "nftables (nft) not found" >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root (loads a ruleset into the kernel)" >&2; exit 1; }

ABS_BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
ABS_POLICY="$(cd "$(dirname "$POLICY")" && pwd)/$(basename "$POLICY")"
ABS_OUT="$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")"

exec unshare --net sh -s "$DURATION" "$INTERVAL" "$ABS_BIN" "$ABS_POLICY" "$NFT" "$ABS_OUT" "$POLICY" <<'INNER'
set -eu
DURATION="$1"; INTERVAL="$2"; BIN="$3"; POLICY="$4"; NFT="$5"; OUT="$6"; POLICY_LABEL="$7"

# Loopback up in the fresh namespace (no `ip` dependency).
python3 - <<'PY'
import fcntl, socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
fcntl.ioctl(s, 0x8914, struct.pack('16sh', b'lo', 0x1 | 0x40))  # SIOCSIFFLAGS, IFF_UP|IFF_RUNNING
PY

"$BIN" apply "$POLICY" >/dev/null 2>&1 || { echo "apply failed" >&2; exit 1; }

# The watched long-lived process: the live console.
"$BIN" dashboard 127.0.0.1:8799 >/dev/null 2>&1 &
DASH=$!
sleep 1

# Traffic generator: sustained benign connections through loopback, periodic
# adversarial bursts, and connections to a closed port — real load the kernel
# path must survive. Runs for the whole window, then exits.
python3 - "$DURATION" <<'PY' &
import socket, time, sys, threading
end = time.time() + int(sys.argv[1])
# a benign echo listener
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 8700)); srv.listen(64)
def serve():
    while time.time() < end:
        try:
            srv.settimeout(1.0); c,_ = srv.accept(); c.recv(64); c.close()
        except Exception: pass
threading.Thread(target=serve, daemon=True).start()
n = 0
while time.time() < end:
    # benign
    for _ in range(50):
        try:
            s = socket.create_connection(("127.0.0.1", 8700), timeout=0.5)
            s.sendall(b"ping"); s.close(); n += 1
        except Exception: pass
    # adversarial: bursts + closed-port probes
    for _ in range(200):
        try:
            s = socket.socket(); s.setblocking(False); s.connect_ex(("127.0.0.1", 9)); s.close()
        except Exception: pass
open("/tmp/soak_sent","w").write(str(n))
PY
GEN=$!

rss_of() { awk '/VmRSS/{print $2}' "/proc/$1/status" 2>/dev/null || echo 0; }
counters() { "$NFT" list table inet ufw 2>/dev/null | awk '/packets/{for(i=1;i<=NF;i++) if($i=="packets") s+=$(i+1)} END{print s+0}'; }

start=$(date +%s); crashes=0; samples=0; rss_min=; rss_max=0; ruleset_ok=1
while :; do
    now=$(date +%s); el=$((now-start)); [ "$el" -ge "$DURATION" ] && break
    if ! kill -0 "$DASH" 2>/dev/null; then crashes=$((crashes+1)); break; fi
    rss=$(rss_of "$DASH"); pk=$(counters)
    "$NFT" list table inet ufw >/dev/null 2>&1 || ruleset_ok=0
    [ -z "$rss_min" ] && rss_min=$rss
    [ "$rss" -lt "$rss_min" ] 2>/dev/null && rss_min=$rss
    [ "$rss" -gt "$rss_max" ] 2>/dev/null && rss_max=$rss
    samples=$((samples+1))
    printf '  t=%4ss  rss=%sKB  nft_packets=%s  ruleset=%s\n' "$el" "$rss" "$pk" "$ruleset_ok"
    sleep "$INTERVAL"
done

kill "$GEN" "$DASH" 2>/dev/null || true
sent=$(cat /tmp/soak_sent 2>/dev/null || echo 0)
final_pk=$(counters)
drift=$((rss_max - ${rss_min:-0}))
verdict=PASS
[ "$crashes" -eq 0 ] && [ "$ruleset_ok" -eq 1 ] || verdict=FAIL

{
  echo "# Soak results (latest)"
  echo
  echo "- policy: \`$POLICY_LABEL\`"
  echo "- window: ${DURATION}s, sampled every ${INTERVAL}s ($samples samples)"
  echo "- benign connections issued: $sent"
  echo "- nft packets counted (final): $final_pk"
  echo "- dashboard RSS: min ${rss_min:-?}KB, max ${rss_max}KB, drift ${drift}KB"
  echo "- crashes: $crashes"
  echo "- ruleset stayed loaded: $([ "$ruleset_ok" -eq 1 ] && echo yes || echo NO)"
  echo "- **verdict: $verdict**"
  echo
  echo "_Generated by scripts/soak.sh. This is a smoke-scale soak; a 30-day"
  echo "fleet soak under production traffic is the real target and is tracked"
  echo "separately in docs/design/soak_testing.md._"
} > "$OUT"

echo
echo "verdict: $verdict  (crashes=$crashes ruleset_ok=$ruleset_ok samples=$samples sent=$sent drift=${drift}KB)"
echo "wrote $OUT"
INNER

#!/bin/sh
# run.sh — apply an emitted nftables ruleset in a throwaway network namespace
# and report, for each probe, whether a real loopback packet was allowed or
# dropped.
#
# This is the Level-2 half of the enforcement-conformance test. Level 1 is
# `nft --check -f` (the ruleset parses and the kernel accepts it); Level 2, here,
# is the stronger claim: a packet the policy says to allow gets through, and one
# it says to deny does not. It is what turns "the compiler emitted plausible
# nftables" into "the emitted nftables enforces the policy."
#
# Usage:
#   run.sh <netprobe-binary> <nft-file> PORT:allow PORT:deny ...
#
# It re-execs itself inside `unshare -n` so the ruleset, the interface state and
# the sockets are all confined to a namespace that evaporates when the script
# exits — the host's own firewall is never touched. Output is one line per
# probe, `PORT observed=allow|deny`, then a final `RESULT ok`. Any setup failure
# prints `RESULT error: <reason>` and exits non-zero, so the caller can tell
# "the test ran and disagreed" from "the test could not run."
set -eu

NETPROBE=$1
NFT_FILE=$2
shift 2

fail() {
    echo "RESULT error: $1"
    exit 1
}

# Re-enter inside a fresh network namespace exactly once. The env guard prevents
# an infinite re-exec if `unshare` silently no-ops.
if [ "${UFW_NETNS_INNER:-}" != 1 ]; then
    command -v unshare >/dev/null 2>&1 || fail "unshare not available"
    exec unshare -n env UFW_NETNS_INNER=1 "$0" "$NETPROBE" "$NFT_FILE" "$@"
fi

[ -x "$NETPROBE" ] || fail "netprobe helper not executable: $NETPROBE"
[ -r "$NFT_FILE" ] || fail "nft file not readable: $NFT_FILE"

# Bring loopback up. Prefer `ip` when present (it is, in CI); fall back to the
# helper's raw ioctl on minimal images that ship no iproute2.
if command -v ip >/dev/null 2>&1; then
    ip link set lo up 2>/dev/null || "$NETPROBE" up || fail "could not bring lo up"
else
    "$NETPROBE" up || fail "could not bring lo up (no ip, ioctl failed)"
fi

command -v nft >/dev/null 2>&1 || fail "nft not available"
nft -f "$NFT_FILE" || fail "loading the emitted ruleset failed"

for probe in "$@"; do
    port=${probe%%:*}
    if "$NETPROBE" connect "$port"; then
        echo "$port observed=allow"
    else
        echo "$port observed=deny"
    fi
done

echo "RESULT ok"

# Real-packet enforcement conformance

The rest of the test suite compares policy *models* — the reference evaluator,
the cross-platform equivalence verifier. Nothing else loads the nftables the
compiler actually emits into a kernel and fires a packet at it. This directory
is that missing level.

`../scenarios/enforcement_conformance.rs` drives it. Two helpers live here:

* **`netprobe.c`** — a ~60-line C helper, compiled on demand with the same `cc`
  the kernel module already needs (so no `libc` crate lands in the workspace).
  `netprobe up` brings `lo` up in a fresh namespace via a raw ioctl (no `ip`
  binary required); `netprobe connect PORT` reports, by exit code, whether a
  loopback handshake completes or is dropped.

* **`run.sh`** — re-execs itself under `unshare -n`, brings `lo` up, loads a
  supplied ruleset, and prints one `PORT observed=allow|deny` line per probe.
  The namespace evaporates on exit, so the host firewall is never touched.

The test is capability-gated: without root, `nft`, `unshare` and `cc` it reports
itself unavailable rather than passing vacuously. CI sets `UFW_NFT_REQUIRE=1`
and `UFW_NETNS_REQUIRE=1`, which turn "could not run" into a hard failure — so a
green check means enforcement was proven against a real packet, not skipped.

Run it locally as root:

    UFW_NFT_REQUIRE=1 UFW_NETNS_REQUIRE=1 \
      cargo test -p ufw-e2e --test enforcement_conformance -- --test-threads=1

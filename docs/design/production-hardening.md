# Production hardening: the roadmap, and what closed it

[`production_readiness.md`](production_readiness.md) named the work that stood
between "correct code" and "a firewall you can deploy" and grouped it into a
roadmap of eleven concrete items across three tiers, plus a fourth tier that is
process rather than code. This document is the completion record: for each item,
what was built, where it lives, and the test that proves it — and, kept in the
same place so the honesty is not buried, the items that remain open because no
commit can close them.

The governing rule throughout was the one this project holds everywhere: **never
fake a green.** Where a guarantee needs a kernel this environment does not have,
or a private key that must not live in the tree, the code builds the real
mechanism and gates the unprovable half behind an environment flag or a
`--features` opt-in that says so, rather than asserting a property it did not
check.

## Tier 1 — the correctness blockers

### 1. Real-packet enforcement conformance

The `allow-inspect` policy bypass existed because the equivalence checker only
ever compared the decision *model*; nothing loaded the nftables the compiler
*emits* into a kernel and fired a packet at it. That class is now closed.

- `tests/harness/enforcement.rs`, `tests/netns/{netprobe.c,run.sh}`,
  `tests/scenarios/enforcement_conformance.rs`.
- Level 1 runs the kernel's own parser over the emitted ruleset (`nft --check`);
  Level 2 loads it in a throwaway network namespace and fires a real loopback
  connection per probe — allow must complete the handshake, deny must be dropped.
- The `allow-inspect` regression is pinned to a *packet*: with the return path
  opened by a positive control, an inspect-layer allow must still leave the
  forward connection failing on the nft path, proving the provisional permit did
  not lower to a terminal accept.
- CI job `enforcement-conformance` runs it as root with `UFW_NFT_REQUIRE=1` /
  `UFW_NETNS_REQUIRE=1`, so "did not run" is a hard failure, never a silent pass.

### 2. Fuzz the whole hostile-byte surface

The unauth crash lived in the console's HTTP parser, which was not fuzzed. The
three Rust parsers that face the network and the fleet channel now are.

- `tests/harness/fuzz.rs`, `tests/scenarios/parser_fuzz.rs`, and
  `cli/src/bin/ufw-nft/dashboard/mod.rs` (`request_head_parsing_never_panics`).
- A deterministic, dependency-free driver drives random and mutation-derived
  inputs through `Message::decode` / `MessageHeader::parse` (the IPC wire
  protocol), `compile_str` (the policy language), and the console request head
  (`parse_request_head`, extracted to a pure function), plus `percent_decode`,
  `qget`, and `rbac::bearer`. The property: any bytes in, a result out, no
  unwind — with the offending input printed in hex on a crash.
- Rides in `cargo test --workspace`; open-ended coverage-guided search stays in
  the scheduled libFuzzer campaign (`fuzz/`).

### 3. Every advertised layer actually runs

The DNS-exfil detector once shipped as dead code while the docs claimed it. One
test now asks each advertised capability to produce a concrete effect, so a
whole layer going no-op is a single named red.

- `tests/scenarios/every_layer_runs.rs`.
- Covers cross-platform equivalence, packet enforcement, identity, the DPI
  signature engine, the inbound WAF, all five egress detectors (portscan,
  brute-force, beacon, DNS-exfil, egress anomaly), and signed fleet rollout with
  rollback. The honeypot, RBAC/mTLS console and one-click contain live in the
  `ufw-nft` binary and are exercised by that crate's own tests, named in the
  module doc so the advertised-to-tested map is complete.

### 4. Third-party audit — external, and made cheaper

An external review by someone with no stake in the result cannot be a commit;
what a commit can do is shrink its scope and its findings. Tier 1 does exactly
that — every emitted artifact is now packet-checked, every hostile-byte parser
fuzzed, every advertised layer proven live — and the audit-preparation artifacts
name the surface for a reviewer: [`../security/audit-brief.md`](../security/audit-brief.md),
[`../security/audit-rfp.md`](../security/audit-rfp.md), and
[`../security/attack-surface.md`](../security/attack-surface.md), with the ring-0
parsing (`dpi_decoders.h`, the reassembler) as the first target. **Open:** the
review itself.

## Tier 2 — fail-safe & resilience

### 5. Documented, tested fail-safe posture

What the daemon does when it *cannot* enforce is now an explicit operator choice,
not an accident. Previously, running without the kernel module printed
"continuing without enforcement" and left the host wide open — a silent
fail-open.

- `daemon/src/failsafe.rs`, config key `daemon.fail_mode`.
- `FailMode { Closed (default), Open }`; `posture(mode, PathHealth)` is a pure
  function whose every outcome is a fault-injection unit test. `closed` installs
  an emergency default-deny nftables barrier that keeps the operator in
  (loopback, established/related flows, and the management/SSH ports); `open`
  leaves the host reachable and unfiltered, loudly. The barrier loads into a real
  kernel (conformance test, using conntrack state and a negative hook priority a
  string test cannot confirm). This complements the runtime `watchdog`, which
  holds the last-installed policy resident on a *post-working* fault.

### 6. Boot-time enforcement gap

- `build/linux/firewall-policy.service`, `tests/scenarios/systemd_hardening.rs`.
- The oneshot restores the ruleset `Before=network-pre.target` with
  `DefaultDependencies=no`, so the host is filtered before the network comes up —
  nftables does not survive a reboot, and this is the directive that closes the
  window. A test pins the ordering so it cannot silently regress.

### 7. Privilege reduction

- `build/linux/*.service`, `tests/scenarios/systemd_hardening.rs`.
- Every unit is bounded to the capabilities it actually uses and sandboxed. The
  self-contained WAF is locked to the empty capability set with a system-call
  allowlist and W^X (`systemd-analyze` exposure 9.x → **1.6**); the console and
  daemon are bounded to `CAP_NET_ADMIN` (+`CAP_NET_RAW`/`CAP_SYSLOG`) with the
  process-hiding, kernel-log and syscall-filter directives deliberately omitted
  where they would break `dmesg`/`journalctl`/`/proc` reads — noted inline so the
  omissions are chosen, not forgotten. A test asserts each unit drops privilege
  and that none bounds in a near-root capability, and (under
  `UFW_SYSTEMD_REQUIRE=1`) that `systemd-analyze verify` accepts every unit.

## Tier 3 — operational maturity

### 8. Tamper-evident audit logs

- `daemon/src/audit.rs`; `ufwd --verify-audit <path>`.
- An append-only, hash-chained log of enforcement changes (policy installs, mode
  switches, the fail-closed barrier, fleet bundles). Any edit, reorder,
  insertion or middle-deletion is detected by `verify_chain`, which names the
  first break. Documented honestly as tamper-*evidence*, not tamper-proofing:
  an optional HMAC key stops an attacker without it from forging a verifying
  record, and an external head anchor (emitted to the event log on each append)
  makes tail truncation detectable. Opened and verified at startup — a start onto
  a tampered log is refused, not laundered under fresh links.

### 9. Self-monitoring + alerting

- `daemon/src/selfcheck.rs`, wired into the daemon idle loop.
- Alerts on the failures that leave the daemon *looking* healthy: a stopped
  detector worker, a failing sink, dropped telemetry, and policy drift (the
  enforced ruleset differing from disk). A pure decision engine with built-in
  de-duplication (a persistent fault is a heartbeat, not a per-tick flood), so
  "the sink has been failing for five minutes" is a unit test.

### 10. Public-key signed fleet bundles

- `daemon/src/fleet.rs`, config key `api.fleet_ed25519_pubkey`, `--features tls`.
- Replaces the documented HMAC weakness (a shared secret every host holds, so any
  host could forge a bundle) with a real Ed25519 signature verified by `ring`.
  On a `tls` build with a public key configured, a bundle must carry a valid
  detached signature; the private key lives only with the fleet signer, so a host
  verifies without being able to mint. HMAC stays the zero-dependency default; a
  public key configured on a non-tls binary is stored but *not checked*, and the
  daemon logs a warning saying so. A tls-gated test proves the round trip and
  that a valid MAC without a signature is refused when a key is required. The
  shipped `.deb` builds `ufwd` **with** `--features tls` (the source build stays
  zero-dependency), so this control is active in the packaged artifact rather
  than dormant — a gap the pre-audit review caught and this branch closed.

### 11. IPv6 enforcement parity

- `tests/scenarios/ipv6_parity.rs`.
- The reference model decides v6 flows the way it decides v4 (named v6 permitted,
  unnamed v6 denied, and neither family's rule leaking into the other's
  decisions); the emitted nftables keeps the families apart (the original
  family-mixing defect, pinned); and the kernel accepts the v6 ruleset via
  `nft --check`. Real v6 *packet* enforcement is environment-gated (many
  CI/container kernels ship without IPv6), so this level is model parity plus
  loadability — and says so rather than implying a test it did not run.

## Tier 4 — the non-code part

- **Reproducible builds — done.** `build/linux/build-deb.sh` pins
  `SOURCE_DATE_EPOCH`, normalizes staged mtimes and remaps the build path out of
  the binaries; `build/linux/verify-reproducible.sh` builds twice and asserts
  identical SHA-256. Verified locally byte-identical. See
  [`../SUPPLY-CHAIN.md`](../SUPPLY-CHAIN.md).
- **Production soak / pilots — open, by nature.** 30+ days on live kernels under
  real traffic is wall-clock bound, not code bound. The *instrument* exists (the
  leak detector, `GET /metrics`, and `daemon/tests/soak.rs`); the runbook is
  [`soak_testing.md`](soak_testing.md). This is the single largest remaining gap
  and it rounds the product score down until it is left running.
- **Responsible-disclosure program.** The repo carries the policy
  ([`../../SECURITY.md`](../../SECURITY.md)); what remains is the staffed inbox
  and the track record, which are operation, not code.

## What is still open, stated plainly

Three gaps no commit in this branch closed, and none of them is pretended shut:

1. **Zero sustained runtime hours** on live kernels under real traffic. The
   dominant gap; measurable now, not yet measured.
2. **No independent audit.** Made cheaper and smaller by Tier 1, still not done.
3. **The macOS packet-layer path** (connectionless/ICMP enforcement) and the
   per-platform boot-watchdog wiring, tracked in
   [`watchdog_parity.md`](watchdog_parity.md).

The eleven code items above are built, wired and tested. The three items here are
time, people and hardware. Conflating the two is how infrastructure hurts people,
so they are kept apart.

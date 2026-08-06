# Production readiness

Where this project stands between "correct code" and "a firewall you can deploy",
and what separates the two.

This is the companion to [`threat_model.md`](threat_model.md). The threat model
asks *what can an adversary do to it*. This document asks a blunter question:
*if you installed it on a real machine tomorrow, would it be safe, and would it
even start?* The answer today is no on both counts, and the honest version of
why is worth writing down — because the codebase is strong enough that it is
easy to mistake for a product, and it is not one yet.

## The two scores

The engineering and the product are graded on different scales, and conflating
them is how infrastructure hurts people.

- **As an engineering artifact — high.** Provable cross-platform equivalence
  over enumerated equivalence classes, memory-safe Rust decoders checked
  byte-for-byte against the C they replace, differential fuzzing under
  ASan/UBSan, a formal denotational semantics with an independent conformance
  checker, evasion resistance with tests that drive each attack and its
  legitimate look-alike. The hard part that most projects never finish is
  finished, and every guarantee is backed by a test that runs the real code.

- **As a deployable product — low.** Roughly a 3 out of 10. Not because the
  code is weak, but because none of the four things below are optional for
  real deployment, and all four are open. The score is bounded by *time and
  process*, not by unsolved research — there is no open problem here, only
  work that has not been done.

The rest of this document is the four things.

## 1. Zero runtime hours — the dominant gap

Nothing here has ever run against real traffic on a real kernel for a sustained
period. Everything verified is *static*: proofs, differential fuzzing,
conformance checks. Static verification is necessary and we have a lot of it.
It is not sufficient, and it structurally cannot catch:

- **Slow leaks.** A few bytes lost per packet that only OOMs the box on day 9.
  No amount of correctness proof surfaces a leak the proof's own model does not
  account for allocating.
- **Lock contention and deadlock.** Behaviour under concurrent load that a
  single-threaded test harness never reproduces. The RCU-shaped publish on
  reload is *shaped* right; whether it starves a reader under real contention
  is a runtime fact.
- **Performance collapse.** The DPI automaton walk can be provably correct and
  still add tens of milliseconds of latency at line rate, which makes it
  unusable even though every verdict it returns is right. Correct and fast are
  independent properties, and only the first is established.
- **Kernel-version drift.** The eBPF verifier, the WFP callout ABI, and the
  Network Extension APIs behave differently across point releases. We compiled
  against a handful; there are hundreds in the field, and "the verifier
  rejected our program on 6.x" is discovered at load time, not at build time.

A firewall is always-on infrastructure. The single most important property —
*does it stay up and stay fast for 30 days under real traffic* — currently has
the value **unknown**, not *good*. For the thing sitting in your packet path,
unknown rounds down.

This is the same risk `threat_model.md` records as "No runtime hours"; it is
repeated here because it is the largest single reason the product score is what
it is, and it deserves to be stated where the product question is being asked.

**What is built:** the *instrument* to measure this now exists. The daemon
exports a Prometheus exposition at `GET /metrics` — including
`ufw_process_resident_memory_bytes`, the leak signal — and a tested leak
detector (`daemon/src/metrics.rs`) fits a trend line through RSS samples and
returns a verdict. A soak harness (`daemon/tests/soak.rs`) drives the real data
path against the loopback kernel and applies it. The full runbook, including the
production pass/fail criteria, is [`soak_testing.md`](soak_testing.md).

**What is still open:** the run itself — 30+ days on live Windows, Linux, and
macOS kernels under representative traffic. That is wall-clock and hardware
bound, not code bound, and no commit can contain it. The change here is that the
gap is now *measurable* rather than merely acknowledged: the question has an
instrument pointed at it, it just has not been left running long enough to
answer.

## 2. No independent audit

Every proof and every test in this repository was written by the same author as
the code it checks. That is a conflict of interest baked into the guarantee. A
verification suite proves the code does what its author *believes* it should —
an audit is the process that tests whether that belief was wrong in the first
place. We have a great deal of the former and zero of the latter.

Real security products bring in a third party who is paid to find the thing the
author could not see, precisely because the author cannot see it. Until that
has happened, "verified" means "self-verified", which is a weaker claim than the
volume of tests makes it look.

**What closes it:** an external security review by someone with no stake in the
result, with the parsing in ring 0 (`dpi_decoders.h`, the reassembler) as the
first target.

## 3. None of the operational scaffolding a product needs

This is where "codebase" and "product" diverge hardest. A correct engine is not
a thing a person can install, run, or recover from. Shipping means:

- **Signed installers, notarization, driver signing.** An unsigned kernel
  driver will not load on a stock Windows or macOS machine — Secure Boot and
  the macOS kext/system-extension approval flow refuse it, and on Linux
  `insmod` is rejected under Secure Boot. This is not a missing feature; it is a
  *will-not-start* gap. The signing *procedure* now exists for all three
  platforms (`build/windows/driver_signing.ps1`, `build/macos/signing.sh` +
  `notarize.sh`, and a new `build/linux/sign-module.sh` for the Secure Boot
  MOK path), plus a signed cross-platform release manifest
  (`shared/src/manifest.rs` + the `ufw-manifest` tool, tested) that proves a
  deployer received exactly the released set — see
  [`../deployment/signing.md`](../deployment/signing.md). What is **still
  missing** is the keys and the pipeline that runs it: signing needs real
  certificates in a secrets store, which cannot live here, so these are
  documented, tooled, and unit-tested procedures rather than an executed,
  key-in-hand release.
- **Crash telemetry and safe-mode recovery.** *Partly built.* The control
  plane now supervises the data path: a fail-safe watchdog
  (`daemon/src/watchdog.rs`) detects a crash-loop — repeated data-path faults
  inside a window — and responds by backing off, then stopping fast retries and
  entering a loud, defined **safe mode** rather than thrashing, on the governing
  rule that *a data-path fault must never cost an operator remote access to the
  host*. A reconnect is fail-closed: the daemon returns to `enforcing` only
  after a successful full reinstall into the reconnected module, so a freshly
  reloaded module is never presented as enforcing while its tables are empty.
  The state is exported in `ufwctl status` (`watchdog.state`, fault counts) and
  at `GET /metrics` so a headless server's monitoring can tell "up" from
  "up, but crash-looping". The ring-0 half now exists too: a **fault latch** in
  the Linux module (`kernel/linux/inc/boot_watchdog.h`, wired into the hook
  path) bounds a bug in the module's *own* data path — if the classifier
  repeatedly produces an impossible verdict, the latch trips, pulls the module
  out of the packet path, and returns a single known-safe verdict (accept by
  default, so the host stays reachable) instead of trusting a classifier that
  has demonstrably broken. A boot-command-line `ufw.bypass=1` gives an operator
  a way to boot a host straight past a broken firewall. The latch logic is
  hosted-tested (`daemon/tests/boot_watchdog_tests.rs`).

  What is **still open** here: the latch catches *soft* faults (a corrupted
  decision), not a hard kernel *oops* — a genuine panic inside the hook is the
  kernel's to handle, and no module can self-recover from it. The equivalent
  latch exists only on Linux so far; the Windows callout and macOS extension
  have no counterpart yet.
- **Field update and rollback.** The fleet code (`daemon/src/fleet.rs`) is
  well-built — HMAC-signed bundles, hash-based canaries, rate-based automatic
  rollback — but it has never pushed a bundle to a machine it did not already
  control. "Elegant in the test" and "survives a botched rollout to a thousand
  real hosts" are different maturities.
- **Docs, support, and a threat-response process.** When someone finds a bypass
  in the wild, there has to be a path from their report to a signed fix on
  every deployed host. None of that process exists.

**What closes it:** productionization work — a signing and notarization
pipeline, a *kernel-side* boot watchdog (the daemon-side supervisor and safe
mode are built), a real staged rollout against hosts outside the lab, and a
security-response process. Mostly engineering, none of it research.

## 4. The macOS path is the weakest leg

The Windows and Linux backends are the more exercised of the three; the macOS
Network Extension side is the newest and least-tested. Its Swift is not compiled
by this workspace's tests — it is pinned by `shared/tests/macos_wire_contract.rs`
and type-checked by the `macos-extension` CI job, which is weaker than a full
build and much weaker than a run. "Cross-platform" is only as strong as its
weakest platform, and macOS has not yet earned the trust the other two have
begun to.

**What closes it:** bring the macOS path to parity — full build in CI, a runtime
harness, and its share of the soak hours from gap 1.

## Why 3, and not 1, and not 6

- **Not 1**, because the hard part most projects never finish is finished and
  finished well. Provable correctness, memory-safe parsers, evasion resistance
  — the foundation a shippable product would be *built on* is unusually solid.
  A 1 is a prototype; this is a verified engine.
- **Not 6**, because none of gaps 1–3 is optional for real deployment, and all
  three are open. You cannot ship always-on kernel infrastructure that has
  never run, was never independently audited, and cannot cleanly install or
  recover from a crash. A 6 would imply "deployable with caveats"; these are not
  caveats, they are preconditions.

## The mental model

This is a finished engine with no chassis, no crash-testing, and no dealership.
The engine is excellent. You still cannot drive it home.

The reassuring half of that picture: everything missing is bounded by time and
process rather than by an unsolved problem. The thing an audit and a soak would
be *validating* is already correct. Do the soak, get the audit, build the
installer-and-recovery scaffolding, and the product score climbs fast — because
it is climbing on top of work that is already done.

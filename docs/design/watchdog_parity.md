# Watchdog parity across Linux, Windows, and macOS

The supervision story has two halves, and it is worth being exact about which
half is at parity today and which is not, because "the watchdog isn't done on
Windows" is true of one half and false of the other.

## The two halves

1. **The daemon-side supervisor** — `daemon/src/watchdog.rs`. Keeps a *running*
   host reachable when the control channel to the data path faults: it detects a
   crash-loop (repeated data-path faults in a window) and enters a defined safe
   posture instead of thrashing. It is pure Rust in the daemon crate, which is
   the same binary on all three platforms, so **this half is already at parity**
   — there is no per-OS version of it to fall behind. Its policy is unit-tested
   (`SupervisorState` ladder) independent of platform.

2. **The kernel-side fault latch** — `kernel/linux/inc/boot_watchdog.h`. Bounds
   the blast radius of a bug in the data path *itself*, below where the daemon
   can see it: after too many impossible verdicts in a window, the in-kernel
   handler stops classifying and returns a single safe verdict, sticky until an
   operator reloads. Today this is wired only into the Linux module. **This is
   the half that is not yet at parity.**

This document is about closing the second half honestly — which means being
clear that most of it is *already shared*, and the remainder is thin
per-platform wiring that needs each platform's kernel toolchain and real runtime
hours, not code that can be written and called done in this repository.

## What is already shared: the trip policy

The decision — "have I seen too many faults too fast; should I latch?" — is in
`boot_watchdog.h` as `static inline` functions (`ufw_latch_init`,
`ufw_latch_on_fault`, `ufw_latch_is_tripped`, `ufw_latch_force`,
`ufw_latch_reset`) that use **no kernel API**: no allocation, no locking, no
sleeping, only fixed-width integers and arithmetic over a bounded timestamp
ring. Off Linux (`__KERNEL__` undefined) the header supplies its own
`__u8/__u32/__u64` typedefs, so a Windows WFP callout driver or a macOS system
extension can `#include` it unmodified and get the **identical, already-tested
decision**.

That portability is not asserted on faith. Two hosted tests in
`daemon/tests/boot_watchdog_tests.rs` compile this exact header and run the
escalation ladder:

- `the_ring0_fault_latch_behaves` — the full ladder under the Linux build flags.
- `the_fault_latch_policy_is_portable_across_platforms` — the same header under
  **strict ISO C** (`-std=c11 -pedantic -Werror -DUFW_ABI_CHECK`, no GNU
  extensions), the constraints a non-Linux kernel toolchain imposes. If anyone
  adds a Linux-ism to the shared policy, this fails in CI — before it silently
  breaks parity on a platform whose kernel toolchain does not run here.

So the *policy* is done and portable. What each platform still owes is the
wiring that calls it and maps its result to that platform's verdict type.

## What Windows still owes: the WFP callout wiring

The Windows data path is a WFP callout driver (`kernel/windows/inc/callout.h`,
`driver.h`, `wfp_helpers.h`). The latch integrates at the classify path:

- **State.** One `struct ufw_fault_latch` per callout, initialized in
  `DriverEntry`/filter-registration with the deployment's `max_faults` and
  `window_ns` (the same knobs the Linux module exposes). It lives in the
  driver's device or filter context, not on the stack.
- **Fault signal.** Where the classifyFn today detects an impossible classifier
  result (a verdict outside the enum, a decode that reports corruption), call
  `ufw_latch_on_fault(&latch, KeQueryInterruptTime() * 100)` (interrupt time is
  100 ns units → ns). Guard the call under the same lock that protects the
  callout's mutable state; the latch does no locking of its own by design.
- **Safe verdict.** When `ufw_latch_on_fault` returns tripped (or
  `ufw_latch_is_tripped` is already set), the classifyFn stops inspecting and
  writes the safe verdict into `FWPS_CLASSIFY_OUT`: `UFW_LATCH_BYPASS` →
  `action = FWP_ACTION_PERMIT` (`classifyOut->rights` cleared so nothing
  downstream overrides it); `UFW_LATCH_FAIL_CLOSED` → `FWP_ACTION_BLOCK`. The
  default is BYPASS, for the same reason it is on Linux: a data-path fault must
  never cost an operator remote access.
- **Boot recovery.** A registry value or a boot-time device-parameter maps to
  `ufw_latch_force`, so an operator locked out of a box can bring the driver up
  already latched (present but out of the packet path) and reach the host to fix
  it — the Windows analogue of the Linux module's bypass command-line parameter.
- **Report + reset.** Surface `total_faults`, `trips`, and `latched` through the
  existing IOCTL status channel (`ipc_ioctl.h`); `ufw_latch_reset` runs only on
  an explicit operator re-arm or a driver reload, never on the hot path.

## What macOS still owes: the NetworkExtension wiring

The macOS data path is a Network/System Extension (`kernel/macos/NetworkExtension`,
`SystemExtension`). The integration is the same shape, against that API:

- **State.** One latch in the provider instance, initialized when the
  `NEFilterDataProvider` (or the packet provider, once connectionless
  enforcement lands — see `production_readiness.md` §4) starts.
- **Fault signal.** Where the flow/packet handler detects an impossible verdict,
  call `ufw_latch_on_fault(&latch, clock_gettime_nsec_np(CLOCK_UPTIME_RAW))`.
- **Safe verdict.** When tripped, return the safe verdict instead of inspecting:
  `UFW_LATCH_BYPASS` → `NEFilterDataVerdict.allow()`; `UFW_LATCH_FAIL_CLOSED` →
  `.drop()`. Default BYPASS, as everywhere.
- **Boot recovery + report.** A provider-configuration key maps to
  `ufw_latch_force`; the latch counters are surfaced through the extension's
  existing status path.

## The honest boundary

Everything above the "still owes" lines is a **specification against a shared,
tested policy**, not implemented driver code, and it is deliberately not faked:

- The WFP classifyFn and the NEFilterDataProvider wiring must be **compiled with
  the platform kernel toolchains** (the WDK on Windows, Xcode with a Network
  Extension entitlement on macOS) and **run on those kernels**. Neither compiles
  in this repository's CI, so writing the ~20 lines here without being able to
  build or run them would be exactly the reckless, unverifiable kernel code this
  project refuses to ship.
- Like every ring-0 path here, once wired each is subject to the Tier 0 gate in
  `production_readiness.md`: real runtime hours under representative traffic, and
  an independent audit. A latch is the component a crash-loop stresses hardest,
  so it earns trust by surviving one, not by passing a simulation.

What this repository *can* and does hold for parity — and now does — is the
shared policy, its cross-platform portability proof, and this precise wiring
contract, so that closing the gap on each platform is a bounded, well-specified
task against tested logic rather than a fresh design.

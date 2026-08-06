# Soak testing

How to measure whether the firewall stays healthy over time — the runtime
question that static verification cannot answer, and the dominant open risk in
[`production_readiness.md`](production_readiness.md).

Everything else in this project checks that a verdict is *correct*. A soak
checks something a proof structurally cannot see: that the process does not
leak, does not thrash, and does not slow down over days of real traffic. A
firewall is always-on infrastructure; "stays up and stays fast for 30 days" is
its single most important property, and it has exactly one source of evidence —
running it and watching.

This page is the runbook. It has two halves: the in-repo harness that proves the
*instrument* works, and the production soak that produces the *evidence*.

## The instrument

Two things ship in the repo so the measurement is trustworthy before anyone
relies on it.

**The metrics endpoint.** The daemon serves a Prometheus exposition at
`GET /metrics` (`daemon/src/metrics.rs`), gated by the same authorization as
`status`. It exports the counters a soak watches — traffic, policy reloads, log
back-pressure, watchdog faults — and, on Linux, the one that matters most:

```
ufw_process_resident_memory_bytes   # the leak signal
```

**The leak detector.** `ResourceSampler` records `(time, RSS)` and fits a
least-squares line through the samples, turning "memory crept up" into a slope
with a verdict (`stable` / `growing` / `insufficient`). Its maths is unit-tested
in `daemon/src/metrics.rs` — a flat run reads stable, a rising run reads growing,
too short a run refuses to conclude — so the instrument itself is checked, not
assumed.

## The in-repo harness

`daemon/tests/soak.rs` drives the real data path — an actual `KernelChannel`
talking to the loopback mock, installing policies and signatures and pumping
events — while sampling RSS and applying the detector.

```sh
# Always runs: a short fixed churn proving the harness drives real code and the
# sampler collects points. Part of `cargo test`.
cargo test -p ufw-daemon --test soak soak_smoke

# The real thing, opt-in. Run it for as long as you can spare:
UFW_SOAK_SECS=1800 cargo test --release -p ufw-daemon --test soak -- --ignored
```

The harness warms up to steady state before measuring — RSS climbs once as the
allocator acquires arenas it reuses but never returns, which is a step, not a
leak — and it declines to reach a verdict on a span under 30 seconds, because
extrapolating a few seconds to an hourly rate turns a single page into a
phantom trend. **This is a smoke test of the code paths, not a substitute for
the production soak.** It exercises userspace churn against a mock kernel; it
does not run the kernel module, real traffic, or real time.

## The production soak — where the evidence comes from

This is the part no commit can contain. It is wall-clock and hardware bound, and
it is what actually moves the deployment score.

### Setup

1. Deploy the daemon and the platform's kernel module on a representative host
   (ideally one of each: Linux, Windows, macOS).
2. Enable the network API on loopback (or behind a scraper with a token) so
   `/metrics` is reachable.
3. Point a Prometheus (or any scraper) at `/metrics`, scraping every 15s.
4. Drive representative traffic — mirrored production, a replay, or a synthetic
   generator — not an idle host. An idle firewall soaks nothing.
5. Run for **at least 30 days**. Leaks and fragmentation that matter are often
   single-digit MB/day; a week can look clean and still be leaking.

### What to watch, and the pass criteria

| Series | Healthy | Fails the soak |
|---|---|---|
| `ufw_process_resident_memory_bytes` | Flat after warmup; slope → 0 over the run | Sustained upward slope (a leak) |
| `ufw_watchdog_safe_mode_entries_total` | `0` | Any increase (the data path crash-looped) |
| `ufw_watchdog_faults_total` | Flat, or rare isolated bumps | Climbing (repeated data-path loss) |
| `ufw_log_events_dropped_total` | Flat | Climbing (the log pipeline is falling behind) |
| `ufw_kernel_connected` | `1` | Any dip (enforcement gaps) |
| latency (measured out of band) | p99 stable | p99 drifting up (throughput decay) |

The memory series is the one that needs the full 30 days: fit a line through the
whole run, not a day. A slope that rounds to zero over a month is the pass; a
slope you can see with a ruler is the fail, and the absolute growth over 30 days
is the number to report.

### If it fails

A `growing` RSS trend or a non-zero `safe_mode_entries` is a finding, not a
tuning problem. Capture the `/metrics` history, the daemon logs around any
watchdog transition, and — for a leak — a heap profile of the daemon under the
same load, then fix the code. The soak is re-run from the start after a fix,
because a leak detector's clock resets when the binary changes.

## Status

The instrument and the harness are built and tested here. The 30-day run on live
kernels is not, and cannot be, done in this repository — it needs real hardware
and real time. It remains the single largest item between this codebase and a
deployable product, and it is now *measurable* rather than merely *acknowledged*:
the difference between "we should soak this" and "here is exactly how, here is
what to watch, and here is the instrument that reads the answer."

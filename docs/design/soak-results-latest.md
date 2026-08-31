# Soak results (latest)

Two soaks are recorded here: the dashboard/nft smoke driven by `scripts/soak.sh`,
and the data-path leak soak driven by `daemon/tests/soak.rs` (the one that fits a
trend line through resident memory — the measurement static verification cannot
do).

## Data-path leak soak (`daemon/tests/soak.rs`, release)

- command: `UFW_SOAK_SECS=360 cargo test --release -p ufw-daemon --test soak -- --ignored`
- churn: **2,604,179** data-path iterations (policy install + signature install +
  event pump against the loopback mock kernel)
- samples: **9,806** RSS samples over a **270 s** steady-state window (after warm-up)
- RSS: 3,596,288 → 3,760,128 bytes (peak 3,760,128) — **~164 KB** total growth
- trend: slope **592 B/s ≈ 2.03 MB/hour**
- **verdict: `stable`** — the leak detector's slope stayed under its
  fail threshold; the run passed.

**How to read this honestly.** This is a **6-minute** run — a smoke, not the
production soak. A positive slope of ~2 MB/hour measured over minutes is
dominated by allocator and arena warm-up and is *not yet distinguishable* from a
slow leak; that separation is exactly what a longer window buys, which is why the
30-day run is the real test and this number does not stand in for it. What the
run does establish: the real data-path code churns two-and-a-half million times
without panicking, the sampler and the leak detector work end to end against real
allocation, and nothing blew the threshold in six minutes.

## Dashboard / nft smoke (`scripts/soak.sh`)

- policy: `policies/base/monitor_baseline.yaml`
- window: 24 s, sampled every 6 s (4 samples)
- benign connections issued: 139,146
- nft packets counted (final): 4,498,512
- dashboard RSS: min 2,936 KB, max 2,936 KB, drift 0 KB
- crashes: 0; ruleset stayed loaded: yes
- **verdict: PASS**

---

_The smoke scale here is not the target. A 30-day fleet soak under production
traffic — a Prometheus monitor on `ufw_process_resident_memory_bytes` for the
full window — is the real bar, tracked in
[`soak_testing.md`](soak_testing.md), and is scheduled to accumulate
automatically via `.github/workflows/soak.yml`. It remains the dominant open
gap in [`production_readiness.md`](production_readiness.md)._

# Detection efficacy

Turns "we have detection" into measured numbers. The harness
(`daemon/tests/detection_efficacy.rs`) runs a **labeled corpus** through the two
callable detectors and prints a confusion matrix. It runs in CI (`cargo test`)
so the numbers can't silently regress.

```
cargo test -p ufw-daemon --test detection_efficacy -- --nocapture
```

## Latest run

| Detector | Catch-rate | False positives | Corpus |
| --- | --- | --- | --- |
| **Egress anomaly** (new-destination-after-baseline) | **100%** (25/25) | **0%** (0/30) | 25 post-baseline novel destinations; 30 benign (baseline revisits + still-learning) |
| **Signature pre-filter** (`scan_content`) | **100% recall** (39/39) | reported, not asserted | 39 payloads carrying real shipped patterns; 6 benign |

The signature pre-filter flagged **6/6** benign payloads as *candidates* — see the
scope note below; this is the pre-filter working as designed, not a detector
false positive.

## Honest scope — read this before quoting a number

- **These measure correctness + regression, not "catches unknown attacks."** The
  anomaly corpus is built to the detector's documented model; the signature
  corpus is built from the engine's **own shipped patterns**. A real efficacy
  figure needs fresh, independent adversary captures (a labeled pcap corpus from
  the wild) — a larger effort this harness does not claim to be.
- **The signature engine has two stages.** `scan_content` is a fast
  Aho-Corasick **pre-filter** over every pattern; a hit only makes a flow a
  *candidate*. The precise verdict comes from evaluating the matched signature's
  full condition tree against its field constraints (protocol, `http.uri`,
  `ja3`, entropy, …). This harness measures the **pre-filter's recall** — the
  property that matters for it (never drop a real candidate) — and deliberately
  does **not** treat a pre-filter hit as a detection. Benign HTTP shares
  byte-substrings with attack patterns, so the pre-filter over-matches on
  purpose; precision is the second stage's job and is out of scope here.
- The **egress-anomaly** number is a genuine end-to-end detector result: real
  detector, labeled inputs, real confusion matrix.

## What would raise the ceiling

1. A labeled real-traffic pcap corpus (benign + known-malicious families) driven
   through the full pipeline — the honest "we catch X% with Y% false positives"
   figure.
2. Extending this harness to the **full** signature evaluation (condition tree +
   field context), so signature *precision* is measured, not just pre-filter
   recall.
3. Per-family breakdowns (SQLi/XSS/C2-beacon/port-knock/JA3) rather than an
   aggregate.

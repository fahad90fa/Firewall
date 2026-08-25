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
| **WAF full pipeline** (`WafEngine::inspect`) | **89.7%** (26/29) | **0%** (0/13) | 29 real web attacks across 10 classes incl. 10 evasion variants (all caught); 13 benign incl. deliberate look-alikes |
| **Egress anomaly** (new-destination-after-baseline) | **100%** (25/25) | **0%** (0/30) | 25 post-baseline novel destinations; 30 benign (baseline revisits + still-learning) |
| **Signature pre-filter** (`scan_content`) | **100% recall** (39/39) | reported, not asserted | 39 payloads carrying real shipped patterns; 6 benign |

The **WAF full-pipeline** number (`daemon/tests/waf_efficacy.rs`) is the honest
end-to-end web number: real HTTP attack requests driven through fact parsing +
percent-decode normalisation + full condition-tree evaluation of every shipped
signature. The corpus is authored **independently of the signature strings** —
canonical forms plus evasion variants (encoding, case, comments) — so a hit means
the WAF *generalised*, not that a fixed string was echoed back. The 3 misses are
the deliberately-FP-prone forms (a bare `'--` comment, a boolean `'1'='1`, a
backtick command sub) left un-generalised to hold the false-positive rate at 0%.
Building this harness surfaced real coverage gaps that were then closed with three
new structural signatures (inline `onload=` XSS, `{{…}}` template injection,
encoded-CRLF header injection).

The signature pre-filter flagged **6/6** benign payloads as *candidates* — see the
scope note below; this is the pre-filter working as designed, not a detector
false positive.

## Behavioral detectors (new defence layers)

Four behavioral detectors ship alongside the efficacy harnesses, each with its
own unit tests that double as a small labeled corpus. The first three are
live-wired into the logging pipeline (they run whenever anomaly detection is on);
the DNS one is fed by the protocol decoder's `dns.qname`.

- **Port-scan / network-sweep** (`daemon/src/logging/portscan.rs`) — one source
  touching many ports on a host, or one port across many hosts, inside a sliding
  window. Tests: vertical scan, horizontal sweep, ordinary traffic (no fire),
  slow-scan-below-window, alert throttling, non-flow ignored.
- **C2 beaconing** (`daemon/src/logging/beacon.rs`) — keeps the inter-arrival
  cadence per (identity, destination) and fires when outbound callbacks are
  numerous AND regular (low coefficient of variation, default ≤ 0.12 over ≥ 8
  samples) in a plausible interval band. Tests: a steady 60s cadence fires;
  jittery human traffic, too-few samples, and sub-second chatter do not. Honest
  scope: legitimately periodic clients (NTP, update pollers) are also regular, so
  this is a triage alert, not a block.
- **Credential brute-force** (`daemon/src/logging/bruteforce.rs`) — counts
  connections per (source, service, port) over a window, only on auth ports
  (SSH/RDP/FTP/SMB/DB/mail/LDAP/VNC), and alerts on a stuffing rate. Tests: SSH
  burst fires; non-auth ports, a few logins, a slow trickle, and distinct
  sources (no pooling) do not.
- **DNS tunneling / exfiltration** (`daemon/src/logging/dns_exfil.rs`) — scores
  query names for a single encoded blob or many chunked high-entropy sub-domains
  under one parent. Tests show it fires on both tunnel shapes and stays quiet on
  ordinary look-ups, CDN shards, and long-but-readable names.

## Honest scope — read this before quoting a number

- **These measure correctness + regression, not "catches unknown attacks."** The
  anomaly corpus is built to the detector's documented model; the signature
  corpus is built from the engine's **own shipped patterns**. A real efficacy
  figure needs fresh, independent adversary captures (a labeled pcap corpus from
  the wild). The **pcap harness for that now ships** — `daemon/tests/pcap_efficacy.rs`
  ingests real `.pcap` captures (Ethernet → IPv4 → TCP reassembly → HTTP → the
  live `WafEngine`) and prints a confusion matrix; point it at a labeled corpus
  with `UFW_PCAP_DIR=/path` (files named `mal_*.pcap` / `ben_*.pcap`, e.g. the
  web-attack captures from CIC-IDS2017 or malware-traffic-analysis.net). Its CI
  self-test proves the pcap→WAF pipeline works on real wire bytes; the wild
  number is one `UFW_PCAP_DIR` run away, needing only the dataset.
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
   figure. **The harness for this now exists** (`daemon/tests/pcap_efficacy.rs`,
   `UFW_PCAP_DIR`); what remains is dropping in a real labeled dataset.
2. Extending this harness to the **full** signature evaluation (condition tree +
   field context), so signature *precision* is measured, not just pre-filter
   recall.
3. Per-family breakdowns (SQLi/XSS/C2-beacon/port-knock/JA3) rather than an
   aggregate.

# Advanced detection & fleet items — where each one lives, and its honest boundary

This document accounts for a specific set of nine capabilities requested as the
"god-level" tier: an IDS/IPS signature engine, differential fuzzing, port
knocking, beaconing detection, JA3/JA4 fingerprinting, identity-aware eBPF,
signed fleet distribution, RBAC + mTLS, and flow-pipeline behavioural analysis.

It exists to be precise about two things at once, because a security roadmap
that blurs them is worse than useless:

1. **What is actually built** — named files, with tests, that you can read and
   run today.
2. **Where the honest boundary is** — the parts that need a vetted crypto
   library, a specific kernel configuration, live-kernel runtime hours, or an
   independent audit before they should be trusted in production. These are
   *flagged, never faked green*: nothing below claims a property it cannot back.

It is a companion to [`protection_roadmap.md`](protection_roadmap.md) (what
layer this is part of) and [`production_readiness.md`](production_readiness.md)
(whether the engine is deployable yet). Tier 0 of the roadmap still governs
everything here: these are host-layer capabilities, and none of them substitutes
for the runtime hours and third-party audit that Tier 0 names.

## The nine items

### 1. IDS/IPS signature engine — built

- **Kernel/daemon DPI signatures:** `daemon/src/signatures.rs` compiles a
  matchable field set (`sig-rules/`) that the kernel evaluates per packet. Field
  ids are derived by name (`ufw_shared::hash::derive_signature_id`) so the daemon
  and kernel agree without a shared numbering table.
- **Console IDS:** `cli/src/bin/ufw-nft/dashboard/ids.rs` is a Suricata-subset
  engine over the console's own event stream — it parses `*.rules` from
  `/etc/unified-firewall/ids-rules/`, matches on header fields (proto, dport,
  flags), and surfaces hits on the dashboard. Unit-tested (`parse_rule`,
  `evaluate`, field matching).
- **Honest scope:** the console engine matches on packet-header fields the log
  exposes, not on reassembled payload — payload/content signatures are the
  kernel DPI's job, above. `ids.rs` says so in its module doc.

### 2. Differential fuzzing — built, and in CI

- `kernel/linux/rust/ufw_kcore/tests/differential.rs` runs the Rust port of the
  ring-0 decoders against the C implementation (`fuzz/decoders.c`) on the same
  inputs and asserts identical output — the property that lets the Rust port be
  trusted as an oracle for the C. It replays the `fuzz/corpus*` files and a
  configurable random budget (`UFW_DIFF_ITERS`, `UFW_DIFF_CORPUS_ALL`).
- **CI:** `.github/workflows/fuzz.yml` runs a nightly `differential` job at a
  raised iteration count.
- **Honest boundary:** differential testing proves the two implementations
  *agree*, not that either is *correct* against a spec. It is the right tool for
  a rewrite-equivalence claim; it is not a substitute for the third-party audit
  of the parsers that Tier 0 calls for.

### 3. Port knocking — built, verified on real nft

- `cli/src/bin/ufw-nft/knock.rs` generates the nftables stage sets and
  advance/drop rules for a knock sequence; `cmd_knock` wires
  `knock <port> <k1> <k2>… | off | status`. Validated against a live `nft`.
- **Honest boundary, stated in-module:** knock gating only protects a port the
  *main policy does not already drop* — it opens a hole on a correct sequence, so
  the base policy must leave the protected port to the knock chain. Port knocking
  is obscurity that raises cost, not authentication; it is documented as such.

### 4. Beaconing detection — built

- `cli/src/bin/ufw-nft/dashboard/beacon.rs` groups egress events by destination
  and flags a low coefficient of variation over enough samples — the rhythm of a
  C2 callback. Surfaced on the Threats page. Unit-tested for detection,
  rejection of irregular/inbound/too-few-sample traffic.
- **Honest scope:** it sees the egress events the firewall logged (denied or
  alerted). Beaconing to a destination the policy *allows* needs the daemon's
  egress-anomaly flow feed (item 9); the maths is the detector, wiring it to
  that feed is the daemon's job, and the module says so.

### 5. JA3 / JA4 TLS fingerprinting — JA4 built (with a documented hash variant)

- The kernel computes a **JA4-structured** client fingerprint
  (`UFW_FIELD_TLS_JA4`, `kernel/linux/inc/dpi_decoders.h`;
  `kernel/linux/rust/ufw_kcore/src/fields.rs::TLS_JA4`), and `tls.ja4` is a
  matchable signature field (`daemon/src/signatures.rs`).
- **The honest variance, already documented in `dpi_decoders.h`:** the structure
  is JA4's, but the component hash is FNV-1a, **not** JA4's truncated SHA-256 —
  and deliberately not JA3's MD5. So the in-kernel value is stable and matchable
  but is not byte-identical to a canonical JA4 hash. To bridge that, the
  component string travels in the log event, so a SIEM can compute the canonical
  JA3 **or** JA4 hash downstream. Canonical in-kernel JA4 (truncated SHA-256)
  is a `tls`-feature change, for the same reason as everything in the boundary
  section: real crypto belongs in a vetted library.

### 6. Identity-aware eBPF — built (kernel C), with a real deployment constraint

- `kernel/linux/ebpf/identity_lsm.c` captures process identity at
  `security_socket_connect` via `bpf_lsm`, in the calling task's own context,
  keyed by socket cookie — removing the pid-race, TTL, and deadline of the
  netlink round-trip path. The daemon still resolves *trust* (signature
  verification is not a BPF program's job); the LSM records *which* executable.
- **Honest boundary, stated in the program header:** it requires
  `CONFIG_BPF_LSM`, `CONFIG_DEBUG_INFO_BTF`, and `lsm=…,bpf` on the kernel
  command line. It is therefore an **addition**, not a replacement — the netlink
  `identity.c` path keeps working and the daemon reports which path is live. Like
  all ring-0 code here, it is subject to the Tier 0 runtime-hours and audit gate.

### 7. Signed fleet distribution — built, at two layers

- **Policy bundles:** `daemon/src/fleet.rs` — HMAC-SHA256-signed bundles with a
  length-prefixed signing input, replay protection (monotonic revision), stable
  canary membership, and rate-based automatic rollback. Extensively unit-tested.
- **Release manifests:** `shared/src/manifest.rs` — a canonical, HMAC-signed
  manifest of shipped artifacts (name, size, SHA-256) so a substituted file is
  caught, tested against tamper and length-extension.
- **Console fleet summaries:** `cli/src/bin/ufw-nft/dashboard/fleet.rs` now
  authenticates each host's published summary with HMAC-SHA256 when
  `/etc/unified-firewall/fleet-key` is present; a summary that fails is marked
  `tampered` and excluded from the roll-up. Unit-tested including tamper
  detection against the exact bytes the publisher writes.
- **Honest boundary, stated identically in all three:** a **shared HMAC key**
  authenticates "a fleet member produced this", not *which* member — any
  key-holder can forge any other's. Per-host **public-key** identity (Ed25519)
  needs a vetted signature implementation and belongs behind the `tls` feature,
  not a hand-rolled one. `daemon/src/fleet.rs` names `Verifier` as the exact
  place to add it, and the bundle format already carries a field for it.

### 8. RBAC + mTLS — RBAC built; mTLS flagged as the transport it needs

- **RBAC:** `cli/src/bin/ufw-nft/dashboard/rbac.rs` — three roles (viewer,
  responder, admin) and a permission table gating the console's mutating actions
  (`contain`/`release` → Contain, `autoresponse` → Configure, `pcap` → Capture).
  A caller's role comes from an optional `Authorization: Bearer <token>` resolved
  against `/etc/unified-firewall/console-auth.json`, else from loopback status
  (default admin), else viewer — preserving the previous loopback-only behaviour
  exactly. `GET /api/whoami` reports the caller's role and capability map so the
  UI can disable actions it cannot use. The role/permission logic is pure and
  unit-tested.
- **mTLS — the flagged part, stated in `rbac.rs`:** authenticating a
  *non-loopback* caller by client certificate, so a role binds to a network
  identity, needs a **real TLS stack** (the `tls` feature's rustls), not a
  hand-rolled one. Until then the console is reached over loopback or an SSH
  tunnel and relies on tokens. The authorization layer is transport-agnostic and
  correct the moment a real mTLS transport feeds it an authenticated identity —
  which is the whole point of separating the two.

### 9. Flow-pipeline behavioural analysis — built, two complementary detectors

- **Beaconing** (item 4) is the timing-regularity detector.
- **Egress-baseline anomaly** (`daemon/src/logging/anomaly.rs`) is its twin over
  *allowed* traffic: it alerts the first time an established application identity
  reaches a never-before-seen external destination — the shape of exfiltration,
  invisible to signatures. Learning window and minimum baseline prevent boot-time
  noise; memory is bounded on both axes; on by default.
- **Honest boundary:** these are unsupervised heuristics tuned to low false
  positives, not a trained classifier. They flag shapes for a human or a SIEM to
  judge; they do not adjudicate intent, and they do not de-anonymise a person
  from an address — out of scope by policy, not by omission.

## The review-gated boundaries, in one place

Four boundaries recur above. They are collected here so the gate is a single,
auditable list rather than a footnote repeated in five modules:

| Boundary | What is built today | What crosses the boundary, and what it needs |
| --- | --- | --- |
| **Non-loopback console identity (mTLS)** | RBAC roles + bearer tokens over loopback/tunnel | Client-certificate auth binding a role to a network identity — needs the `tls` feature's rustls; the RBAC layer is already transport-agnostic |
| **Per-host fleet identity** | HMAC-SHA256 over bundles, manifests, and console summaries (shared key) | Ed25519 per-host signatures so one member cannot forge another — needs a vetted signature impl behind `tls`; `Verifier` is the insertion point |
| **Canonical in-kernel JA4** | JA4-structured fingerprint, FNV-1a components, canonical hash computable downstream from logged components | Truncated-SHA-256 JA4 in-kernel — real crypto belongs in a vetted library, not ring 0 |
| **Ring-0 / eBPF trust** | Differential-tested decoders; `bpf_lsm` identity capture | The Tier 0 gate: 30+ days of live-kernel runtime hours and an independent audit of the parsers — closed by *running and auditing*, not by a commit |

The rule these share: where correctness depends on cryptography or on the
kernel behaving as assumed under real traffic, the code is written to be correct
*and* is explicit that the assurance is not yet earned — a vetted library not yet
wired, or runtime hours not yet run. That honesty is the feature. A firewall
that overstates its own assurance is more dangerous than one that states its
limits, because someone deploys the first one believing the overstatement.

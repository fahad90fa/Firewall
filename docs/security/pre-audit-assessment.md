# Pre-audit self-assessment

The point of an external audit is to find what the authors could not see. That
value is *higher*, not lower, when the authors hand over an honest account of
what they already looked for and found — an auditor who does not have to
re-discover the known issues spends the engagement on the unknown ones. This is
that account.

It is a **self**-assessment. It is explicitly not a substitute for the
independent review described in [`audit-brief.md`](audit-brief.md) and
[`audit-rfp.md`](audit-rfp.md); it is the baseline that review should start from.

## 1. Findings we found ourselves, and fixed

A full internal audit pass over the codebase produced fifteen findings across
four severities. All fifteen are fixed, each with a regression test so the class
cannot silently return. Summarised for a reviewer who wants to confirm the fixes
rather than re-find the bugs:

| # | Sev | Finding | Fix |
| --- | --- | --- | --- |
| 1 | **CRIT** | Unauth console crash: `percent_decode` sliced a `&str` mid-codepoint (fatal under `panic=abort`) | byte-wise decode that cannot panic; regression test + it is now fuzzed |
| 2 | **HIGH** | `allow-inspect` lowered to a *terminal* nft `accept`, skipping deeper denies on the module-off path — a policy bypass | lowers to a comment (fail-closed); now pinned by a **real-packet** conformance test |
| 3 | **HIGH** | Per-source detector state was unbounded; `expire()` unwired | bounded caps + `expire()` wired on the idle tick |
| 4/9 | HIGH/MED | Kernel UDP length / transport-header / prefix reads not fully bounded | bounds added; differential-fuzzed against the Rust twin |
| 5 | MED | DNS-exfil detector advertised but not wired into the pipeline | wired (or the claim removed); covered by the every-layer test |
| 6 | MED | Anomaly alert carried a zero timestamp | real event timestamp |
| 7 | MED | IPv4-mapped IPv6 not canonicalized → loopback/LAN misclassified as public | canonicalize before classification; unit-tested |
| 8 | MED | Source-port match silently accepted for portless protocols | semantic lint rejects it |
| 10 | MED | Length-prefix truncation on wire encoders | clamped; covered by the wire-protocol fuzz |
| 11–15 | LOW | rate-limiter race, non-constant-time token compare, output escaping, an eBPF count, kernel privileged over-reads | each fixed; see the commit history |

The two that matter most to an auditor — #1 (the unauth crash) and #2 (the
policy bypass) — are also the two whose *class* is now closed by new test
infrastructure: the console HTTP parser is fuzzed, and the emitted nftables is
loaded into a real kernel and hit with real packets.

## 2. Internal review of the production-hardening branch

The eleven-item hardening work (see [`../design/production-hardening.md`](../design/production-hardening.md))
touches crypto verification (Ed25519 fleet signatures), a privileged subprocess
(the fail-closed `nft` barrier), a hash-chained audit log, and wire-format
parsing (the `sig_ed25519` field). Because those are exactly the areas where a
mistake is a real vulnerability, the branch was put through an adversarial
internal security review before this document was written, with attention to:

- whether `fleet::Verifier::accept` can accept a bundle with a **bad or absent
  Ed25519 signature** when a public key is configured (the whole point of the
  feature);
- whether any **untrusted input can influence the emitted fail-closed ruleset**
  (an injection that opens a hole while claiming to close one);
- whether the **audit-log verifier** uses a constant-time compare and actually
  detects every tamper shape;
- whether the wire `sig_ed25519` **hex parse** is safe.

**Result.** The adversarial review found **no high-confidence, exploitable
vulnerability** newly introduced by the branch. Each sensitive area was confirmed
to fail closed:

- `fleet::Verifier::accept` enforces **both** the HMAC *and* the Ed25519
  signature when a public key is configured; an absent (empty) signature is
  explicitly rejected — there is no "empty means skip" path — and `ring` rejects
  a wrong-length key or signature, so every malformed/forged case is refused.
- the wire `sig_ed25519` is parsed with `unhex` (rejects odd length / non-hex,
  returns an error, never panics or indexes unchecked); length is enforced by
  `ring` at verify time.
- the fail-closed barrier hardcodes `policy drop` on both hooks and interpolates
  only a `const` table name and a `u16` decimal port set — **no untrusted input
  reaches the nft text**, and there is no code path that emits an allow-all.
- the audit-log verifier recomputes the digest and compares with the tree's
  genuine constant-time `constant_time_eq`, and detects edit / reorder / insert /
  middle-delete / sequence-gap; `open` refuses to append onto a tampered file.

Two **below-threshold observations** were surfaced — neither an exploitable
vulnerability — and **both were then fixed in this branch**, which is the point
of running the review:

1. *Insecure temp file (low).* The barrier wrote its ruleset to a predictable
   `/tmp` path before `nft -f` (a symlink/TOCTOU surface, already mitigated by
   `PrivateTmp=yes` on every unit). Fixed by piping the ruleset to `nft -f -`
   over **stdin** — the filesystem is no longer touched.
2. *Dormant control (medium, as a product gap).* The shipped `.deb` built `ufwd`
   *without* `--features tls`, so the Ed25519 fleet check was compiled out of the
   packaged daemon — it would store a configured public key but never verify a
   signature (the daemon did warn at runtime). Fixed by building the packaged
   `ufwd` with `--features tls` so the control is **active in the shipped
   artifact**, not just in a source build.

## 3. Dependency posture

- **The default build has zero third-party crates.** Nothing outside this
  workspace executes in the default binaries — the parsers, crypto primitives,
  and HTTP server are all hand-written and tested against published vectors.
- **The only external crates** (`ring`, `rustls`, `rustls-pemfile` and their
  transitive tree — `getrandom`, `libc`, `subtle`, `untrusted`, `zeroize`, …)
  are pulled **only** by the opt-in `tls` feature. The pinned versions
  (`ring 0.17.x`, `rustls 0.23.x`) are current and carry no known RustSec
  advisory as of this document's date.
- Continuous checking is wired: `.github/workflows/dependency-audit.yml` runs
  `cargo audit` against the committed lockfile weekly and on any lockfile change,
  so a newly-disclosed advisory becomes a failing check rather than a surprise.

## 4. What this assessment does not cover

The same three gaps the readiness docs keep open, restated so this document does
not imply more than it is:

1. **No sustained runtime hours** — a leak or a lock-contention bug that only
   appears under days of real traffic is not visible to any static review,
   internal or external.
2. **This is self-review.** The author reviewing the author finds what the
   author can see. That is the conflict of interest an external audit exists to
   break, and nothing here removes the need for it.
3. **Ring-0 parsing** (`dpi_decoders.h`, the reassembler) is the first target
   named for the external review, precisely because memory-safety in C is where
   an internal reviewer's confidence should be lowest.

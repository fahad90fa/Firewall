# Audit brief

A single entry point for an external security reviewer. It says what to review,
where it lives, what we already claim (and how we measured it), and what we do
**not** claim. It is deliberately short; every row links to the primary source.

This document does not assert the product is secure. It asserts that the scope
is written down honestly, so a review can start from facts instead of marketing.

## 1. What this software actually enforces

Read [`SECURITY.md`](../../SECURITY.md) first — the "What this software actually
enforces" table is the ground truth. In one line:

- **The L3/L4 packet layer enforces today** through one `nftables` table
  (`inet ufw`), compiled from the policy. No kernel module required.
- **Identity-aware / DPI enforcement is available but off by default**, via the
  shipped DKMS kernel module (`ufw.ko`). It adds ring-0 surface and is **not
  externally audited**.
- **Detection** (IDS/IPS signatures, egress-anomaly, beaconing, JA3/JA4) detects
  and logs; acting on a detection is a separate, opt-in response.
- **Licensing** is a node-locked deterrent, not DRM.

## 2. Highest-value review targets, in order

The single highest-value review is the **ring-0 code and the nftables
emission** — a bug there is a bug in the thing that is supposed to protect the
host. Suggested order:

| # | Target | Where | Why it's first |
| --- | --- | --- | --- |
| 1 | nftables emission — can a policy compile to a ruleset that allows what it names as denied, or vice-versa? | `cli/` packet compiler; tests in `cli/tests/` | This is the layer that actually enforces today. A miscompile is a silent policy bypass. |
| 2 | Ring-0 hostile-byte parsers (packet decoders, stream reassembly, DPI automaton) | `kernel/linux/src/`, `kernel/linux/inc/`; Rust reimpl in `kernel/linux/rust/ufw_kcore` | Attacker-controlled input in ring 0. Memory-safety bugs here are remote kernel compromise. |
| 3 | Daemon request-path / IPC and the console's one mutating action | `daemon/`, `cli/src/bin/ufw-nft/dashboard/` | Local privilege boundary; the "contain" action mutates nftables. |
| 4 | Licensing client node-lock + Ed25519 verification + hardware binding | `cli/src/bin/ufw-nft/license.rs`; backend in `website/supabase/functions/` | Trust decision made on the client; verify the deterrent can't be trivially forged into enforcement-on, and that the paid value is server-gated (see below), not just a client boolean. |

## 3. What we already claim, and how we measured it

Every claim below is from our own tests, not a third party. The point of listing
them is that each is reproducible and each has a documented scope.

| Claim | Evidence | Honest scope |
| --- | --- | --- |
| Ring-0 parsers are fuzzed | `.github/workflows/fuzz.yml` — sanitizer-instrumented, coverage-guided fuzzing in CI + nightly | Fuzzing finds crashes; it is not a proof of correctness. |
| A memory-safe core exists and is **gated** to match the C byte-for-byte | `kernel/linux/rust/ufw_kcore`; the named `differential` CI job (`UFW_DIFF_REQUIRE=1`, full corpus + 40k mutations) | The Rust core (`no_std`, no `unsafe`) is the reference; the C is what ships in `ufw.ko`. The gate can't pass vacuously. In the **default build the C never sees hostile bytes** — the module is opt-in. |
| Detection efficacy is a measured number, not a slogan | `daemon/tests/detection_efficacy.rs`, [`detection-efficacy.md`](../design/detection-efficacy.md) | Measures **correctness + regression** on a labeled corpus, **not** novel-attack coverage. The signature figure is **pre-filter recall**, not end-to-end precision. Read the scope note before quoting a number. |
| The live path survives sustained real traffic | `scripts/soak.sh`, [`soak-results-latest.md`](../design/soak-results-latest.md) | The published run is smoke-scale (seconds), not a 7-day soak; the harness runs the full duration when you give it one. |
| Every change is gated | `.github/workflows/ci.yml` — `cargo test`, `clippy -D warnings`, `fmt`, `--features tls` build, SBOM | Standard hygiene, not a security proof. |
| Releases can be cryptographically verified | signed apt repo — `build/linux/sign-release.sh`, [`apt-repo.md`](../apt-repo.md) | Proves *provenance* (the bytes are the key-holder's), not *behaviour*. |

## 4. What we do NOT claim

- **No third-party audit has been performed.** This brief is the scope for one,
  not a substitute for one.
- **We do not claim to catch unknown/novel attacks at a measured rate.** The
  detection numbers are correctness-and-regression figures on a corpus built to
  the detectors' own models. A real-world efficacy figure needs an independent
  labeled pcap corpus — see the "what would raise the ceiling" section of the
  detection doc.
- **The kernel module is not claimed to be memory-safe as shipped.** The C is
  fuzzed and differential-tested against a Rust reference; that lowers risk, it
  does not eliminate it. If you do not need identity/DPI enforcement, leave the
  module off and the ring-0 surface disappears.
- **Client-side licensing is a deterrent, not DRM.** A determined customer with
  root on their own machine can patch the binary and bypass the local gate; the
  node-lock, Ed25519 verification, and hardware binding raise the effort, they do
  not make it impossible. The **durable** control is that the recurring value
  (fleet plane, threat-intel feed, managed telemetry) is **server-gated** behind
  the license — a cracked client forfeits it. See `docs/security/licensing-keys.md`
  ("server-gated value") and `website/LICENSING.md`.

## 5. Trust boundaries and adversaries

See [`threat-model.md`](threat-model.md) (assets, trust boundaries, adversaries
A1–A6, explicit non-goals, fail-safe posture) and
[`attack-surface.md`](attack-surface.md) (every listening socket, privileged
path, and file the software trusts, ranked by risk).

## 6. Secrets and provenance (what an auditor should confirm is absent)

- The **licensing signing secret** (`LICENSE_SIGNING_SECRET` /
  `LICENSE_ED25519_PKCS8`) and the **Supabase service-role key** are
  server-side only. They must never appear in the client bundle, the `.deb`, or
  the repository. The client ships **only** the Ed25519 **public** key and the
  Supabase **anon** key (both public by design).
- The signed apt repo carries an SBOM (`sbom.cdx.json`) so the dependency set is
  auditable alongside the package.

## 7. How to reproduce the claims

```sh
cargo test --workspace                                   # unit + integration
cargo test -p ufw-daemon --test detection_efficacy -- --nocapture   # detection numbers
cargo clippy --workspace --all-targets -- -D warnings    # lint gate
cargo build -p ufw-cli --features tls                    # Ed25519 verify + console mTLS
sudo sh scripts/soak.sh 604800 policies/base/monitor_baseline.yaml 300   # full soak
```

Nothing here needs network access except a first `--features tls` build (which
pulls the pinned `rustls`/`ring` from crates.io); the default build is fully
offline.

# Security policy

## Reporting a vulnerability

**Do not open a public issue for a security bug.** Report it privately through
one of:

- a **GitHub security advisory** — <https://github.com/fahad90fa/Firewall/security/advisories/new>
  (gives us a private fork to fix in), or
- **email** to **security@unifiedfirewall.dev**.

Include:

- the component (packet compiler, kernel module, daemon, dashboard, licensing),
- affected version (`ufw-nft --version` / package version),
- a description and, if possible, a reproducer (a policy, a packet capture, or a
  crash input).

We aim to acknowledge within **72 hours** and to ship a fix or mitigation for a
confirmed high-severity issue within **14 days**. We will credit reporters who
want it. Please give us a reasonable disclosure window before going public.

The full internal process — triage SLA, the severity rubric (a policy bypass or
a ring-0 memory-safety bug is graded a notch higher than CVSS alone), fixing
under embargo, and the CVE/disclosure flow — is in
[`docs/security/vulnerability-response.md`](docs/security/vulnerability-response.md).
The machine-readable contact is published at
[`/.well-known/security.txt`](https://unifiedfirewall.dev/.well-known/security.txt)
(RFC 9116).

## Supported versions

This is pre-1.0 software. Only the **latest released version** receives security
fixes. Pin a version for reproducibility, but expect to upgrade for fixes.

## What this software actually enforces (read before you rely on it)

Being precise here is itself a security property — a wrong mental model of what
blocks is a vulnerability in the operator.

| Layer | Mechanism | Status |
| --- | --- | --- |
| **L3/L4 packet policy** | one `nftables` table (`inet ufw`), compiled from your policy | **Enforces today.** No kernel module required. |
| **Identity-aware / DPI** | ring-0 kernel module (`ufw.ko`) + eBPF, policy over netlink | **Available via the shipped DKMS module**, off by default (`mode=monitor`). Not externally audited — see below. |
| **Detection** (IDS/IPS sigs, WAF, egress anomaly, port-scan, C2 beaconing, brute-force, DNS-tunnel, honeypot/deception, JA3/JA4) | user-space daemon + console | Detects and logs; enforcement of a detection is a separate, opt-in response. WAF full-pipeline efficacy is **measured** (89.7% catch / 0% FP on an independent corpus) — see `docs/design/detection-efficacy.md`. |
| **Licensing / activation** | Supabase edge functions + a client node-lock | A **deterrent**, not DRM (see `website/LICENSING.md`). |

The packet layer is real enforcement: after `firewall apply`, the kernel filters
this host's traffic against the policy, and nothing the compiler cannot express
is silently added — untranslatable rules are dropped, not weakened.

## Audit status (honest)

- **Not yet externally audited.** No third-party security review has been
  performed. The claims below are from our own tests, not an outside party.
- **The default build puts no out-of-tree C on the hostile-byte path.** The
  kernel module is off by default; the packet layer is in-kernel `nftables`
  (upstream, widely audited) and the daemon's own protocol parsing is the
  memory-safe Rust core. The ring-0 C decoders only ever see attacker bytes if
  *you* build and load `ufw.ko` and switch to enforce — an opt-in, not the
  baseline.
- **When the module IS built, its decoders are proven equivalent to a
  memory-safe core.** `kernel/linux/rust/ufw_kcore` is a `no_std`, no-`unsafe`
  Rust reimplementation of the ring-0 decoders; the `differential` CI job
  compiles the C and runs both over the whole fuzz corpus plus tens of thousands
  of mutations, asserting they extract every field **byte-for-byte identically**.
  `UFW_DIFF_REQUIRE=1` makes a missing toolchain a hard failure, so the gate
  cannot pass vacuously. A place where the C would read out of bounds is exactly
  a place the Rust returns `None` — and the gate turns that divergence red.
- **Continuously fuzzed:** the ring-0 C parsers (decoders, stream reassembly,
  DPI automaton) run under sanitizer-instrumented, coverage-guided fuzzing in CI
  (`.github/workflows/fuzz.yml`), plus a nightly campaign.
- **Hardened code generation:** `ufw.ko` is built with `-Werror`,
  `-Wframe-larger-than`, `-Wvla`, and (via `cc-option`) stack-protector plus the
  no-strict-overflow / no-null-check-deletion flags, on top of the host kernel's
  own hardening — so a bounds check written for defence is never optimised away.
- **CI gates every change** on `cargo test`, `clippy -D warnings`, `fmt`, the
  fuzz smoke campaigns, and the named `differential` equivalence gate.

None of this is a substitute for a **third-party audit of the ring-0 code and
the nftables emission** — that remains the single highest-value next step, and
the equivalence gate is designed to make that audit cheaper, not to replace it.
It does, however, change the honest one-line summary from "unaudited C in the
kernel" to "the hostile-byte path is memory-safe by construction in the default
build, and equivalence-gated against a memory-safe core when you opt into the
module."

## For an external reviewer

Start with the [**audit brief**](docs/security/audit-brief.md): what to review and
in what order, every claim we make with its evidence and honest scope, and what
we explicitly do **not** claim. Then the
[**pre-audit self-assessment**](docs/security/pre-audit-assessment.md): the
findings we already found and fixed, our own adversarial review of the latest
hardening, and the dependency posture — the baseline so your engagement is spent
on the unknowns, not re-finding the knowns. To **commission** an audit, see the
[**audit RFP / outreach packet**](docs/security/audit-rfp.md) — scope of work, a
shortlist of real firms, a ready-to-send request, a readiness checklist, and the
(grant-funded) engagement model.

## Threat model & attack surface

See [`docs/security/threat-model.md`](docs/security/threat-model.md) and
[`docs/security/attack-surface.md`](docs/security/attack-surface.md).

## Acknowledgements

We credit everyone who reports a valid security issue in good faith and wants
the credit; ask to stay anonymous and we honor that. No external reports have
been received yet — this section is where reporters will be listed as they are.

## Hardening notes for operators

- The kernel module **adds ring-0 attack surface**. If you do not need
  identity/DPI enforcement, do not build/load it — the packet layer stands alone.
- Under **Secure Boot**, an unsigned out-of-tree `ufw.ko` will not load
  (fail-closed). Sign it with an enrolled MOK, or leave the module off.
- The web console binds **loopback only** and is read-only apart from one
  loopback-gated action. Do not expose it; if you must, front it with the mTLS +
  RBAC build (`--features tls`) and an SSH tunnel — never a bare port.
- The licensing signing secret and the Supabase service-role key are
  **server-side only** and never shipped in the client or the `.deb`.

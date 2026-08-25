# Security policy

## Reporting a vulnerability

**Do not open a public issue for a security bug.** Email
**security@unifiedfirewall.dev** with:

- the component (packet compiler, kernel module, daemon, dashboard, licensing),
- affected version (`ufw-nft --version` / package version),
- a description and, if possible, a reproducer (a policy, a packet capture, or a
  crash input).

We aim to acknowledge within **72 hours** and to ship a fix or mitigation for a
confirmed high-severity issue within **14 days**. We will credit reporters who
want it. Please give us a reasonable disclosure window before going public.

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
| **Detection** (IDS/IPS sigs, beaconing, JA3/JA4, egress anomaly) | user-space daemon | Detects and logs; enforcement of a detection is a separate, opt-in response. |
| **Licensing / activation** | Supabase edge functions + a client node-lock | A **deterrent**, not DRM (see `website/LICENSING.md`). |

The packet layer is real enforcement: after `firewall apply`, the kernel filters
this host's traffic against the policy, and nothing the compiler cannot express
is silently added — untranslatable rules are dropped, not weakened.

## Audit status (honest)

- **Not yet externally audited.** No third-party security review has been
  performed. The claims below are from our own tests, not an outside party.
- **Continuously fuzzed:** the ring-0 C parsers (decoders, stream reassembly,
  DPI automaton) run under sanitizer-instrumented, coverage-guided fuzzing in CI
  (`.github/workflows/fuzz.yml`), plus a nightly campaign.
- **A memory-safe core exists:** `kernel/linux/rust/ufw_kcore` reimplements the
  hostile-byte parsers in Rust and is differential-tested against the C.
- **CI gates every change** on `cargo test`, `clippy -D warnings`, `fmt`, and the
  fuzz smoke campaigns.

The single highest-value next step for this project's security posture is a
**third-party audit of the ring-0 code and the nftables emission**; self-tests
do not substitute for it.

## For an external reviewer

Start with the [**audit brief**](docs/security/audit-brief.md): what to review and
in what order, every claim we make with its evidence and honest scope, and what
we explicitly do **not** claim.

## Threat model & attack surface

See [`docs/security/threat-model.md`](docs/security/threat-model.md) and
[`docs/security/attack-surface.md`](docs/security/attack-surface.md).

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

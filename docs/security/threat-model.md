# Threat model

Scope: the Unified Firewall host agent (packet compiler + `ufw-nft`, the daemon
`ufwd`, the kernel module `ufw.ko` + eBPF, the web console) and the licensing
backend. This document is written to be **audit-ready**: it states assets, trust
boundaries, adversaries, and — deliberately — the residual risks we have *not*
closed.

## Assets

1. **The host's availability and integrity.** The firewall runs in the packet
   path (and, with the module, in ring 0). A defect here can take the host off
   the network or crash the kernel.
2. **Policy integrity.** The compiled ruleset must faithfully reflect the
   authored policy — never enforce *more* than it says (a false sense of a rule
   that isn't there) nor *less* (a silently dropped deny).
3. **Telemetry / audit truth.** Denials, detections, and the activation log must
   be attributable and not forgeable by the traffic they describe.
4. **Licensing revenue.** Keys, activation state, admin access.

## Trust boundaries

```
   hostile network packets ──▶ [ eBPF / nft ] ──▶ [ ufw.ko ring-0 parsers ]   ← highest risk
   local unprivileged user  ──▶ [ web console :8787 (loopback) ]
   local root               ──▶ [ ufw-nft / ufwctl CLIs ]
   fleet control plane      ──▶ [ ufwd REST :9600 (HMAC-authenticated) ]
   customer host            ──▶ [ Supabase edge functions (public) ]  ──▶ service role ──▶ DB
   browser (admin)          ──▶ [ admin edge function (JWT + allowlist) ]
```

Everything left of an arrow is **untrusted** relative to what's right of it.

## Adversaries and what they can attempt

### A1 — Remote attacker sending hostile packets (unauthenticated)
The most important adversary, because the parsers process attacker-controlled
bytes **in the kernel**.
- **Goals:** crash the kernel (DoS), corrupt memory (privilege escalation / RCE
  in ring 0), or evade classification (smuggle traffic past a deny).
- **Surface:** `ufw.ko` decoders, stream reassembly, DPI automaton; the eBPF
  XDP/conntrack paths.
- **Mitigations:** bounds-checked parsers hardened against overflow/OOB;
  sanitizer-instrumented, coverage-guided fuzzing in CI + nightly; a Rust
  reimplementation (`ufw_kcore`) differential-tested against the C; `-Werror`,
  `-Wvla`, and a 512-byte frame cap in the module build.
- **Residual risk:** **no external audit** of the ring-0 code. Fuzzing reduces
  but does not eliminate memory-safety risk. Running the module is opt-in for
  exactly this reason.

### A2 — Local unprivileged user
- **Goals:** read/alter firewall state, reach the one mutating console action,
  or escalate via the daemon/module.
- **Surface:** web console (`:8787`, loopback, read-only + one loopback-gated
  `Contain`), the daemon's local REST (`:9600`), world-readable files.
- **Mitigations:** console binds loopback and gates the mutating action on the
  request arriving over loopback; the license store is root-only (`0600`);
  privileged CLIs require root. Optional mTLS + RBAC (`--features tls`) for the
  console when exposed.
- **Residual risk:** a local user in the loopback trust zone can reach the
  console's read views and the Contain action; treat console access as
  privileged.

### A3 — Attacker on the fleet control plane
- **Goals:** push a malicious policy to hosts.
- **Mitigations:** fleet messages are HMAC-authenticated with a per-deployment
  secret (`fleet_secret`, ≥32 chars) that the installer forces you to change;
  policy integrity is checked before apply. On a `--features tls` build,
  configuring the fleet signer's public key (`api.fleet_ed25519_pubkey`) makes a
  detached **Ed25519 signature** required in addition to the MAC — the private
  key lives only with the signer, so a compromised host can verify a bundle but
  cannot mint one (`daemon/src/fleet.rs`).
- **Residual risk:** on the default (non-tls) build the shared HMAC secret is
  symmetric — protect it like a key; the asymmetric upgrade requires the `tls`
  build and a configured public key.

### A4 — Malicious license holder (the customer's own root)
- **Goal:** run past expiry / on more machines than licensed.
- **Reality:** the agent runs as **root on the attacker's own box** and the
  activation token is symmetric-HMAC. This is a **deterrent, not DRM**, and we
  say so. Ed25519 (client verifies, cannot forge) is the documented upgrade.
- **Not defended:** a determined owner *can* bypass client-side licensing.

### A5 — Supply-chain attacker
- **Goal:** ship a tampered `.deb`/module to victims.
- **Mitigations:** reproducible packaging; an SBOM (CycloneDX) is produced in
  CI; the module is Dual MIT/GPL source built on the target via DKMS.
- **Residual risk:** the `.deb` is **not yet GPG-signed** and there is no signed
  apt repo — a pending hardening item. Until then, verify the published SHA-256.

### A6 — Attacker against the licensing backend
- **Mitigations:** the licensing tables have RLS on with **no** anon/authenticated
  policies (service-role only); the browser never touches them. `activate` /
  `validate` authenticate the *key value*; `admin` requires a Supabase Auth JWT
  **and** an `admin_users` allowlist entry. The service-role key and signing
  secret are server-only.
- **Residual risk:** a leaked service-role key is total compromise of the
  licensing DB — it must never reach a client or the repo.

## Explicit non-goals

- Defeating an attacker who already has **root on the protected host**.
- Unbreakable license enforcement (see A4).
- Protecting the console for an attacker already inside the loopback trust zone
  without the mTLS build.

## Fail-safe posture

- Default install is **monitor mode** — observes, does not block; nothing can
  cut your own access until you deliberately `apply`.
- `trial <policy> <secs>` arms a detached auto-revert so a lockout heals itself.
- On Secure Boot, an unsigned module **fails closed** (won't load) rather than
  loading unverified ring-0 code.
- A lapsed license reverts enforcement to unprotected + warns, rather than
  silently keeping stale rules.
- **When enforcement is unavailable**, `daemon.fail_mode` decides the posture as
  an explicit operator choice (`daemon/src/failsafe.rs`): `closed` (default)
  installs an emergency default-deny nftables barrier that keeps the operator in
  (loopback, established flows, management/SSH ports); `open` leaves the host
  reachable and unfiltered, loudly. The prior silent fail-open on a missing
  module is gone.
- A data-path fault that occurs *after* the module was working is held by the
  `watchdog` (last policy stays resident, crash-loop → loud safe mode), never a
  flush to allow-all.

## Tamper-evidence and self-monitoring

- Enforcement changes (policy install, mode switch, the fail-closed barrier,
  fleet bundles) are written to an append-only, **hash-chained audit log**
  (`daemon/src/audit.rs`); `ufwd --verify-audit` detects any edit, reorder or
  truncation, so an attacker who lands cannot silently erase how they got in.
  This is tamper-*evidence*, not tamper-proofing — the honest limit and its two
  defences (an optional HMAC key, an external head anchor) are documented in the
  module.
- A **self-check** engine (`daemon/src/selfcheck.rs`) alerts when a detector
  worker stops, a sink fails, telemetry is dropped, or the enforced policy drifts
  from disk — the failures that leave the daemon looking healthy.

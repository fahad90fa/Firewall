# DDoS, WAF/CDN, and patching/backups — what this firewall does, and where it stops

Three honest limitations were raised about this project:

> It can't absorb a DDoS, it isn't a CDN/WAF at the edge, and it doesn't
> replace patching, backups.

All three are worth taking seriously, because the failure mode of a security
product is a user who believes it covers something it does not. This document
says exactly what the firewall now does about each, and — kept in the same place
so the honesty is not buried — exactly where a host firewall physically cannot
go and something else has to.

## 1. Floods and DDoS

### What was added

There is now a real, opt-in on-host flood layer:
[`daemon/src/edge_hardening.rs`](../../daemon/src/edge_hardening.rs), config
section `[edge]`, key `edge.flood_protection`.

When enabled, the daemon installs a standalone nftables table (`inet ufw_edge`)
at hook priority **-150**, ahead of the policy table (priority 0). It drops, in
the kernel's own conntrack path and before policy evaluation spends a cycle:

- **invalid / out-of-state packets** — `ct state invalid drop`;
- a **SYN-flood cap** — new-connection SYNs over `syn_rate_per_sec` (default
  200/s, burst 50);
- a **per-source concurrent-connection cap** — one source IP holding more than
  `conns_per_source` (default 100) live connections, via `ct count`, for both v4
  and v6;
- an **ICMP / ICMPv6 echo cap** — ping floods over `icmp_rate_per_sec`
  (default 20/s, burst 10).

Every rule is a *drop-what-exceeds* rule. The only `accept` is loopback; nothing
here terminally accepts, so within-rate traffic falls straight through to the
policy table and this layer can never widen what the policy permits. It is
proven to load into a live kernel (`nft --check`) by
[`tests/scenarios/enforcement_conformance.rs`](../../tests/scenarios/enforcement_conformance.rs)
(`the_edge_flood_hardening_layer_loads_into_the_kernel`), and its shape is unit-tested
in the module.

This closes the classes of flood that are about **state and connection rate**
rather than raw bandwidth: SYN floods that fill the connection table, one source
opening thousands of sockets, malformed/out-of-state bursts, ICMP storms. Those
are exactly the floods a single host *can* refuse to fall over from, and now it
does.

### Where it stops — and why no code can move the line

A host firewall **cannot absorb a volumetric DDoS**, and this one does not claim
to. By the time a packet reaches this host it has already crossed the network
and consumed the very bandwidth a volumetric flood exists to exhaust. Dropping
it here does not un-send it — the link is already saturated upstream of any rule
this daemon can install. Absorbing a bandwidth flood needs capacity *in front
of* the host: a scrubbing centre, a CDN/anycast edge, or the provider's DDoS
protection. This is physics, not a missing feature, and the module doc, the
config comment, and the daemon's own startup log line all say so in as many
words ("mitigates connection-rate floods; a volumetric DDoS still needs upstream
scrubbing").

**Net:** the "can't absorb a DDoS" gap is now split correctly. Connection-rate
and state floods — mitigated, in the kernel, opt-in. Volumetric floods — still
an upstream job, and honestly labelled as one.

## 2. "It isn't a CDN/WAF at the edge"

This one is two claims, and they resolve differently.

### The WAF part is already partly wrong — there is a host-side WAF

The project ships a userspace WAF engine ([`daemon/src/waf.rs`](../../daemon/src/waf.rs),
binary [`daemon/src/bin/ufw-waf.rs`](../../daemon/src/bin/ufw-waf.rs)) that runs
the shipped OWASP signature set against **decrypted** HTTP — the gap the on-wire
DPI layer cannot see, because an HTTPS payload is ciphertext to it. The same
signatures are authored once and enforced both by the kernel DPI path (on
plaintext) and by this engine (behind a TLS-terminating reverse proxy).

What it is *not*, and its own module doc says so: a full WAF. No request
normalization pipeline, no OWASP Core Rule Set, no virtual patching, no bot
management. It is signature detection on decrypted traffic — the slice a host
firewall can genuinely provide — meant to sit **beside** a dedicated edge WAF,
not replace one. So "it isn't a WAF" is too strong; "it isn't a *full,
edge-grade* WAF" is exact, and that is how it is documented.

### The CDN part is true, and by definition uncloseable on the origin

A CDN is a *distributed* system: many points of presence, geographically spread,
serving cached content and absorbing traffic close to the client. "A CDN on the
origin host" is a contradiction in terms — the whole value of a CDN is that it is
*not* on your host. No code in this repository can become a CDN, and it does not
pretend to. If you need edge caching or anycast absorption, that is a service in
front of the host (Cloudflare, Fastly, a cloud provider's edge), and the on-host
flood layer in §1 is the origin-side complement to it, not a substitute.

**Net:** there *is* a host-side WAF (signature detection on decrypted HTTP);
there is *not*, and cannot be, a CDN on the origin. Both are now stated plainly
rather than implied away.

## 3. Patching and backups

This is the most important one to get right, because conflating a firewall with
patching or backups is how people get hurt.

A firewall **does not replace patching, and does not replace backups.** These are
categorically different controls:

- **Patching** removes the vulnerability. A firewall can only limit who can reach
  it and detect attempts to exploit it — it cannot make the bug not exist. An
  unpatched service behind this firewall is still an unpatched service.
- **Backups** are recovery. A firewall is prevention and detection; it has no
  role in restoring data after ransomware, disk failure, a bad deploy, or an
  operator mistake. Nothing in this repository is a backup, and it must never be
  counted as one.

What the firewall legitimately contributes *alongside* those controls, without
substituting for them:

- The DPI/IPS and WAF signature layers can **detect and block exploitation
  attempts** against a known-vulnerable service — buying time before a patch
  lands (this is detection/mitigation, explicitly *not* a virtual patch that
  removes the bug).
- Egress detectors (portscan, brute-force, beacon, DNS-exfil, anomaly) can
  surface **post-compromise behaviour** — which is the signal that you now need
  your backups and your incident process, not a replacement for either.
- Signed fleet bundles and the tamper-evident audit log protect the *firewall's
  own* integrity and change history; they are not a backup of your data.

**Net:** patching and backups are separate, non-negotiable controls that this
product complements and never replaces. The honest posture is "firewall +
patching + backups + upstream DDoS protection," and each of those four is a
distinct line item.

## The one-paragraph version

The firewall now mitigates connection-rate and state floods on the host itself,
and says clearly that volumetric DDoS absorption is an upstream job. It ships a
host-side WAF (signature detection on decrypted HTTP) but is not a full edge WAF
and cannot be a CDN on the origin — a CDN is by definition elsewhere. And it does
not replace patching or backups: it complements them by detecting exploitation
and post-compromise behaviour, but removing vulnerabilities and recovering data
are separate controls it will never stand in for. Every one of these boundaries
is enforced in the code's own logs and docs, not just this file, so a deployer
cannot mistake the layer for the whole.

## See also

- [`edge_hardening.rs`](../../daemon/src/edge_hardening.rs) — the flood layer and
  its ceiling, in the module doc.
- [`production-hardening.md`](production-hardening.md) — the full hardening
  roadmap and what closed each item.
- [`threat-model.md`](../security/threat-model.md) — what is in and out of scope
  for the product as a whole.

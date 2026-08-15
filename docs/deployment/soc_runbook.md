# SOC runbook and compliance mapping

Tier 3 — a security operations team, incident response, and compliance — is
**people and process**, not code, and no commit to this repository staffs a SOC
or passes an audit. What a repository *can* hold is the runbook that turns this
firewall's telemetry into action, and the mapping that shows an auditor which
control each feature supports. That is what this document is: the process glue,
so the people layer has a defined starting point rather than a blank page.

Nothing here runs on its own. It is written to be lifted into a real SOC's
ticketing and on-call.

## Alert triage — what this firewall emits, and the first move

Every row is an event this firewall actually produces (see
[`edge_integration.md`](edge_integration.md) for the export wiring). Severity is
the daemon's; the response is the operator's.

| Alert (tags / kind) | Means | First move | Escalate when |
| --- | --- | --- | --- |
| **`anomaly` / `egress-baseline`** | An established identity reached a **new external destination** — the shape of exfiltration | Pull the identity's recent egress; confirm the destination is expected (new SaaS? deploy?) | The process is user-facing or the destination is unclassified — treat as possible compromise |
| **`correlation`** across >1 host | The same block fanned out across the fleet | Treat as one incident, not N tickets; find the common cause (bad push? worm?) | Hosts span security zones |
| **IPS deny** (`ips`, lateral-movement / web-attack sigs) | A known exploitation primitive on the wire | Confirm source; block at the edge if inbound, isolate the host if egress | The signature is `critical` (Log4Shell, Shellshock, psexec) |
| **Port scan / RDP-VNC probe** (dashboard attack analysis) | Recon | Note the source; correlate with any later auth events | Scan is internal (already inside) |
| **Policy / mode change** (`PolicyChange`) | The firewall's own configuration moved | Confirm it was an authorized change | It was not in the change log — possible tamper |
| **`SystemFault` / watchdog safe-mode** | The data path faulted and backed off | Check the host is still reachable; read the fault | The watchdog latched (repeated faults) |

The **egress anomaly is the highest-value alert** and the reason the anomaly
detector exists: signatures catch known-bad, but a novel exfil destination has
no signature — only a baseline flags it.

## Incident response — the path from alert to signed fix

The runbook a security-response process needs, expressed against this firewall's
own controls:

1. **Detect.** The SIEM raises one of the alerts above.
2. **Contain.** The fastest containment this firewall offers is a mode change:
   `ufwctl debug mode enforce` guarantees the policy is enforcing, and for a
   compromised host the egress rules already deny anything the policy did not
   name. To harden further, push a tightened bundle (below).
3. **Eradicate + fix.** Author the corrective policy (a new deny, a scoped
   port, a fresh signature). Validate it: `ufwctl policy validate`, and for a
   signature `ufwctl debug signatures reload` distributes it fleet-wide without
   a restart.
4. **Roll out under control.** Sign the fix as a bundle and push it with a
   canary so a bad rule cannot take the fleet offline at once:
   `ufwctl fleet distribute fix.yaml --revision N --to <members> --canary-percent 5`.
   Each member authenticates it, compiles it locally, and the `fleet.rs`
   rate-based rollback backs out automatically if the denial rate spikes.
5. **Recover + review.** Confirm the alert has stopped; the policy-change events
   and the signed bundle history are the audit trail of what was done and when.

The property that makes step 4 safe is that a data-path fault must never cost an
operator remote access to the host — the watchdog and the boot-command-line
`ufw.bypass=1` are the escape hatches (see
[`../design/production_readiness.md`](../design/production_readiness.md)).

## Compliance control mapping

Which feature *supports* which control. "Supports" is deliberate: a control is
satisfied by the whole program (policy, evidence, people), and this firewall is
one input. This mapping is what an auditor uses to trace a control to a
mechanism, not a certification.

| Control (SOC 2 CC / ISO 27001 A) | Firewall mechanism |
| --- | --- |
| **CC6.1 / A.8.20** Network access restriction | The policy itself: identity-gated egress, source-scoped inbound (`policies/server/`) |
| **CC6.1 / A.8.20** Least privilege on the wire | Default-deny baselines; egress permitted only to named destinations |
| **CC6.6 / A.8.23** Boundary protection | Zone classification, perimeter-crossing DPI, the server-role inbound surface |
| **CC6.8 / A.8.7** Malicious activity detection | DPI signatures, lateral-movement IPS, the egress-baseline anomaly detector |
| **CC7.1 / A.8.16** Monitoring | The structured log export (SIEM/syslog/CEF) and the correlation engine |
| **CC7.2 / A.8.15** Logging of security events | Per-decision events with rule attribution and the author's reason |
| **CC7.3 / A.5.25** Incident response | This runbook; the mode/rollback controls; the signed-bundle audit trail |
| **CC8.1 / A.8.32** Change management | Policy-revision history, signed bundles, canary rollout, automatic rollback |
| **CC7.1 / A.8.8** Configuration integrity | The ruleset hash, the ABI-revision handshake, the reproducible zero-dependency build |

## What is still owed to the people layer

This document does not create: a staffed 24/7 SOC, an on-call rotation, a
red-team program, a bug-bounty, or an executed third-party audit. Those are
budget, hiring, and time — set out honestly in
[`../design/production_readiness.md`](../design/production_readiness.md). What
this firewall gives that layer is clean, attributed, exportable telemetry and a
safe, auditable way to push a fix. The rest is the organization's to build.

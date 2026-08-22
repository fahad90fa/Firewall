# Protection roadmap: where this firewall fits, and what has to sit around it

A recurring question is whether this firewall can "fully protect our servers
and websites." The honest answer starts with a reframe: full protection at the
scale people have in mind is not a product, it is a *program* — roughly a dozen
systems layered together, plus the people and process that run them. This
firewall is **one layer** in that program: the host layer. It is a good one,
and it is not the others.

This document is the map. It says what this project *is*, what it now does that
it did not before, where the honest boundary of a host firewall lies, and what
must exist on the other side of that boundary for a website or a fleet of
servers to be genuinely defended. It is the companion to
[`production_readiness.md`](production_readiness.md), which asks whether this
layer is deployable yet; this one asks what the layer is *part of*.

## The layered picture

A request to a protected website passes through several controls, and this
firewall is exactly one of them:

```
Internet
  → CDN + DDoS scrubbing + WAF        edge: volumetric absorption, L7 web-attack filtering
  → Load balancer / TLS termination   where HTTPS is decrypted for inspection
  → Application server (hardened)      app security, dependency and patch hygiene
  → ★ THIS FIREWALL, on each host ★    host layer: segmentation, egress containment, host IPS
  → SIEM / SOC watching all of it     detection, correlation, human response
```

Nothing below the edge can do the edge's job, and the edge cannot do the host's.
A host firewall on the origin cannot absorb a volumetric flood (the packets have
already arrived), and a CDN cannot stop a compromised process on the origin from
opening a reverse shell (it never sees that traffic). The layers are not
substitutes.

## Tier 0 — make this layer real

None of the host-layer work below matters until the engine is deployable, and
today it is not. This is tracked in full in
[`production_readiness.md`](production_readiness.md); the short form is four
gaps, all of them time-and-process rather than unsolved problems:

1. **Zero runtime hours.** Nothing here has run on a live kernel under real
   traffic for a sustained period. The instrument to measure it exists (the
   soak harness, the `/metrics` leak detector); the 30+ day run does not. This
   gap is closed by *running it*, and no commit can contain that.
2. **No independent audit.** Every proof was written by the code's own author.
   The ring-0 parsers are the first thing a third party should be paid to break.
3. **Operational scaffolding.** Signing/notarization with real keys, a
   kernel-side watchdog on Windows and macOS, a staged rollout proven on hosts
   outside the lab, a security-response process.
4. **macOS parity.** Connectionless (ICMP) enforcement via a
   `NEFilterPacketProvider`, and real Network Extension runtime hours.

Everything in Tier 1 is built *on* Tier 0. Shipping features on an engine with
zero runtime hours would be building on sand.

## Tier 1 — host-layer capability that belongs in this project

These are natural extensions of the engine, the daemon, and the signature set.
Some now exist; the rest are the sequenced next steps.

### Shipped in this iteration

- **A server role.** `policies/server/` now carries worked web-server and
  database-server policies: inbound surface locked to named service ports,
  administration scoped to a management network, egress identity-gated, and — on
  the web server — an inbound IPS on the exposed listener via `allow-inspect`.
  See [`policies/server/README.md`](../../policies/server/README.md). Both pass
  cross-platform equivalence, and CI holds them to it.
- **Inbound web-attack signatures.** `sig-rules/exploits/web_attacks.yaml` adds
  the exploitation and reconnaissance primitives that are unambiguous on the
  wire — Log4Shell (`${jndi:`), Shellshock (`() {`), encoded traversal,
  null-byte injection, the union-based SQLi shape, `${...}` expression
  injection, and probes for exposed `.git` and `.env`. These extend the host
  IPS from its egress/lateral-movement focus to the inbound direction a public
  server actually faces.
- **Egress-baseline anomaly detection.** `daemon/src/logging/anomaly.rs` is the
  twin of the denial correlator: it watches what policy *allowed* and alerts the
  first time an established application identity reaches a never-before-seen
  external destination — the shape of exfiltration, invisible to signatures. A
  learning window and a minimum baseline keep it from alerting on boot; memory
  is bounded on both axes. On by default (`logging.anomaly`).
- **Runtime signature feeds.** Signatures reload from disk without a restart
  (`ufwctl debug signatures reload`, `POST /v1/signatures/reload`), with a
  content digest that recognises an unchanged set as a no-op and a fail-closed
  install ordering so a rejected set leaves the previous one resident. A
  threat-intel update no longer means a window with no filtering.
- **A reachable fleet control plane.** `daemon/src/fleet.rs`'s bundle
  authentication, canary membership, and rate-based rollback — 13 tested
  functions that had zero callers — are now wired to the management API
  (`ufwctl fleet`, `/v1/fleet*`): a member registry, and a `fleet-verify` that
  authenticates a signed bundle and confirms it compiles on the host before it
  is trusted. Enabled by `api.fleet_secret`.
- **A server attack-surface view** in the dashboard: the live inbound chain,
  graded by what it exposes and to whom (world-open SSH/RDP/databases are
  findings; the same scoped to a source set is the intended shape).
- **Connection-rate controls at L3/L4** — SYN-flood and brute-force dampening.
  A `rate_limit:` block (`rate` / `per` / `burst`) on any `allow` or
  `allow-inspect` rule lowers to a **native nftables `limit` statement**
  (`ct state new limit rate 20/minute burst 5 packets accept`): new connections
  are accepted up to the cap and a flood beyond it falls through to the default
  deny, enforced in the kernel's own conntrack path with no module involvement.
  It is **decision-invariant** — neither `matches` nor `effective_action` reads
  it — so cross-platform equivalence stays green, and it is carried to the
  Linux artifact but kept off the daemon↔module wire (rate limiting is an
  nftables-layer feature, so there was no ABI change and no ring-0 edit). The
  analyzer notes that enforcement is Linux-only for now; Windows and macOS
  permit at the same verdict but do not yet throttle. `policies/server/`
  demonstrates it on the SSH and web listeners.

### Still to build

- **Rate-limit enforcement on Windows and macOS.** The Linux nftables path
  enforces today; the WFP callout and the Network Extension would each need
  their own token bucket to honour the same `rate_limit:` block. The verdict is
  already identical across all three — only the throttle is Linux-only.
- **Sender-side fleet distribution — now built, pending field runtime.** The
  receive side authenticates a pushed bundle, decides canary membership,
  compiles it locally, and installs it through the fail-closed pipeline
  (`fleet-push`, `POST /v1/fleet/push`). The send side is now here too: a
  single-shot fan-out (`daemon/src/fleet_client.rs`: sign once, post to each
  member, collect outcomes) and, on top of it, a **staged-rollout controller**
  (`daemon/src/fleet_rollout.rs`) — a pure decision engine that widens a rollout
  through gated waves (1%→10%→50%→100%), advancing only when a wave both
  converges and stays healthy and aborting within the current cohort on a
  regression. It is proven at scale by a deterministic 1000-host simulation. What
  is left is not code but wall-clock: driving it against real hosts outside the
  lab, which is the Tier 0 runtime gate, not new daemon capability.

## Tier 2 — separate systems this firewall integrates with, and must not become

These are the controls a website needs that a host firewall categorically does
not provide. The correct engineering is to **integrate**, not to absorb them.

| Need | What it is | Why it is not this firewall |
| --- | --- | --- |
| **WAF** | SQLi/XSS/OWASP filtering, virtual patching, at a reverse proxy | L7 request inspection in front of the app, on decrypted traffic. The host IPS here catches wire-unambiguous primitives only |
| **DDoS + CDN/edge** | Volumetric absorption, anycast, caching | The origin cannot absorb a flood that has already reached it |
| **EDR/XDR** | Endpoint process behaviour and response | A different sensor from a network filter |
| **SIEM + SOC** | Log correlation across all layers, humans watching | Aggregation and response, not enforcement |
| **IAM / Zero-Trust access** | SSO, MFA, mTLS, service mesh | Identity of *users and services*, not of local processes |
| **PKI / secrets / KMS** | Certificate and key lifecycle | Key custody |
| **Vuln management / SAST / DAST** | Scanning and patch pipeline | Finding flaws, not filtering traffic |

### The integration seam that already exists

The one Tier-2 boundary this project is already built to cross is the **SIEM**.
The daemon's logging fan-out (`daemon/src/logging/`) renders every decision as
structured output and ships it off-host:

- **Formats:** JSON lines, text, and **CEF** (`LogFormat::Cef`), the common
  denominator most SIEMs ingest.
- **Transports:** a file sink with rotation, an **RFC 5424 syslog** sink over
  UDP, and a dedicated **SIEM sink** with TLS, buffering, and reconnect
  (`daemon/src/logging/sink.rs`).
- **Configuration:** `logging.siem.enabled`, `logging.siem.address`,
  `logging.siem.format`, `logging.siem.tls`, `logging.siem.ca_path`, and the
  `logging.syslog.*` keys (`daemon/src/config.rs`).
- **Back-pressure is bounded:** a stalled collector drops the oldest events and
  counts the drop rather than stalling packet decisions — a logging problem must
  never become an outage. Drops are themselves logged.

So the host layer's telemetry already flows into the detection layer. What it
feeds — the correlation rules, the dashboards, the on-call rotation — is the
SOC's to build, and is Tier 3.

A worked reference for the whole edge — a WAF reverse proxy in front of the
server policy, the CDN/DDoS posture, and the exact SIEM export configuration —
is in [`../deployment/edge_integration.md`](../deployment/edge_integration.md).
It is integration glue for external products, not a claim to replace them.

## Tier 3 — the part that is not code

At the scale the original question imagines, most of the actual work is people
and process, and no amount of engineering substitutes for it:

- A security team and a 24/7 SOC to watch the telemetry the layers emit.
- Red-team exercises and a bug-bounty program to find what the authors could not.
- Incident-response runbooks: a path from "a bypass was found in the wild" to "a
  signed fix is on every deployed host."
- Compliance regimes appropriate to the data — SOC 2 / ISO 27001, and for
  government-adjacent work, FedRAMP / FISMA.

These are named here not because this repository implements them, but because a
roadmap that omitted them would imply that shipping the code is the finish line.
It is not; it is the host layer of a much larger thing.

What the repository *can* hold for this tier is the process glue: a SOC runbook
that turns this firewall's own alerts into a triage-and-response path, and a
compliance control mapping tracing each control to a mechanism. That is
[`../deployment/soc_runbook.md`](../deployment/soc_runbook.md) — a starting
point for the people layer, not a substitute for it.

## What to take away

This firewall's job is to be the best host layer it can be: shrink each server's
inbound surface, contain what a compromised server can do outbound, and catch the
inbound primitives that are unambiguous on the wire — then hand its telemetry to
the detection layer above it. It should be paired with a WAF and a CDN/DDoS edge
in front of any website, and watched by a SOC. Trying to make it *become* those
other layers would make all of them worse. Owning the host layer well, and
integrating cleanly with the rest, is the whole ambition — and it is a real one.

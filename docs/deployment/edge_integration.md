# Edge integration: the layers in front of and above the host firewall

This firewall is the **host layer**. A production website needs layers this
firewall deliberately does not provide — a WAF for application-layer attacks, a
CDN/DDoS edge for volumetric absorption, and a SIEM/SOC for correlation and
response. Those are **separate products**; this document is not a claim to
replace them. It is the concrete wiring that makes them work *with* the server
policies in [`policies/server/`](../../policies/server/), so an operator has a
worked reference rather than a diagram.

```
Internet
  → CDN + DDoS scrubbing + WAF        edge (Cloudflare / Akamai / AWS)  — Tier 2
  → Load balancer / TLS termination   where HTTPS is decrypted           — Tier 2
  → Web server host  ← policies/server/web_server.yaml + THIS firewall   — host layer
  → App / DB hosts   ← policies/server/database_server.yaml
  → SIEM / SOC        ← this firewall's log export                       — Tier 2/3
```

Two rules of thumb the layering enforces:

- **Nothing below the edge can do the edge's job.** A host firewall on the
  origin cannot absorb a volumetric flood — the packets have already arrived.
  The origin's `rate_limit:` on port 80/443 is *second-line* dampening; the
  edge is the first line.
- **The edge cannot do the host's job.** A CDN never sees a compromised process
  on the origin opening a reverse shell. That is exactly what this firewall's
  egress rules and anomaly detector catch.

## The WAF, in front of the origin

The host IPS (`sig-rules/exploits/web_attacks.yaml`) catches the handful of
inbound primitives that are unambiguous on the wire — Log4Shell, Shellshock,
traversal. It is **not** a WAF: it does not do the full OWASP rule set, virtual
patching, or bot management, and on HTTPS it cannot see the request at all
(the payload is encrypted until the app or a proxy terminates TLS).

Put a real WAF where it can see decrypted requests — at a reverse proxy in front
of the app. A minimal Coraza/ModSecurity reverse proxy that fronts the web
server the policy protects:

```nginx
# nginx + libmodsecurity (OWASP CRS) in front of the origin web server.
# The origin's policy (web_server.yaml) opens 80/443 to *this* proxy's network
# and rate-limits; this proxy does the L7 inspection the host cannot.
server {
    listen 443 ssl;
    server_name app.example.com;
    ssl_certificate     /etc/tls/app.crt;
    ssl_certificate_key /etc/tls/app.key;

    modsecurity on;
    modsecurity_rules_file /etc/modsecurity/crs-setup.conf;   # OWASP Core Rule Set

    location / {
        proxy_pass https://origin-web;      # the host running web_server.yaml
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
```

Then tighten the origin policy so the web ports are reachable **only from the
proxy tier**, turning the world-open listener into a scoped one — the same
`saddr` scoping the database server already uses:

```yaml
# In web_server.yaml, replace the world-open web rule's scope:
  - id: allow-web-inbound
    # ...
    source:
      addresses: [proxy_tier]      # only the WAF proxies, not the whole internet
```

The dashboard's **Attack surface** view will then grade those ports `good`
(scoped) rather than flagging them world-open.

## The CDN / DDoS edge

Volumetric DDoS is an upstream-capacity problem; it is solved before traffic
reaches the origin, by anycast and scrubbing at a provider (Cloudflare, Akamai,
AWS Shield/CloudFront). There is nothing to configure in this firewall for it —
the point is the opposite: **do not rely on the origin for volumetric
defense.** The origin's `rate_limit:` protects against what leaks past the edge
and against direct-to-origin attacks that bypass it, which is why the origin's
real IP should not be publicly resolvable when an edge is in use.

## The SIEM seam — already built

The one Tier-2 boundary this firewall is built to cross. Every decision, every
correlation, and every egress anomaly is rendered as a structured event and
shipped off-host. Turn it on:

```toml
# /etc/ufw/ufwd.toml
[logging.siem]
enabled = true
address = "siem-collector.example.com:6514"
format  = "cef"        # json | text | cef  — CEF is the common SIEM denominator
tls     = true
ca_path = "/etc/ufw/siem-ca.pem"

[logging.syslog]       # or plain RFC 5424 syslog, if that is the collector
enabled = true
address = "10.10.20.5:514"
```

What flows, and why it matters to a SOC:

| Event | Source | What the SOC does with it |
| --- | --- | --- |
| Denied flow, with the rule and the author's reason | every backend | Baseline noise; spikes are a probe |
| Correlated pattern (same block across N hosts) | `logging/correlation.rs` | Fleet-wide incident, not one noisy host |
| **Egress anomaly** (identity reached a new external dest) | `logging/anomaly.rs` | The exfiltration signal — highest-value alert |
| Port-scan / lateral-movement IPS hits | `sig-rules/` | Post-compromise activity |
| Policy change / mode change / fault | daemon | Change audit and tamper evidence |

Back-pressure is bounded: a stalled collector drops the oldest events and counts
the drop rather than stalling packet decisions — a logging outage never becomes
a filtering outage. The drop count is itself logged.

## What stays out of this repo

The WAF rules, the CDN account, the SIEM's correlation content, and the people
watching it are all outside this codebase — they are other products and other
teams. This firewall's contribution to that stack is a well-scoped host layer
that emits clean, structured telemetry into it. The
[protection roadmap](../design/protection_roadmap.md) is the full map of who
owns which layer.

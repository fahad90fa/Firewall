# Monitoring

Every daemon exposes its state three ways, from the same read-only API. Nothing
here is a separate service to install — it is the daemon you already run.

## The web dashboard

Each daemon serves a self-contained dashboard at the root of its REST API:

```
http://127.0.0.1:8080/            # or https://…, or /dashboard
```

It is one HTML file embedded in the binary — no external scripts, fonts or
images, the same zero-dependency rule as the rest of the project — so it works
on an air-gapped host and adds nothing to the attack surface but the bytes it
serves. Open it and it shows, for each device, everything the API knows:

- **Health** — enforcing / degraded / safe-mode, mode, uptime, process memory.
- **Kernel** — connected or not, module version, capabilities, last error.
- **Watchdog** — state, faults in the window, total faults, safe-mode entries.
- **Policy** — revision, rule count, reloads and failures, source file.
- **Traffic** — flows seen / allowed / denied, packets, DPI scans and hits,
  conntrack entries, eBPF fast-path decisions.
- **Identity** — resolver, queries, cache hit rate.
- **Logging** — received / written, queue drops, sink errors.

It refreshes on an interval you choose, and a summary bar totals the fleet:
how many devices are online, enforcing, degraded, and how many flows have been
denied across all of them.

### Reaching it safely

The dashboard is served without authentication — it is static HTML with no
secrets — but every piece of *data* it fetches goes through the same
authorization as `ufwctl status`. So:

- **Loopback (recommended).** With the API on `127.0.0.1`, open the dashboard
  locally, or tunnel to it: `ssh -L 8080:127.0.0.1:8080 host`. No token, nothing
  on the wire.
- **Remote.** A non-loopback API bind already requires a bearer token and TLS
  (the daemon refuses otherwise). Enter that token when you add the device; it is
  sent only as an `Authorization` header to that device.

## The fleet view — all your devices in one page

Open one device's dashboard and use **+ Device** to add the others by URL
(`https://mac-01.local:8443`) and, if they require one, a bearer token. Each
device is polled and shown as its own card — 🐧 Linux, 🪟 Windows, 🍎 macOS —
side by side. The device list is stored in your browser, not on any daemon.

For your browser to read *another* device cross-origin, that device's daemon has
to name the dashboard's origin. That is the one setting the fleet view needs:

```toml
[api]
rest_bind   = "0.0.0.0:8443"
auth_token  = "…at least 32 chars…"
tls_cert    = "/etc/ufw/tls/cert.pem"
tls_key     = "/etc/ufw/tls/key.pem"
# The origin of the page you open the fleet view from:
cors_origins = ["https://ops-laptop.local:8443"]
```

`cors_origins` is **empty by default**: a device is never readable cross-origin
until you list an origin here, and the daemon echoes only the exact origins
named — never a blanket `*` alongside a token. A single `"*"` is accepted for a
trusted network but is a deliberate choice, not a default.

## Prometheus / long-term metrics

The same data is a scrape target at `GET /metrics`, in Prometheus text format —
including `ufw_process_resident_memory_bytes`, the leak signal a soak watches.
Point a Prometheus at it and you get history, alerting, and Grafana for free; see
[`soak_testing.md`](../design/soak_testing.md) for the series that matter and
their pass/fail thresholds. The scrape endpoint is gated by the same token as
`status`.

## `ufwctl`

For a terminal, `ufwctl status` and `ufwctl stats` return the same state as
JSON over the local control socket — no HTTP, no token, just Unix-socket
permissions. The dashboard, `/metrics`, and `ufwctl` all read one source, so
they cannot disagree.

## Self-check alerts, the audit log, and fail-safe

Three things the daemon now surfaces without you having to go looking:

- **Self-monitoring.** The daemon watches its own vital signs and emits a
  `self-check [...]` event (at Critical or Warning) when a detector worker
  stops, the event sink starts failing, telemetry is dropped on a full queue, or
  the enforced policy drifts from the one on disk — the failures that leave it
  *looking* healthy. These reach the same event stream the dashboard and SIEM
  export read, so a silent partial failure becomes a visible alert.
- **Tamper-evident audit log.** Enforcement changes are written to an
  append-only, hash-chained log under the state directory. Verify it any time
  with `ufwd --verify-audit /var/lib/unified-firewall/audit.jsonl`; it reports
  `intact` or names the first break. Ship the periodic `audit[...] chain head`
  events to a remote sink so tail truncation of the local file is detectable
  against a head you kept elsewhere.
- **Fail-safe posture.** If the kernel enforcement path is unavailable and you
  run without it, `daemon.fail_mode = closed` (the default) installs an emergency
  default-deny barrier that keeps management access; `open` leaves the host
  reachable and unfiltered. Either way the daemon says which, at Critical.

## An honest caveat

The dashboard shows the daemon's own account of itself. It is an excellent way to
watch a soak, catch a device slipping to `degraded`, or see denials climb — but
it reports what the daemon believes, and on a host that has never been soaked
(see [`../design/production_readiness.md`](../design/production_readiness.md))
"the daemon believes it is healthy" is not yet the same as "it is." Read it as
instrumentation for the validation still owed, not as proof that validation is
done.

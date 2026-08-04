# REST API

Off by default. When enabled, it binds loopback unless an `auth_token` of at
least 32 characters is configured — the daemon **refuses to start** with a
routable bind and no token, because a management API that can install policy is a
remote code path into the kernel.

```toml
[api]
bind = "127.0.0.1:9443"
auth_token = "..."      # required for any non-loopback bind
```

`Authorization: Bearer <token>`, compared in constant time.

## What the server deliberately does not do

- **No chunked transfer-encoding.** Most of the request-smuggling surface, none
  of it needed for JSON bodies of a few kilobytes.
- **No header continuations.** Obsolete, and a parser-differential source.
- **No keep-alive, no pipelining.** One request per connection. This API handles a
  handful of requests a day, and connection reuse buys nothing against the
  desynchronisation risk.
- **No redirects, no content negotiation.** One representation: JSON.

Every one of these is a feature a general-purpose server needs and this one does
not. Each is also a place where two parsers disagreeing becomes a request the
front end did not see.

## Endpoints

| | |
| --- | --- |
| `GET /healthz`, `GET /v1/ping` | Liveness |
| `GET /v1/status` | Health, revision, counters |
| `GET /v1/stats` | Kernel counters |
| `GET /v1/rules[?filter=]` | Installed rules |
| `GET /v1/rules/{name-or-id}` | One rule |
| `GET /v1/revisions` | Retained revisions |
| `GET /v1/trust` | Trust database and cache |
| `GET /v1/signatures` | Loaded signatures, and dangling references |
| `POST /v1/policy/reload` | Recompile from disk and install |
| `POST /v1/policy/validate` | Validate without installing |
| `POST /v1/policy/diff` | Diff on-disk against installed |
| `POST /v1/policy/rollback` | `{"revision": N}` |
| `POST /v1/policy/flush` | Remove every rule |
| `POST /v1/mode` | `{"mode": "enforce"｜"monitor"｜"emergency-allow"}` |
| `POST /v1/identity/resolve` | `{"pid": N}` |
| `POST /v1/shutdown` | |
| `POST /v1/rpc` | Generic entry point: any operation as a JSON body |

The route table is explicit rather than pattern-matched, so adding an endpoint is
a visible change and a read-only verb cannot drift onto a mutating operation.

## Authority

`GET` is read-only. Every mutating endpoint — and `identity/resolve`, which
inspects another process — requires administrative authority. The check happens
in the shared `Router`, so it cannot be enforced on one surface and forgotten on
another.

## Errors

```json
{"ok": false, "status": 403, "error": "`flush-policy` requires administrative authority"}
```

| | |
| --- | --- |
| `400` | Malformed request |
| `401` | Missing or bad token |
| `403` | Insufficient authority |
| `404` | No such route, rule or revision |
| `409` | The operation conflicts with current state |
| `503` | No policy installed, or the kernel module is unreachable |

## One router, three surfaces

REST, gRPC-Web and the CLI socket all dispatch the same `Request` enum through
the same `Router`. They cannot answer differently, and an operation added to one
is available on all three or on none.

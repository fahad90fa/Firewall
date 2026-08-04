# REST API

Off by default. A routable bind needs **both** a token and TLS — the daemon
refuses to start with either missing, because a management API that can install
policy is a remote code path into the kernel, and a bearer token sent in the
clear protects the token from nothing.

```toml
[api]
rest_bind  = "0.0.0.0:9443"
auth_token = "..."                        # >= 32 chars, required off loopback
tls_cert   = "/etc/unified-firewall/api.crt"
tls_key    = "/etc/unified-firewall/api.key"
tls_client_ca = "/etc/unified-firewall/clients.crt"   # optional mTLS
```

`Authorization: Bearer <token>`, compared in constant time.

## TLS

TLS is a **build-time opt-in**:

```sh
cargo build --release                              # zero dependencies
cargo build --release --features ufw-daemon/tls    # rustls, TLS in the daemon
```

The workspace is otherwise dependency-free because everything in it lands in the
trusted computing base of a kernel-mode filtering decision. TLS is the one place
that reasoning does not survive contact with reality: the alternative to a vetted
library is a hand-written one, and hand-rolled crypto in a security product is
strictly worse than no TLS — it looks like protection and is not.

So the choice is the operator's, and both answers are supported:

| Deployment | Build | Config |
| --- | --- | --- |
| Loopback only | default | nothing |
| TLS terminated by a proxy | default | `allow_plaintext = true` |
| TLS in the daemon | `--features tls` | `tls_cert` + `tls_key` |

What is **not** supported is configuring TLS and silently getting plaintext. A
binary built without the feature refuses to start when the configuration asks
for TLS, and names the build flag rather than reporting a generic failure.

`allow_plaintext = true` is required for the proxy case: the daemon does not
guess that something is terminating TLS in front of it.

Client certificates (`tls_client_ca`) are optional and worth using. A bearer
token authenticates whoever holds it; a client certificate authenticates a key
that cannot be copied out of a log file or a shell history.

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

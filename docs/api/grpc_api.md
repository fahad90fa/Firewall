# gRPC API

gRPC-**Web** over HTTP/1.1, not gRPC over HTTP/2.

The workspace takes no dependencies, and an HTTP/2 implementation is a
substantial amount of code — HPACK, flow control, stream multiplexing — every
line of which would sit in the trusted computing base of a kernel-mode filtering
decision. gRPC-Web reuses the HTTP/1.1 server already needed for REST, and the
framing is a five-byte prefix.

The cost: no bidirectional streaming, and clients need a gRPC-Web-capable stub
(`grpc-web` for JavaScript, an Envoy or `grpcwebproxy` shim for native clients).
Given the traffic this API carries — a handful of administrative calls — that is
a good trade.

## Service

```protobuf
service UnifiedFirewall {
  rpc Status          (Empty)      returns (JsonReply);
  rpc Stats           (Empty)      returns (JsonReply);
  rpc ListRules       (RuleFilter) returns (JsonReply);
  rpc GetRule         (RuleKey)    returns (JsonReply);
  rpc ListRevisions   (Empty)      returns (JsonReply);
  rpc ListTrust       (Empty)      returns (JsonReply);
  rpc ListSignatures  (Empty)      returns (JsonReply);
  rpc ResolveIdentity (Pid)        returns (JsonReply);
  rpc ReloadPolicy    (Empty)      returns (JsonReply);
  rpc ValidatePolicy  (Empty)      returns (JsonReply);
  rpc DiffPolicy      (Empty)      returns (JsonReply);
  rpc FlushPolicy     (Empty)      returns (JsonReply);
  rpc Rollback        (Revision)   returns (JsonReply);
  rpc SetMode         (Mode)       returns (JsonReply);
  rpc Shutdown        (Empty)      returns (JsonReply);
  rpc Ping            (Empty)      returns (JsonReply);
}
```

The full `.proto` is served at `GET /v1/proto`, generated from the same table
that dispatches the calls — so the schema a client generates from cannot describe
a method the server does not implement.

## Why every reply is `JsonReply`

```protobuf
message JsonReply { string json = 1; }
```

A typed message per response would mean the same payload described twice — once
in protobuf, once in the JSON the REST API and the CLI already return — and two
descriptions of one thing drift.

Returning the JSON verbatim means all three surfaces answer identically by
construction. A client that wants types generates them from the JSON; a client
that wants gRPC's transport gets it without a second schema to keep in step.

## Wire format

```
┌──────┬──────────────┬─────────────┐
│ flag │  length u32  │   payload   │
│  u8  │   big-endian │             │
└──────┴──────────────┴─────────────┘
  0x00 = message, 0x80 = trailers
```

Status arrives in the trailers frame:

```
grpc-status: 0
grpc-message: OK
```

`Content-Type: application/grpc-web+proto`.

## Status mapping

| gRPC | When |
| --- | --- |
| `0 OK` | |
| `3 INVALID_ARGUMENT` | Malformed request |
| `5 NOT_FOUND` | No such rule, revision or method |
| `7 PERMISSION_DENIED` | Insufficient authority |
| `14 UNAVAILABLE` | No policy installed, or the kernel is unreachable |
| `16 UNAUTHENTICATED` | Missing or bad token |

Authentication and authority are identical to REST: the same `Bearer` token, the
same `Router`, the same authority check.

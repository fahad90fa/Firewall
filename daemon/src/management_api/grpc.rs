//! gRPC surface, spoken as gRPC-Web over HTTP/1.1.
//!
//! # Why gRPC-Web and not HTTP/2 gRPC
//!
//! Wire-level gRPC requires HTTP/2: HPACK, flow control, stream multiplexing,
//! settings negotiation. That is a large, stateful protocol implementation,
//! and putting one in front of an interface that can rewrite the firewall
//! policy — in a workspace that deliberately takes no dependencies — is a poor
//! trade.
//!
//! gRPC-Web carries the same protobuf messages, the same service and method
//! naming, and the same status trailers over HTTP/1.1. Every mainstream gRPC
//! client library can speak it, usually by flipping one flag, and `grpcurl`
//! speaks it directly. So callers get gRPC semantics and this crate keeps a
//! framing layer that is a few hundred lines.
//!
//! The service definition lives in `docs/api/grpc_api.md` and is reproduced by
//! [`PROTO`] below so the two cannot drift.
//!
//! # Framing
//!
//! ```text
//!   request  : [1-byte flags][4-byte big-endian length][protobuf message]
//!   response : [1-byte flags][4-byte big-endian length][protobuf message]
//!              [0x80        ][4-byte big-endian length][trailers as text]
//! ```
//!
//! Flags bit 7 marks a trailer frame. Status travels in the trailers, which is
//! why a gRPC call can return `200 OK` at the HTTP layer and still be a
//! failure.

use ufw_shared::json::JsonWriter;

use super::{ApiError, Authority, Request, Response, Router};

/// The service definition. Kept here so a change to the wire format and a
/// change to the published `.proto` are the same edit.
pub const PROTO: &str = r#"syntax = "proto3";
package ufw.v1;

// Every operation the management plane exposes. The REST surface routes onto
// exactly the same set, so the two cannot diverge.
service Firewall {
  rpc Status          (Empty)          returns (JsonReply);
  rpc Stats           (Empty)          returns (JsonReply);
  rpc ListRules       (RuleFilter)     returns (JsonReply);
  rpc GetRule         (RuleKey)        returns (JsonReply);
  rpc ListRevisions   (Empty)          returns (JsonReply);
  rpc ListTrust       (Empty)          returns (JsonReply);
  rpc ListSignatures  (Empty)          returns (JsonReply);
  rpc ResolveIdentity (Pid)            returns (JsonReply);
  rpc ReloadPolicy    (Empty)          returns (JsonReply);
  rpc ValidatePolicy  (Empty)          returns (JsonReply);
  rpc DiffPolicy      (Empty)          returns (JsonReply);
  rpc FlushPolicy     (Empty)          returns (JsonReply);
  rpc Rollback        (Revision)       returns (JsonReply);
  rpc SetMode         (Mode)           returns (JsonReply);
  rpc Shutdown        (Empty)          returns (JsonReply);
  rpc Ping            (Empty)          returns (JsonReply);
}

message Empty {}
message RuleFilter { string filter = 1; }
message RuleKey    { string key = 1; }
message Pid        { uint32 pid = 1; }
message Revision   { uint64 revision = 1; }
message Mode       { string mode = 1; }

// Responses carry the same JSON the REST surface returns. Modelling every
// reply as a protobuf message would mean maintaining two schemas for one set
// of answers; carrying the JSON means a gRPC client and a REST client see
// byte-identical payloads.
message JsonReply  { string json = 1; }
"#;

/// gRPC status codes used by this service.
pub mod status {
    pub const OK: u32 = 0;
    pub const INVALID_ARGUMENT: u32 = 3;
    pub const NOT_FOUND: u32 = 5;
    pub const PERMISSION_DENIED: u32 = 7;
    pub const UNAUTHENTICATED: u32 = 16;
    pub const FAILED_PRECONDITION: u32 = 9;
    pub const INTERNAL: u32 = 13;
    pub const UNAVAILABLE: u32 = 14;

    /// Map an HTTP status onto the gRPC code with the same meaning.
    pub fn from_http(http: u16) -> u32 {
        match http {
            200 => OK,
            400 | 413 => INVALID_ARGUMENT,
            401 => UNAUTHENTICATED,
            403 => PERMISSION_DENIED,
            404 => NOT_FOUND,
            405 => INVALID_ARGUMENT,
            409 => FAILED_PRECONDITION,
            503 => UNAVAILABLE,
            _ => INTERNAL,
        }
    }
}

// ===========================================================================
// Protobuf wire format
// ===========================================================================

/// Field wire types this codec handles.
const WIRE_VARINT: u8 = 0;
const WIRE_LEN: u8 = 2;

/// Encode a base-128 varint.
pub fn encode_varint(value: u64, out: &mut Vec<u8>) {
    let mut v = value;
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Decode a base-128 varint, returning the value and how many bytes it used.
pub fn decode_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        // Ten groups of seven bits is the most a u64 can hold; anything longer
        // is malformed and must not shift into oblivion.
        if i >= 10 {
            return None;
        }
        value |= ((b & 0x7F) as u64) << (7 * i);
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

/// Encode a `string` field.
pub fn encode_string_field(field: u32, value: &str, out: &mut Vec<u8>) {
    if value.is_empty() {
        // proto3 omits default values.
        return;
    }
    encode_varint(((field as u64) << 3) | WIRE_LEN as u64, out);
    encode_varint(value.len() as u64, out);
    out.extend_from_slice(value.as_bytes());
}

/// Encode a numeric field.
pub fn encode_varint_field(field: u32, value: u64, out: &mut Vec<u8>) {
    if value == 0 {
        return;
    }
    encode_varint(((field as u64) << 3) | WIRE_VARINT as u64, out);
    encode_varint(value, out);
}

/// A decoded protobuf message: field number to value.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Fields {
    pub strings: Vec<(u32, String)>,
    pub numbers: Vec<(u32, u64)>,
}

impl Fields {
    pub fn string(&self, field: u32) -> Option<&str> {
        self.strings
            .iter()
            .find(|(f, _)| *f == field)
            .map(|(_, v)| v.as_str())
    }

    pub fn number(&self, field: u32) -> Option<u64> {
        self.numbers.iter().find(|(f, _)| *f == field).map(|(_, v)| *v)
    }
}

/// Decode a protobuf message, skipping fields this service does not define.
///
/// Skipping unknown fields is what proto3 requires, and it is what lets a
/// newer client talk to an older daemon without either side being rebuilt.
pub fn decode_message(mut bytes: &[u8]) -> Result<Fields, ApiError> {
    let mut out = Fields::default();
    while !bytes.is_empty() {
        let (tag, n) = decode_varint(bytes).ok_or_else(|| ApiError::bad_request("bad tag"))?;
        bytes = &bytes[n..];
        let field = (tag >> 3) as u32;
        match (tag & 0x07) as u8 {
            WIRE_VARINT => {
                let (v, n) =
                    decode_varint(bytes).ok_or_else(|| ApiError::bad_request("bad varint"))?;
                bytes = &bytes[n..];
                out.numbers.push((field, v));
            }
            WIRE_LEN => {
                let (len, n) =
                    decode_varint(bytes).ok_or_else(|| ApiError::bad_request("bad length"))?;
                bytes = &bytes[n..];
                let len = len as usize;
                if len > bytes.len() {
                    return Err(ApiError::bad_request("length-delimited field runs past the end"));
                }
                let text = std::str::from_utf8(&bytes[..len])
                    .map_err(|_| ApiError::bad_request("field is not valid UTF-8"))?;
                out.strings.push((field, text.to_string()));
                bytes = &bytes[len..];
            }
            1 => {
                // 64-bit fixed: not used by this service, but skippable.
                if bytes.len() < 8 {
                    return Err(ApiError::bad_request("truncated fixed64"));
                }
                bytes = &bytes[8..];
            }
            5 => {
                if bytes.len() < 4 {
                    return Err(ApiError::bad_request("truncated fixed32"));
                }
                bytes = &bytes[4..];
            }
            other => {
                return Err(ApiError::bad_request(format!("wire type {other} is not supported")))
            }
        }
    }
    Ok(out)
}

// ===========================================================================
// gRPC-Web framing
// ===========================================================================

/// Marks a trailer frame.
pub const FLAG_TRAILER: u8 = 0x80;

/// Wrap a message in a data frame.
pub fn frame_message(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 5);
    out.push(0);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Build the trailer frame carrying the gRPC status.
pub fn frame_trailers(code: u32, message: &str) -> Vec<u8> {
    // Trailer values are ASCII; a status message with a newline would forge a
    // trailer, so it is flattened.
    let sanitized = message.replace(['\r', '\n'], " ");
    let text = format!("grpc-status:{code}\r\ngrpc-message:{sanitized}\r\n");
    let mut out = Vec::with_capacity(text.len() + 5);
    out.push(FLAG_TRAILER);
    out.extend_from_slice(&(text.len() as u32).to_be_bytes());
    out.extend_from_slice(text.as_bytes());
    out
}

/// Unwrap a single data frame.
pub fn unframe_message(body: &[u8]) -> Result<&[u8], ApiError> {
    if body.len() < 5 {
        return Err(ApiError::bad_request("gRPC-Web frame is too short"));
    }
    if body[0] & FLAG_TRAILER != 0 {
        return Err(ApiError::bad_request("expected a data frame, got trailers"));
    }
    let len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    if 5 + len > body.len() {
        return Err(ApiError::bad_request("gRPC-Web frame length exceeds the body"));
    }
    Ok(&body[5..5 + len])
}

// ===========================================================================
// Method dispatch
// ===========================================================================

/// Map a `/ufw.v1.Firewall/Method` path and its message onto a [`Request`].
pub fn route(path: &str, message: &Fields) -> Result<Request, ApiError> {
    let method = path
        .rsplit('/')
        .next()
        .filter(|m| !m.is_empty())
        .ok_or_else(|| ApiError::not_found("missing method"))?;

    if !path.contains("/ufw.v1.Firewall/") {
        return Err(ApiError::not_found(format!("unknown service in `{path}`")));
    }

    Ok(match method {
        "Status" => Request::Status,
        "Stats" => Request::Stats,
        "ListRules" => Request::ListRules {
            filter: message.string(1).map(str::to_string).filter(|s| !s.is_empty()),
        },
        "GetRule" => Request::GetRule {
            key: message
                .string(1)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| ApiError::bad_request("RuleKey.key is required"))?
                .to_string(),
        },
        "ListRevisions" => Request::ListRevisions,
        "ListTrust" => Request::ListTrust,
        "ListSignatures" => Request::ListSignatures,
        "ResolveIdentity" => Request::ResolveIdentity {
            pid: message
                .number(1)
                .ok_or_else(|| ApiError::bad_request("Pid.pid is required"))?
                as u32,
        },
        "ReloadPolicy" => Request::ReloadPolicy,
        "ValidatePolicy" => Request::ValidatePolicy,
        "DiffPolicy" => Request::DiffPolicy,
        "FlushPolicy" => Request::FlushPolicy,
        "Rollback" => Request::Rollback {
            revision: message
                .number(1)
                .ok_or_else(|| ApiError::bad_request("Revision.revision is required"))?,
        },
        "SetMode" => {
            let text = message
                .string(1)
                .ok_or_else(|| ApiError::bad_request("Mode.mode is required"))?;
            Request::SetMode {
                mode: ufw_shared::protocol::EnforcementMode::parse(text).ok_or_else(|| {
                    ApiError::bad_request(format!("`{text}` is not an enforcement mode"))
                })?,
            }
        }
        "Shutdown" => Request::Shutdown,
        "Ping" => Request::Ping,
        other => return Err(ApiError::not_found(format!("unknown method `{other}`"))),
    })
}

/// Encode a `JsonReply`.
pub fn encode_reply(json: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(json.len() + 8);
    encode_string_field(1, json, &mut payload);
    payload
}

/// Serve one gRPC-Web call: body in, `(http status, headers, body)` out.
pub fn handle(
    router: &Router,
    path: &str,
    body: &[u8],
    authority: Authority,
) -> (u16, Vec<(&'static str, String)>, Vec<u8>) {
    let outcome = (|| -> Result<Response, ApiError> {
        let payload = unframe_message(body)?;
        let message = decode_message(payload)?;
        let request = route(path, &message)?;
        router.dispatch(request, authority)
    })();

    let (code, message, json) = match outcome {
        Ok(response) => (status::OK, String::new(), response.body),
        Err(e) => (
            status::from_http(e.status),
            e.message.clone(),
            e.to_json(),
        ),
    };

    let mut out = frame_message(&encode_reply(&json));
    out.extend_from_slice(&frame_trailers(code, &message));

    // gRPC always answers 200 at the HTTP layer; the real status is in the
    // trailers. A client that reads the HTTP code instead is misreading the
    // protocol, but a proxy in between must still pass the body through.
    (
        200,
        vec![
            ("Content-Type", "application/grpc-web+proto".to_string()),
            ("grpc-status", code.to_string()),
        ],
        out,
    )
}

/// The service description, for a discovery endpoint.
pub fn service_json() -> String {
    let mut w = JsonWriter::new();
    w.begin_object();
    w.str_field("service", "ufw.v1.Firewall");
    w.str_field("protocol", "grpc-web+proto over HTTP/1.1");
    w.str_field("proto", PROTO);
    w.end_object();
    w.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::management_api::tests::harness;

    fn call(payload: Vec<u8>) -> Vec<u8> {
        frame_message(&payload)
    }

    fn string_message(field: u32, value: &str) -> Vec<u8> {
        let mut out = Vec::new();
        encode_string_field(field, value, &mut out);
        out
    }

    fn number_message(field: u32, value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        encode_varint_field(field, value, &mut out);
        out
    }

    /// Pull the JSON out of a framed reply.
    fn reply_json(body: &[u8]) -> String {
        let payload = unframe_message(body).unwrap();
        let fields = decode_message(payload).unwrap();
        fields.string(1).unwrap_or_default().to_string()
    }

    fn trailers(body: &[u8]) -> String {
        // Skip the data frame, then read the trailer frame.
        let len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
        let rest = &body[5 + len..];
        assert_eq!(rest[0], FLAG_TRAILER);
        let tlen = u32::from_be_bytes([rest[1], rest[2], rest[3], rest[4]]) as usize;
        String::from_utf8(rest[5..5 + tlen].to_vec()).unwrap()
    }

    #[test]
    fn varints_round_trip_including_boundaries() {
        for value in [0u64, 1, 127, 128, 300, u32::MAX as u64, u64::MAX] {
            let mut out = Vec::new();
            encode_varint(value, &mut out);
            assert_eq!(decode_varint(&out), Some((value, out.len())), "for {value}");
        }
    }

    #[test]
    fn a_malformed_varint_does_not_run_away() {
        // Continuation bits with no terminator.
        assert_eq!(decode_varint(&[0x80; 20]), None);
        assert_eq!(decode_varint(&[]), None);
    }

    #[test]
    fn messages_round_trip() {
        let mut bytes = Vec::new();
        encode_string_field(1, "allow-dns", &mut bytes);
        encode_varint_field(2, 4242, &mut bytes);
        let fields = decode_message(&bytes).unwrap();
        assert_eq!(fields.string(1), Some("allow-dns"));
        assert_eq!(fields.number(2), Some(4242));
    }

    #[test]
    fn proto3_default_values_are_omitted() {
        let mut bytes = Vec::new();
        encode_string_field(1, "", &mut bytes);
        encode_varint_field(2, 0, &mut bytes);
        assert!(bytes.is_empty());
        assert_eq!(decode_message(&bytes).unwrap(), Fields::default());
    }

    #[test]
    fn unknown_fields_are_skipped_not_rejected() {
        // A newer client sending a field this daemon does not know must still
        // be understood.
        let mut bytes = Vec::new();
        encode_string_field(1, "dns", &mut bytes);
        encode_varint_field(99, 7, &mut bytes);
        // A fixed32 in a field this service never defines.
        encode_varint(((7u64) << 3) | 5, &mut bytes);
        bytes.extend_from_slice(&[1, 2, 3, 4]);

        let fields = decode_message(&bytes).unwrap();
        assert_eq!(fields.string(1), Some("dns"));
        assert_eq!(fields.number(99), Some(7));
    }

    #[test]
    fn truncated_messages_are_rejected() {
        // A length prefix that claims more than is there.
        let mut bytes = Vec::new();
        encode_varint((1 << 3) | 2, &mut bytes);
        encode_varint(100, &mut bytes);
        bytes.extend_from_slice(b"short");
        assert!(decode_message(&bytes).is_err());
    }

    #[test]
    fn framing_round_trips() {
        let framed = frame_message(b"payload");
        assert_eq!(framed[0], 0);
        assert_eq!(unframe_message(&framed).unwrap(), b"payload");
    }

    #[test]
    fn framing_rejects_short_and_overlong_frames() {
        assert!(unframe_message(b"abc").is_err());
        let mut bad = vec![0u8];
        bad.extend_from_slice(&999u32.to_be_bytes());
        bad.extend_from_slice(b"short");
        assert!(unframe_message(&bad).is_err());
    }

    #[test]
    fn a_trailer_frame_is_not_mistaken_for_data() {
        let trailer = frame_trailers(status::OK, "");
        assert!(unframe_message(&trailer).is_err());
    }

    #[test]
    fn status_messages_cannot_forge_a_trailer() {
        let frame = frame_trailers(status::INTERNAL, "line one\r\ngrpc-status:0");
        let text = String::from_utf8(frame[5..].to_vec()).unwrap();
        // Exactly one trailer *line* declares a status. The injected text
        // survives as part of the message, flattened onto one line, where it
        // cannot be read as a trailer of its own.
        assert_eq!(
            text.lines().filter(|l| l.starts_with("grpc-status")).count(),
            1
        );
        assert_eq!(text.lines().count(), 2);
        assert!(text.contains("grpc-status:13"));
    }

    #[test]
    fn methods_route_onto_the_shared_request_set() {
        let cases: [(&str, Vec<u8>, Request); 5] = [
            ("/ufw.v1.Firewall/Status", vec![], Request::Status),
            (
                "/ufw.v1.Firewall/ListRules",
                string_message(1, "dns"),
                Request::ListRules { filter: Some("dns".into()) },
            ),
            (
                "/ufw.v1.Firewall/GetRule",
                string_message(1, "allow-dns"),
                Request::GetRule { key: "allow-dns".into() },
            ),
            (
                "/ufw.v1.Firewall/Rollback",
                number_message(1, 7),
                Request::Rollback { revision: 7 },
            ),
            (
                "/ufw.v1.Firewall/SetMode",
                string_message(1, "monitor"),
                Request::SetMode {
                    mode: ufw_shared::protocol::EnforcementMode::Monitor,
                },
            ),
        ];
        for (path, payload, expected) in cases {
            let fields = decode_message(&payload).unwrap();
            assert_eq!(route(path, &fields).unwrap(), expected, "for {path}");
        }
    }

    #[test]
    fn an_unknown_method_or_service_is_not_found() {
        let empty = Fields::default();
        assert_eq!(
            route("/ufw.v1.Firewall/Teleport", &empty).unwrap_err().status,
            404
        );
        assert_eq!(route("/other.Service/Status", &empty).unwrap_err().status, 404);
    }

    #[test]
    fn required_arguments_are_enforced() {
        let empty = Fields::default();
        for method in ["GetRule", "Rollback", "SetMode", "ResolveIdentity"] {
            let err = route(&format!("/ufw.v1.Firewall/{method}"), &empty).unwrap_err();
            assert_eq!(err.status, 400, "{method} should require an argument");
        }
    }

    #[test]
    fn a_successful_call_returns_status_zero_and_the_shared_json() {
        let h = harness();
        let (http, headers, body) = handle(
            &h.router,
            "/ufw.v1.Firewall/Status",
            &call(vec![]),
            Authority::ReadOnly,
        );
        assert_eq!(http, 200);
        assert!(headers
            .iter()
            .any(|(k, v)| *k == "Content-Type" && v.contains("grpc-web")));
        assert!(trailers(&body).contains("grpc-status:0"));

        let json = reply_json(&body);
        let v = ufw_shared::json::parse(&json).unwrap();
        assert_eq!(v.get("host_id").unwrap().as_str(), Some("host-a"));
    }

    #[test]
    fn a_forbidden_call_maps_onto_permission_denied() {
        let h = harness();
        let (_, _, body) = handle(
            &h.router,
            "/ufw.v1.Firewall/FlushPolicy",
            &call(vec![]),
            Authority::ReadOnly,
        );
        let t = trailers(&body);
        assert!(t.contains(&format!("grpc-status:{}", status::PERMISSION_DENIED)), "{t}");
        assert!(t.contains("administrative authority"));
    }

    #[test]
    fn http_statuses_map_onto_the_matching_grpc_codes() {
        assert_eq!(status::from_http(200), status::OK);
        assert_eq!(status::from_http(403), status::PERMISSION_DENIED);
        assert_eq!(status::from_http(401), status::UNAUTHENTICATED);
        assert_eq!(status::from_http(404), status::NOT_FOUND);
        assert_eq!(status::from_http(409), status::FAILED_PRECONDITION);
        assert_eq!(status::from_http(503), status::UNAVAILABLE);
        assert_eq!(status::from_http(500), status::INTERNAL);
    }

    #[test]
    fn the_published_proto_names_every_routed_method() {
        // A method that exists in the router but not in the .proto would be
        // undiscoverable; one in the .proto but not the router would 404.
        for method in [
            "Status",
            "Stats",
            "ListRules",
            "GetRule",
            "ListRevisions",
            "ListTrust",
            "ListSignatures",
            "ResolveIdentity",
            "ReloadPolicy",
            "ValidatePolicy",
            "DiffPolicy",
            "FlushPolicy",
            "Rollback",
            "SetMode",
            "Shutdown",
            "Ping",
        ] {
            assert!(PROTO.contains(&format!("rpc {method} ")), "{method} missing from PROTO");
            // Values valid for every method that takes an argument, so this
            // checks routing rather than validation.
            let fields = Fields {
                strings: vec![(1, "monitor".into())],
                numbers: vec![(1, 1)],
            };
            assert!(
                route(&format!("/ufw.v1.Firewall/{method}"), &fields).is_ok(),
                "{method} is in PROTO but not routed"
            );
        }
    }

    #[test]
    fn the_service_description_is_valid_json() {
        let v = ufw_shared::json::parse(&service_json()).unwrap();
        assert_eq!(v.get("service").unwrap().as_str(), Some("ufw.v1.Firewall"));
        assert!(v.get("proto").unwrap().as_str().unwrap().contains("service Firewall"));
    }
}

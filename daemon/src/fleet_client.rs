//! Sender-side fleet distribution.
//!
//! [`fleet`](crate::fleet) is the *receive* side: a host authenticates a bundle
//! pushed to it and installs it. This is the *send* side: a daemon acting as a
//! distribution point signs a bundle once and posts it to each member's
//! `/v1/fleet/push`. The two halves share the same [`Bundle`] and [`Verifier`],
//! so a bundle this module signs is exactly what a member's
//! `install_bundle` authenticates — the signature is over the bundle content,
//! not the recipient, so one signing serves the whole fleet.
//!
//! The network is behind [`BundlePoster`] so the distribution loop — the part
//! with the interesting behaviour (sign once, fan out, collect outcomes) — is
//! tested without a socket.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use ufw_shared::hash;
use ufw_shared::json::JsonWriter;

use crate::fleet::{Bundle, Verifier};

/// The outcome of pushing a bundle to one member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberResult {
    pub member: String,
    pub ok: bool,
    /// HTTP status, or 0 when the request never completed.
    pub status: u16,
    pub detail: String,
}

/// Posts a signed bundle body to a member. Abstracted so the fan-out is
/// testable without a network.
pub trait BundlePoster {
    fn post(&self, member: &str, body: &str) -> MemberResult;
}

/// Sign `bundle` once and post it to every member, collecting per-member
/// outcomes. The signature covers the bundle, not the recipient, so all
/// members receive the identical signed body.
pub fn distribute(
    verifier: &Verifier,
    mut bundle: Bundle,
    members: &[String],
    poster: &dyn BundlePoster,
) -> Vec<MemberResult> {
    verifier.sign(&mut bundle);
    let body = push_body(&bundle);
    members.iter().map(|m| poster.post(m, &body)).collect()
}

/// The JSON body a member's `/v1/fleet/push` expects: a `fleet-push` op with
/// the bundle fields and the MAC as hex.
pub fn push_body(b: &Bundle) -> String {
    let mut w = JsonWriter::new();
    w.begin_object();
    w.str_field("op", "fleet-push");
    w.u64_field("revision", b.revision);
    w.str_field("source", &b.source);
    w.u64_field("canary_percent", b.canary_percent as u64);
    w.u64_field("canary_seconds", b.canary_seconds);
    w.str_field("mac", &hash::hex(&b.mac));
    // Carry the Ed25519 signature when the bundle was signed with one, so the
    // public-key check survives the hop to each member. Omitted when empty, so
    // an HMAC-only fleet's wire format is unchanged.
    if !b.sig_ed25519.is_empty() {
        w.str_field("sig_ed25519", &hash::hex(&b.sig_ed25519));
    }
    w.end_object();
    w.finish()
}

/// Summarise the fan-out as JSON for the management response.
pub fn results_json(revision: u64, results: &[MemberResult]) -> String {
    let installed = results.iter().filter(|r| r.ok).count();
    let mut w = JsonWriter::with_capacity(2048);
    w.begin_object();
    w.bool_field("ok", true);
    w.u64_field("revision", revision);
    w.u64_field("members", results.len() as u64);
    w.u64_field("accepted", installed as u64);
    w.begin_array_field("results");
    for r in results {
        w.begin_object();
        w.str_field("member", &r.member);
        w.bool_field("ok", r.ok);
        w.u64_field("status", r.status as u64);
        w.str_field("detail", &r.detail);
        w.end_object();
    }
    w.end_array();
    w.end_object();
    w.finish()
}

/// A real HTTP/1.1 poster over plaintext TCP. TLS termination, where a member's
/// management API is on a routable address, is expected at a proxy in front of
/// it — the same posture the daemon's own REST server takes.
pub struct HttpPoster {
    pub auth_token: Option<String>,
    pub timeout: Duration,
}

impl BundlePoster for HttpPoster {
    fn post(&self, member: &str, body: &str) -> MemberResult {
        match self.try_post(member, body) {
            Ok((status, detail)) => MemberResult {
                member: member.to_string(),
                ok: (200..300).contains(&status),
                status,
                detail,
            },
            Err(e) => MemberResult {
                member: member.to_string(),
                ok: false,
                status: 0,
                detail: e,
            },
        }
    }
}

impl HttpPoster {
    fn try_post(&self, member: &str, body: &str) -> Result<(u16, String), String> {
        let mut stream = TcpStream::connect(member).map_err(|e| format!("connect failed: {e}"))?;
        let _ = stream.set_read_timeout(Some(self.timeout));
        let _ = stream.set_write_timeout(Some(self.timeout));
        let auth = self
            .auth_token
            .as_ref()
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        let request = format!(
            "POST /v1/fleet/push HTTP/1.1\r\nHost: {member}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\
             {auth}Connection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("write failed: {e}"))?;
        let mut resp = Vec::new();
        stream
            .read_to_end(&mut resp)
            .map_err(|e| format!("read failed: {e}"))?;
        parse_http_response(&resp)
    }
}

fn parse_http_response(bytes: &[u8]) -> Result<(u16, String), String> {
    let text = String::from_utf8_lossy(bytes);
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| "no HTTP status line in response".to_string())?;
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.trim().to_string())
        .unwrap_or_default();
    Ok((status, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A poster that records what it was asked to send and returns a scripted
    /// status per member.
    struct MockPoster {
        seen: RefCell<Vec<(String, String)>>,
        status_for: fn(&str) -> u16,
    }

    impl BundlePoster for MockPoster {
        fn post(&self, member: &str, body: &str) -> MemberResult {
            self.seen
                .borrow_mut()
                .push((member.to_string(), body.to_string()));
            let status = (self.status_for)(member);
            MemberResult {
                member: member.to_string(),
                ok: (200..300).contains(&status),
                status,
                detail: String::new(),
            }
        }
    }

    fn bundle() -> Bundle {
        Bundle {
            revision: 7,
            source: "version: 1\nrules: []\n".into(),
            canary_percent: 100,
            canary_seconds: 0,
            mac: [0u8; 32],
            sig_ed25519: Vec::new(),
        }
    }

    #[test]
    fn distribute_signs_once_and_posts_the_same_body_to_every_member() {
        let verifier = Verifier::new(b"a-32-byte-fleet-secret-key-000000".to_vec());
        let poster = MockPoster {
            seen: RefCell::new(Vec::new()),
            status_for: |_| 200,
        };
        let members = vec!["10.0.0.1:8080".to_string(), "10.0.0.2:8080".to_string()];

        let results = distribute(&verifier, bundle(), &members, &poster);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.ok));

        let seen = poster.seen.borrow();
        assert_eq!(seen.len(), 2);
        // The identical signed body reaches both members, and it carries a mac
        // the receive side would accept.
        assert_eq!(seen[0].1, seen[1].1);
        assert!(seen[0].1.contains("\"op\":\"fleet-push\""));
        assert!(seen[0].1.contains("\"mac\":"));
        // The signed bundle round-trips through the receive-side verifier.
        let signed = signed_bundle(&verifier);
        assert!(verifier.accept(&signed, 0).is_ok());
    }

    #[test]
    fn a_member_that_rejects_is_reported_without_failing_the_others() {
        let verifier = Verifier::new(b"a-32-byte-fleet-secret-key-000000".to_vec());
        let poster = MockPoster {
            seen: RefCell::new(Vec::new()),
            status_for: |m| if m.contains("10.0.0.2") { 409 } else { 200 },
        };
        let members = vec![
            "10.0.0.1:8080".to_string(),
            "10.0.0.2:8080".to_string(),
            "10.0.0.3:8080".to_string(),
        ];

        let results = distribute(&verifier, bundle(), &members, &poster);
        assert_eq!(results.iter().filter(|r| r.ok).count(), 2);
        let rejected = results.iter().find(|r| !r.ok).unwrap();
        assert_eq!(rejected.member, "10.0.0.2:8080");
        assert_eq!(rejected.status, 409);

        let json = results_json(7, &results);
        assert!(json.contains("\"accepted\":2"));
    }

    fn signed_bundle(v: &Verifier) -> Bundle {
        let mut b = bundle();
        v.sign(&mut b);
        b
    }

    #[test]
    fn an_http_response_is_parsed_for_status_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}";
        let (status, body) = parse_http_response(raw).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, "{\"ok\":true}");
    }
}

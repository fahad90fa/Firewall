//! HTTP/1.1 REST surface.
//!
//! A hand-written server, for the same reason as everything else in this
//! workspace: the management plane can rewrite the firewall policy, so its
//! attack surface is worth keeping small and readable. What it supports is
//! exactly what the API needs — `GET` and `POST`, a bounded request line, a
//! bounded header block, `Content-Length` bodies, and `Connection: close`.
//!
//! What it deliberately does not support is the interesting half of the CVE
//! history: chunked transfer encoding, pipelining, `Transfer-Encoding` at all,
//! header continuation lines, and keep-alive. Every one of those is a
//! request-smuggling primitive, and none of them is needed to answer
//! `GET /v1/status`.
//!
//! # Guards
//!
//! * The request line and each header are length-capped, so a client cannot
//!   make the server allocate by sending a very long line.
//! * The body is capped by configuration and by `Content-Length`, whichever is
//!   smaller, and a `Content-Length` larger than the cap is rejected before a
//!   byte is read.
//! * A read timeout means a client that opens a connection and stops talking
//!   releases the worker thread rather than holding it forever.
//! * A bearer token is required unless the listener is on loopback *and* no
//!   token is configured, and the source address must pass the allow-list.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

use crate::config::ApiConfig;
use crate::state::DaemonState;

use super::{parse_body, token_matches, ApiError, Authority, Request, Response, Router};

/// Longest request line accepted.
const MAX_REQUEST_LINE: usize = 8 * 1024;
/// Longest single header line accepted.
const MAX_HEADER_LINE: usize = 8 * 1024;
/// Most headers accepted.
const MAX_HEADERS: usize = 64;
/// How long a client may take to send its request.
const READ_TIMEOUT: Duration = Duration::from_secs(15);
const WRITE_TIMEOUT: Duration = Duration::from_secs(15);

/// The fleet dashboard, embedded so the daemon serves it with no external file.
const DASHBOARD_HTML: &str = include_str!("dashboard.html");

/// A parsed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl HttpRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// One query parameter, percent-decoded.
    pub fn param(&self, name: &str) -> Option<String> {
        let query = self.query.as_deref()?;
        query.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k == name).then(|| percent_decode(v))
        })
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Read and parse one request.
pub fn read_request<R: Read>(stream: R, max_body: usize) -> Result<HttpRequest, ApiError> {
    let mut reader = BufReader::new(stream);

    let mut line = String::new();
    read_line(&mut reader, &mut line, MAX_REQUEST_LINE)?;
    let mut parts = line.trim_end().split(' ');
    let method = parts
        .next()
        .ok_or_else(|| ApiError::bad_request("empty request line"))?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| ApiError::bad_request("missing request target"))?
        .to_string();
    let version = parts.next().unwrap_or("HTTP/1.1");
    if !version.starts_with("HTTP/1.") {
        return Err(ApiError::bad_request("only HTTP/1.x is supported"));
    }

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (target, None),
    };

    let mut headers = Vec::new();
    loop {
        let mut header = String::new();
        read_line(&mut reader, &mut header, MAX_HEADER_LINE)?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if headers.len() >= MAX_HEADERS {
            return Err(ApiError::bad_request("too many headers"));
        }
        // A leading space is a header continuation, which this server does not
        // accept; ambiguity about where a header ends is how smuggling starts.
        if header.starts_with(' ') || header.starts_with('\t') {
            return Err(ApiError::bad_request(
                "header continuation lines are not supported",
            ));
        }
        let (name, value) = header
            .split_once(':')
            .ok_or_else(|| ApiError::bad_request("malformed header"))?;
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }

    if headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"))
    {
        return Err(ApiError::bad_request(
            "Transfer-Encoding is not supported; send Content-Length",
        ));
    }

    let declared = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.parse::<usize>())
        .transpose()
        .map_err(|_| ApiError::bad_request("malformed Content-Length"))?
        .unwrap_or(0);

    if declared > max_body {
        return Err(ApiError {
            status: 413,
            message: format!("body exceeds {max_body} bytes"),
        });
    }

    let mut body = vec![0u8; declared];
    if declared > 0 {
        reader
            .read_exact(&mut body)
            .map_err(|e| ApiError::bad_request(format!("truncated body: {e}")))?;
    }
    let body =
        String::from_utf8(body).map_err(|_| ApiError::bad_request("body is not valid UTF-8"))?;

    Ok(HttpRequest {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn read_line<R: BufRead>(reader: &mut R, out: &mut String, max: usize) -> Result<(), ApiError> {
    let mut buf = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        match reader.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                if buf.len() >= max {
                    return Err(ApiError::bad_request("line too long"));
                }
                buf.push(byte[0]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ApiError::bad_request(format!("read failed: {e}"))),
        }
    }
    *out = String::from_utf8_lossy(&buf).into_owned();
    Ok(())
}

/// Map an HTTP method and path onto a [`Request`].
///
/// The route table is explicit rather than pattern-matched so that adding an
/// endpoint is a visible change and a read-only verb cannot drift onto a
/// mutating operation.
pub fn route(request: &HttpRequest) -> Result<Request, ApiError> {
    let path = request.path.trim_end_matches('/');
    match (request.method.as_str(), path) {
        ("GET", "/v1/ping") | ("GET", "/healthz") => Ok(Request::Ping),
        ("GET", "/v1/status") => Ok(Request::Status),
        ("GET", "/v1/stats") => Ok(Request::Stats),
        ("GET", "/v1/rules") => Ok(Request::ListRules {
            filter: request.param("filter"),
        }),
        ("GET", "/v1/revisions") => Ok(Request::ListRevisions),
        ("GET", "/v1/trust") => Ok(Request::ListTrust),
        ("GET", "/v1/signatures") => Ok(Request::ListSignatures),
        ("GET", "/v1/fleet") => Ok(Request::FleetStatus),
        ("GET", p) if p.starts_with("/v1/rules/") => Ok(Request::GetRule {
            key: percent_decode(&p["/v1/rules/".len()..]),
        }),
        ("POST", "/v1/policy/reload") => Ok(Request::ReloadPolicy),
        ("POST", "/v1/policy/validate") => Ok(Request::ValidatePolicy),
        ("POST", "/v1/policy/diff") => Ok(Request::DiffPolicy),
        ("POST", "/v1/policy/flush") => Ok(Request::FlushPolicy),
        ("POST", "/v1/policy/rollback") => parse_body(&request.body),
        ("POST", "/v1/signatures/reload") => Ok(Request::ReloadSignatures),
        ("POST", "/v1/fleet/enroll") => parse_body(&request.body),
        ("POST", "/v1/fleet/verify") => parse_body(&request.body),
        ("POST", "/v1/fleet/push") => parse_body(&request.body),
        ("POST", "/v1/mode") => parse_body(&request.body),
        ("POST", "/v1/identity/resolve") => parse_body(&request.body),
        ("POST", "/v1/shutdown") => Ok(Request::Shutdown),
        // A single generic entry point, so a client can use one code path for
        // every operation if it prefers.
        ("POST", "/v1/rpc") => parse_body(&request.body),
        ("GET", _) | ("POST", _) => Err(ApiError::not_found(format!("no route for {path}"))),
        (method, _) => Err(ApiError {
            status: 405,
            message: format!("{method} is not allowed"),
        }),
    }
}

/// Decide what a caller may do.
pub fn authorize(
    config: &ApiConfig,
    peer: IpAddr,
    request: &HttpRequest,
) -> Result<Authority, ApiError> {
    if !config.allow_from.is_empty() && !config.allow_from.contains(&peer) && !peer.is_loopback() {
        return Err(ApiError::forbidden(format!(
            "{peer} is not in api.allow_from"
        )));
    }

    match &config.auth_token {
        Some(expected) => {
            let provided = request
                .header("authorization")
                .and_then(|v| v.strip_prefix("Bearer "))
                .ok_or_else(|| ApiError::unauthorized("a bearer token is required"))?;
            if token_matches(expected, provided.trim()) {
                Ok(Authority::Admin)
            } else {
                Err(ApiError::unauthorized("invalid bearer token"))
            }
        }
        // No token configured. The configuration layer already refuses to bind
        // a non-loopback address in that case, so reaching here means the
        // caller is local.
        None if peer.is_loopback() => Ok(Authority::Admin),
        None => Err(ApiError::unauthorized(
            "no api.auth_token is configured, so only loopback callers are accepted",
        )),
    }
}

/// Serialize a JSON response.
pub fn render_response(status: u16, body: &str) -> Vec<u8> {
    render_response_full(status, body, "application/json", "")
}

/// Serialize a response with an explicit content type. Used by the Prometheus
/// scrape endpoint, which must be `text/plain` — a scraper that receives
/// `application/json` for `/metrics` rejects the target.
pub fn render_response_with(status: u16, body: &str, content_type: &str) -> Vec<u8> {
    render_response_full(status, body, content_type, "")
}

/// Serialize a response with a content type and any extra header lines (each
/// terminated with `\r\n`, or empty). The extra lines are where CORS headers go
/// for the fleet dashboard.
pub fn render_response_full(
    status: u16,
    body: &str,
    content_type: &str,
    extra_headers: &str,
) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let mut out = Vec::with_capacity(body.len() + 256 + extra_headers.len());
    out.extend_from_slice(
        format!(
            "HTTP/1.1 {status} {reason}\r\n\
             Content-Type: {content_type}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: no-store\r\n\
             X-Content-Type-Options: nosniff\r\n\
             {extra_headers}\
             \r\n",
            body.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(body.as_bytes());
    out
}

/// The CORS header lines to grant a browser at `origin` read access to this
/// API, or empty if the origin is not allowed. Empty `allowed` means CORS is
/// off — the default — so a device is not exposed cross-origin until an operator
/// opts in by listing the dashboard's origin.
///
/// The specific origin is echoed rather than `*`, so it composes with the bearer
/// token a cross-origin fetch carries (the wildcard is disallowed alongside
/// credentials) and so a device is only ever readable by the origins named.
pub fn cors_headers(origin: Option<&str>, allowed: &[String]) -> String {
    let Some(origin) = origin else {
        return String::new();
    };
    if allowed.is_empty() {
        return String::new();
    }
    let permitted = allowed.iter().any(|a| a == "*" || a == origin);
    if !permitted {
        return String::new();
    }
    format!(
        "Access-Control-Allow-Origin: {origin}\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: Authorization, Content-Type\r\n\
         Access-Control-Max-Age: 600\r\n\
         Vary: Origin\r\n"
    )
}

/// Handle one connection end to end.
/// Serve one request.
///
/// Generic over the stream so the plaintext and TLS paths are the same code.
/// A separate TLS request loop would be a second copy of the parsing, and the
/// two would drift — which on an HTTP parser means two implementations
/// disagreeing about where a request ends.
pub fn handle_connection<S: Read + Write>(
    router: &Router,
    config: &ApiConfig,
    peer: IpAddr,
    stream: &mut S,
) {
    // Timeouts are set by the caller on the underlying socket, before any TLS
    // wrapping. Setting them here would mean reaching through the wrapper for a
    // property that belongs to the socket, and the handshake itself needs them
    // in place before this function is reached.
    let bytes = match read_request(&mut *stream, config.max_body_bytes) {
        Ok(request) => {
            // CORS is decided from the request's Origin and the allow-list, and
            // attached to every response below.
            let cors = cors_headers(request.header("origin"), &config.cors_origins);
            let path = request.path.trim_end_matches('/');

            if request.method == "OPTIONS" {
                // The browser's cross-origin preflight, before a GET that carries
                // a token. Answered without auth — it is asking whether it may
                // send the real request, and it carries no credentials of its own.
                render_response_full(204, "", "text/plain", &cors)
            } else if request.method == "GET" && matches!(path, "" | "/" | "/dashboard") {
                // The dashboard page: static HTML with no secrets, served without
                // auth so a browser can load it by navigation (which cannot send
                // a bearer token). The DATA it then fetches goes through
                // `authorize` like everything else.
                render_response_full(200, DASHBOARD_HTML, "text/html; charset=utf-8", &cors)
            } else {
                match authorize(config, peer, &request) {
                    // The Prometheus scrape endpoint sits beside the JSON RPC
                    // surface, not inside it: its body is `text/plain`. It is
                    // still gated by the same authorization as `status` — a scrape
                    // reveals traffic counts and process memory.
                    Ok(authority) => {
                        if request.method == "GET" && matches!(path, "/metrics" | "/v1/metrics") {
                            let body = crate::metrics::prometheus(router.state());
                            render_response_full(
                                200,
                                &body,
                                "text/plain; version=0.0.4; charset=utf-8",
                                &cors,
                            )
                        } else {
                            match route(&request).and_then(|op| router.dispatch(op, authority)) {
                                Ok(Response { status, body }) => {
                                    render_response_full(status, &body, "application/json", &cors)
                                }
                                Err(e) => render_response_full(
                                    e.status,
                                    &e.to_json(),
                                    "application/json",
                                    &cors,
                                ),
                            }
                        }
                    }
                    Err(e) => {
                        render_response_full(e.status, &e.to_json(), "application/json", &cors)
                    }
                }
            }
        }
        Err(e) => render_response(e.status, &e.to_json()),
    };
    let _ = stream.write_all(&bytes);
    let _ = stream.flush();
}

/// Run the REST listener until the daemon shuts down.
pub fn serve(
    router: Arc<Router>,
    config: ApiConfig,
    state: Arc<DaemonState>,
) -> std::io::Result<()> {
    let Some(bind) = config.rest_bind.clone() else {
        return Ok(());
    };
    // Built before the listener binds. A certificate that does not load should
    // stop the daemon at startup, not produce a port that accepts connections
    // and fails every one of them.
    let acceptor = if config.tls.is_enabled() {
        Some(
            crate::tls::TlsAcceptor::from_config(&config.tls)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?,
        )
    } else {
        None
    };

    let listener = TcpListener::bind(&bind)?;
    // A short accept timeout is what lets the loop notice a shutdown request
    // without a second wake-up mechanism.
    listener.set_nonblocking(true)?;

    while !state.is_shutting_down() {
        match listener.accept() {
            Ok((stream, addr)) => {
                let _ = stream.set_nonblocking(false);
                // On the raw socket, before any TLS wrapping: the handshake
                // itself needs a deadline, or a client that connects and never
                // sends a ClientHello holds a worker thread forever.
                let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
                let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
                let router = Arc::clone(&router);
                let config = config.clone();
                let peer = normalize_peer(addr);
                let acceptor = acceptor.clone();
                std::thread::Builder::new()
                    .name("ufw-rest".into())
                    .spawn(move || {
                        // The handshake happens on the worker thread, not in
                        // the accept loop. A client that opens a connection and
                        // never sends a ClientHello would otherwise stall every
                        // other caller — which is a denial of service against
                        // the management plane costing one socket.
                        let mut stream = match &acceptor {
                            Some(acceptor) => match acceptor.accept(stream) {
                                Ok(wrapped) => wrapped,
                                Err(_) => return,
                            },
                            None => crate::tls::MaybeTls::Plain(stream),
                        };
                        handle_connection(&router, &config, peer, &mut stream);
                    })
                    .ok();
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
    Ok(())
}

/// Unwrap an IPv4-mapped IPv6 peer address.
///
/// A dual-stack listener reports `127.0.0.1` as `::ffff:127.0.0.1`, which is
/// not `is_loopback()` under the v6 rules and would silently turn a local
/// caller into a rejected one.
pub fn normalize_peer(addr: SocketAddr) -> IpAddr {
    match addr.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        ip => ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::management_api::tests::harness;
    use std::io::Cursor;

    fn config() -> ApiConfig {
        ApiConfig {
            allow_plaintext: false,
            tls: Default::default(),
            cli_socket: "/tmp/ufw.sock".into(),
            rest_bind: Some("127.0.0.1:0".into()),
            grpc_bind: None,
            allow_from: Vec::new(),
            auth_token: None,
            fleet_secret: None,
            max_body_bytes: 64 * 1024,
            cors_origins: Vec::new(),
        }
    }

    fn request(raw: &str) -> Result<HttpRequest, ApiError> {
        read_request(Cursor::new(raw.as_bytes().to_vec()), 64 * 1024)
    }

    fn loopback() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    #[test]
    fn a_simple_get_parses() {
        let r = request("GET /v1/status HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/v1/status");
        assert_eq!(r.header("host"), Some("x"));
        assert!(r.body.is_empty());
    }

    #[test]
    fn a_post_with_a_body_parses() {
        let body = r#"{"op":"status"}"#;
        let raw = format!(
            "POST /v1/rpc HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let r = request(&raw).unwrap();
        assert_eq!(r.body, body);
        assert_eq!(route(&r).unwrap(), Request::Status);
    }

    #[test]
    fn query_parameters_are_decoded() {
        let r = request("GET /v1/rules?filter=allow%2Ddns&x=1 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(r.param("filter").as_deref(), Some("allow-dns"));
        assert_eq!(r.param("missing"), None);
    }

    #[test]
    fn transfer_encoding_is_refused() {
        // Accepting both framings is how request smuggling starts.
        let err =
            request("POST /v1/rpc HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap_err();
        assert_eq!(err.status, 400);
        assert!(err.message.contains("Transfer-Encoding"));
    }

    #[test]
    fn header_continuations_are_refused() {
        let err = request("GET /v1/status HTTP/1.1\r\nHost: a\r\n  continued\r\n\r\n").unwrap_err();
        assert_eq!(err.status, 400);
    }

    #[test]
    fn an_oversized_body_is_rejected_before_it_is_read() {
        let err = read_request(
            Cursor::new(b"POST /v1/rpc HTTP/1.1\r\nContent-Length: 999999\r\n\r\n".to_vec()),
            1024,
        )
        .unwrap_err();
        assert_eq!(err.status, 413);
    }

    #[test]
    fn an_overlong_line_is_rejected() {
        let raw = format!(
            "GET /{} HTTP/1.1\r\n\r\n",
            "a".repeat(MAX_REQUEST_LINE + 10)
        );
        assert_eq!(request(&raw).unwrap_err().status, 400);
    }

    #[test]
    fn too_many_headers_are_rejected() {
        let mut raw = String::from("GET /v1/status HTTP/1.1\r\n");
        for i in 0..(MAX_HEADERS + 5) {
            raw.push_str(&format!("X-{i}: v\r\n"));
        }
        raw.push_str("\r\n");
        assert_eq!(request(&raw).unwrap_err().status, 400);
    }

    #[test]
    fn routes_map_verbs_to_the_right_operations() {
        let cases: [(&str, Request); 6] = [
            ("GET /v1/status HTTP/1.1\r\n\r\n", Request::Status),
            ("GET /healthz HTTP/1.1\r\n\r\n", Request::Ping),
            (
                "GET /v1/rules HTTP/1.1\r\n\r\n",
                Request::ListRules { filter: None },
            ),
            (
                "GET /v1/rules/allow-dns HTTP/1.1\r\n\r\n",
                Request::GetRule {
                    key: "allow-dns".into(),
                },
            ),
            (
                "POST /v1/policy/reload HTTP/1.1\r\n\r\n",
                Request::ReloadPolicy,
            ),
            ("POST /v1/shutdown HTTP/1.1\r\n\r\n", Request::Shutdown),
        ];
        for (raw, expected) in cases {
            let r = request(raw).unwrap();
            assert_eq!(route(&r).unwrap(), expected, "for {raw:?}");
        }
    }

    #[test]
    fn a_mutating_operation_is_not_reachable_by_get() {
        let r = request("GET /v1/policy/reload HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(route(&r).unwrap_err().status, 404);
    }

    #[test]
    fn an_unknown_method_is_405() {
        let r = request("DELETE /v1/rules/a HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(route(&r).unwrap_err().status, 405);
    }

    #[test]
    fn loopback_without_a_token_is_admin() {
        let r = request("GET /v1/status HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(
            authorize(&config(), loopback(), &r).unwrap(),
            Authority::Admin
        );
    }

    #[test]
    fn a_remote_caller_without_a_token_is_refused() {
        let r = request("GET /v1/status HTTP/1.1\r\n\r\n").unwrap();
        let err = authorize(&config(), "203.0.113.9".parse().unwrap(), &r).unwrap_err();
        assert_eq!(err.status, 401);
    }

    #[test]
    fn a_bearer_token_is_required_and_checked_when_configured() {
        let mut c = config();
        c.auth_token = Some("0123456789abcdef0123456789abcdef".into());
        let remote: IpAddr = "203.0.113.9".parse().unwrap();

        let no_token = request("GET /v1/status HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(authorize(&c, remote, &no_token).unwrap_err().status, 401);

        let wrong = request(
            "GET /v1/status HTTP/1.1\r\nAuthorization: Bearer wrongwrongwrongwrongwrongwrong12\r\n\r\n",
        )
        .unwrap();
        assert_eq!(authorize(&c, remote, &wrong).unwrap_err().status, 401);

        let right = request(
            "GET /v1/status HTTP/1.1\r\nAuthorization: Bearer 0123456789abcdef0123456789abcdef\r\n\r\n",
        )
        .unwrap();
        assert_eq!(authorize(&c, remote, &right).unwrap(), Authority::Admin);
    }

    #[test]
    fn the_allow_list_is_enforced_for_remote_callers() {
        let mut c = config();
        c.auth_token = Some("0123456789abcdef0123456789abcdef".into());
        c.allow_from = vec!["198.51.100.4".parse().unwrap()];

        let r = request(
            "GET /v1/status HTTP/1.1\r\nAuthorization: Bearer 0123456789abcdef0123456789abcdef\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            authorize(&c, "203.0.113.9".parse().unwrap(), &r)
                .unwrap_err()
                .status,
            403
        );
        assert!(authorize(&c, "198.51.100.4".parse().unwrap(), &r).is_ok());
        // Loopback is always permitted so an operator is never locked out of
        // the box they are standing on.
        assert!(authorize(&c, loopback(), &r).is_ok());
    }

    #[test]
    fn a_dual_stack_loopback_peer_is_recognized() {
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:5000".parse().unwrap();
        assert!(normalize_peer(mapped).is_loopback());
        let real_v6: SocketAddr = "[2001:db8::1]:5000".parse().unwrap();
        assert!(!normalize_peer(real_v6).is_loopback());
    }

    #[test]
    fn responses_carry_a_length_and_close_the_connection() {
        let bytes = render_response(200, r#"{"ok":true}"#);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Length: 11\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        assert!(text.contains("X-Content-Type-Options: nosniff\r\n"));
        assert!(text.ends_with("\r\n\r\n{\"ok\":true}"));
    }

    #[test]
    fn a_full_round_trip_answers_status() {
        let h = harness();
        let r = request("GET /v1/status HTTP/1.1\r\n\r\n").unwrap();
        let authority = authorize(&config(), loopback(), &r).unwrap();
        let response = h.router.dispatch(route(&r).unwrap(), authority).unwrap();
        let v = ufw_shared::json::parse(&response.body).unwrap();
        assert_eq!(v.get("host_id").unwrap().as_str(), Some("host-a"));
    }

    /// A read/write pair over in-memory buffers, so a full `handle_connection`
    /// can be exercised without a socket.
    struct MockStream {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn the_metrics_endpoint_serves_a_prometheus_exposition() {
        let h = harness();
        let mut stream = MockStream {
            input: Cursor::new(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n".to_vec()),
            output: Vec::new(),
        };
        handle_connection(&h.router, &config(), loopback(), &mut stream);
        let text = String::from_utf8_lossy(&stream.output);

        // A scraper rejects the target unless the body is text/plain.
        assert!(
            text.contains("Content-Type: text/plain"),
            "wrong content type in:\n{text}"
        );
        // The exposition itself is present and well-formed.
        assert!(text.contains("# TYPE ufw_up gauge\r\n") || text.contains("# TYPE ufw_up gauge\n"));
        assert!(text.contains("ufw_up 1"));
        assert!(text.contains("ufw_watchdog_state{state=\"nominal\"} 1"));
    }

    #[test]
    fn the_metrics_endpoint_is_not_reachable_by_post() {
        // Read-only surface: POST must fall through to the JSON router, which has
        // no such route, rather than silently scraping.
        let r = request("POST /metrics HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(route(&r).unwrap_err().status, 404);
    }

    fn serve(config: &ApiConfig, raw: &str) -> String {
        let h = harness();
        let mut stream = MockStream {
            input: Cursor::new(raw.as_bytes().to_vec()),
            output: Vec::new(),
        };
        handle_connection(&h.router, config, loopback(), &mut stream);
        String::from_utf8_lossy(&stream.output).into_owned()
    }

    #[test]
    fn the_dashboard_is_served_at_root_and_dashboard() {
        for path in ["/", "/dashboard"] {
            let text = serve(
                &config(),
                &format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n"),
            );
            assert!(
                text.starts_with("HTTP/1.1 200 OK\r\n"),
                "{path}: {}",
                &text[..40]
            );
            assert!(
                text.contains("Content-Type: text/html"),
                "{path} content type"
            );
            assert!(text.contains("Unified Firewall"), "{path} body content");
        }
    }

    #[test]
    fn cors_headers_respect_the_allow_list() {
        let allow = vec!["https://dash.example".to_string()];
        assert!(cors_headers(Some("https://dash.example"), &allow)
            .contains("Access-Control-Allow-Origin: https://dash.example"));
        // Off by default (empty list), unlisted origin, and no origin: all empty.
        assert!(cors_headers(Some("https://dash.example"), &[]).is_empty());
        assert!(cors_headers(Some("https://evil.example"), &allow).is_empty());
        assert!(cors_headers(None, &allow).is_empty());
        // A wildcard echoes the specific origin, never a bare "*" — which would
        // be rejected alongside the bearer token a fetch carries.
        let star = vec!["*".to_string()];
        let h = cors_headers(Some("https://anything"), &star);
        assert!(h.contains("Access-Control-Allow-Origin: https://anything"));
        assert!(!h.contains("Allow-Origin: *"));
    }

    #[test]
    fn a_listed_origin_is_granted_cors_and_a_preflight() {
        let mut cfg = config();
        cfg.cors_origins = vec!["https://dash.example".to_string()];

        // The preflight is answered 204 with the grant, without auth.
        let pre = serve(
            &cfg,
            "OPTIONS /v1/status HTTP/1.1\r\nOrigin: https://dash.example\r\n\r\n",
        );
        assert!(
            pre.starts_with("HTTP/1.1 204 No Content\r\n"),
            "{}",
            &pre[..40]
        );
        assert!(pre.contains("Access-Control-Allow-Origin: https://dash.example"));

        // The real GET carries the grant too (loopback, so authorized).
        let get = serve(
            &cfg,
            "GET /v1/status HTTP/1.1\r\nOrigin: https://dash.example\r\n\r\n",
        );
        assert!(get.contains("Access-Control-Allow-Origin: https://dash.example"));

        // An origin not on the list gets no grant — so the browser refuses to
        // read the response, which is the point.
        let denied = serve(
            &cfg,
            "GET /v1/status HTTP/1.1\r\nOrigin: https://evil.example\r\n\r\n",
        );
        assert!(!denied.contains("Access-Control-Allow-Origin"));
    }

    #[test]
    fn cors_is_absent_by_default() {
        // Default config lists no origins, so even a well-formed Origin gets no
        // CORS grant: a device is not cross-origin readable until an operator
        // opts in.
        let text = serve(
            &config(),
            "GET /v1/status HTTP/1.1\r\nOrigin: https://dash.example\r\n\r\n",
        );
        assert!(!text.contains("Access-Control-Allow-Origin"));
    }
}

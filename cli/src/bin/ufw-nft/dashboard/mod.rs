//! The live enforcement console: one embedded page, one JSON endpoint.
//!
//! `GET /` serves the self-contained HTML console; `GET /api/state` returns
//! everything it renders: the loaded ruleset with counters, the parsed
//! denied/alerted packet history, attack classification, and this host's
//! listeners and connections. The server is std-only — TcpListener, a
//! thread per connection — in keeping with the workspace's zero-dependency
//! rule, and read-only by design: there is no endpoint that mutates
//! anything. It binds loopback unless told otherwise and says so loudly
//! when told otherwise.

mod attacks;
mod beacon;
mod bounded;
mod contain;
mod daemon;
mod events;
mod exposure;
mod features;
mod fleet;
mod honeypot;
mod ids;
mod lint;
mod network;
mod pcap;
mod ports;
mod rbac;
mod respond;
mod ruleset;
mod services;
mod threatintel;
mod tls;

use std::io::{Read, Write};
use std::net::TcpListener;

pub use tls::TlsOptions;

use ufw_shared::json::JsonWriter;

use crate::state;

const PAGE: &str = include_str!("page.html");
const MAX_EVENTS: usize = 2000;

pub fn serve(bind: &str, tls_opts: &TlsOptions) -> Result<(), String> {
    // Validate the TLS request before binding, and refuse rather than serve
    // plaintext on a port the operator believes is encrypted.
    tls_opts.validate()?;
    if tls_opts.is_enabled() && !tls::available() {
        return Err(tls::unavailable_message());
    }
    let acceptor = if tls_opts.is_enabled() {
        Some(tls::Acceptor::from_options(tls_opts)?)
    } else {
        None
    };

    let listener =
        TcpListener::bind(bind).map_err(|e| format!("could not listen on {bind}: {e}"))?;
    let local = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| bind.into());

    let scheme = if acceptor.is_some() { "https" } else { "http" };
    println!("dashboard: {scheme}://{local}/");
    println!("  live rules, denied packets, attack analysis, listeners; read-only.");
    if acceptor.is_some() {
        println!(
            "  \u{1f512} TLS on, with mTLS: a client certificate that chains to your --tls-client-ca\n     \
             is mapped to an RBAC role by its SHA-256 fingerprint (console-auth.json)."
        );
    } else if !local.starts_with("127.") && !local.starts_with("[::1]") {
        println!(
            "  \u{26a0} bound to a non-loopback address without TLS: anyone who can reach {local}\n     \
             can read this host's firewall state, and only loopback callers may act. Consider\n     \
             --tls-cert/--tls-key/--tls-client-ca (needs a --features tls build) or an SSH tunnel."
        );
    }
    if !is_root() {
        println!(
            "  \u{26a0} not running as root: nft and the kernel log are likely unreadable,\n     \
             so the page will show errors instead of live data. Run with sudo."
        );
    }
    if respond::is_enabled() {
        println!("  auto-response: ENABLED — matching sources will be contained automatically.");
    }
    println!("  stop: Ctrl-C");

    // The adaptive auto-response engine: a slow background loop that classifies
    // the live denial stream and applies opt-in containment playbooks. It reads
    // nothing expensive while disabled, so it is free until an operator turns it
    // on from the console.
    std::thread::spawn(auto_response_loop);

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let acceptor = acceptor.clone();
                std::thread::spawn(move || {
                    // Wrap in TLS if configured; a handshake failure (a probe, a
                    // client with no ClientHello) closes this one connection
                    // without disturbing the accept loop.
                    let stream = match &acceptor {
                        Some(a) => match a.accept(s) {
                            Ok(w) => w,
                            Err(_) => return,
                        },
                        None => tls::Stream::Plain(s),
                    };
                    let _ = handle(stream);
                });
            }
            // Back off briefly on a transient accept error (e.g. momentary fd
            // exhaustion) so the loop degrades gracefully instead of spinning
            // the CPU while descriptors free up.
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
        }
    }
    Ok(())
}

fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .map(|s| s.lines().any(|l| l.starts_with("Uid:\t0\t")))
        .unwrap_or(false)
}

/// How often the auto-response engine re-evaluates the denial stream. Slow on
/// purpose: containment is not latency-critical and the log read is bounded.
const RESPOND_INTERVAL_SECS: u64 = 12;

fn auto_response_loop() {
    loop {
        std::thread::sleep(std::time::Duration::from_secs(RESPOND_INTERVAL_SECS));
        // Cheap gate: while the engine is off we do not even read the log.
        if !respond::is_enabled() {
            continue;
        }
        let (events, _errors) = events::collect(MAX_EVENTS);
        let attacks = attacks::classify(&events);
        respond::tick(&attacks);
    }
}

fn handle(mut stream: tls::Stream) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    // A write timeout too: without one, respond()'s write_all can block forever
    // on a client that stops reading, pinning the thread and its fd.
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(10)));
    // Who is calling — the mutating actions are gated by role, of which loopback
    // is the weakest source.
    // The completed-handshake source address. `from_loopback` gates the mutating
    // actions; `peer_ip` is also the (non-spoofable, post-accept) source a
    // honeypot decoy hit records and may auto-contain.
    // Canonicalize an IPv4-mapped IPv6 peer (`::ffff:127.0.0.1`) to its IPv4
    // form before any loopback/public classification. On a dual-stack bind a
    // v4 client is reported in mapped form, and `Ipv6Addr::is_loopback()` is
    // true only for `::1` — so without this a genuine loopback caller would be
    // demoted below admin, and a LAN source would look public to the honeypot.
    let peer_ip = stream.peer_addr().ok().map(|p| canonical_ip(p.ip()));
    let from_loopback = peer_ip.map(|ip| ip.is_loopback()).unwrap_or(false);
    let mut buf = [0u8; 4096];
    let mut head = Vec::new();
    // Read until the end of the request head; the request has no body we care
    // about, and 16 KiB is far beyond any GET we serve. A read timeout or an
    // idle client stops the read cleanly rather than dropping the connection
    // with no response — the poll should degrade to an error, never hang.
    let head_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let n = match stream.read(&mut buf) {
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break
            }
            Err(e) => return Err(e),
        };
        if n == 0 {
            break;
        }
        head.extend_from_slice(&buf[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") || head.len() > 16 * 1024 {
            break;
        }
        if std::time::Instant::now() >= head_deadline {
            break;
        }
    }
    // A client that connected but sent nothing (a browser preconnect, a probe):
    // close quietly rather than treating an empty head as a request for "/".
    if head.is_empty() {
        return Ok(());
    }
    let request = String::from_utf8_lossy(&head);
    // The caller's credentials, strongest first (see rbac.rs):
    //   * a verified client-certificate fingerprint — available only now that
    //     the head has been read and the TLS handshake has therefore completed;
    //   * an `Authorization: Bearer <token>` header.
    // Either resolves to a role via console-auth.json; otherwise loopback decides.
    let cert_fp = stream.client_fingerprint();
    let token = rbac::bearer(&request);
    let mut line0 = request.lines().next().unwrap_or("").split_whitespace();
    let method = line0.next().unwrap_or("GET");
    let target = line0.next().unwrap_or("/");
    let (route, query) = target.split_once('?').unwrap_or((target, ""));
    let user_agent = request
        .lines()
        .find_map(|l| {
            l.strip_prefix("User-Agent:")
                .or_else(|| l.strip_prefix("user-agent:"))
        })
        .map(str::trim)
        .unwrap_or("");

    // Canary honeytoken replay: this token only ever lived in a FAKE decoy page,
    // so its arrival as a real bearer credential proves the decoy was scraped and
    // the "secret" exfiltrated. Record it (highest-signal event) and reject —
    // never let it authenticate, whatever route it is presented to.
    if let Some(t) = token.as_deref() {
        if honeypot::is_canary(t) {
            honeypot::record_hit(
                peer_ip,
                cert_fp.as_deref(),
                route,
                user_agent,
                "canary-replay",
            );
            return respond(
                &mut stream,
                401,
                "application/json",
                "{\"error\":\"invalid token\"}",
            );
        }
    }

    match (method, route) {
        (_, "/") | (_, "/index.html") => {
            respond(&mut stream, 200, "text/html; charset=utf-8", PAGE)
        }
        (_, "/api/state") => {
            let body = state_json();
            respond(&mut stream, 200, "application/json", &body)
        }
        ("GET", "/api/features") => {
            // The "what's new" page: recently-added capabilities and, where the
            // host can tell, their live status. Read-only, so not gated.
            let body = features::features_json(cert_fp.is_some());
            respond(&mut stream, 200, "application/json", &body)
        }
        ("GET", "/api/whoami") => {
            // The caller's resolved role and its capability map, so a role-aware
            // console can disable actions this caller may not perform. Reading is
            // open to everyone, so this endpoint is not itself gated.
            let role = rbac::role_for(from_loopback, token.as_deref(), cert_fp.as_deref());
            let mut w = JsonWriter::with_capacity(200);
            w.begin_object();
            w.str_field("role", rbac::role_name(role));
            w.bool_field("from_loopback", from_loopback);
            // Report the identity source so the console can show how the caller
            // was authenticated (a pinned cert, a token, or just loopback).
            w.opt_str_field("client_cert", cert_fp.as_deref());
            w.begin_object_field("can");
            for (name, action) in rbac::ALL_ACTIONS {
                w.bool_field(name, rbac::allows(role, action));
            }
            w.end_object();
            w.end_object();
            respond(&mut stream, 200, "application/json", &w.finish())
        }
        ("GET", "/api/stream") => {
            // Server-Sent Events: push a snapshot on the cadence the client asks
            // for, until it disconnects. The write timeout set on the socket is
            // the safety valve — a client that stops reading frees the thread.
            let ms = qget(query, "ms")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(3000)
                .clamp(1000, 30000);
            stream_sse(&mut stream, ms)
        }
        (_, "/api/network") => {
            // Discovery is passive by default; a scan is opt-in via ?scan=1.
            let active = query
                .split('&')
                .any(|kv| kv == "scan=1" || kv == "scan=true");
            let body = network_json(active);
            respond(&mut stream, 200, "application/json", &body)
        }
        ("GET", "/api/ptr") => {
            // Reverse-DNS for the incident dossier — a name lookup, nothing more.
            let ip = qget(query, "ip").unwrap_or_default();
            let name = contain::reverse_dns(&ip);
            let mut w = JsonWriter::with_capacity(128);
            w.begin_object();
            w.opt_str_field("ptr", name.as_deref());
            w.end_object();
            respond(&mut stream, 200, "application/json", &w.finish())
        }
        ("POST", "/api/contain") | ("POST", "/api/release") => {
            // A mutating surface. Authorize by role: loopback (or a responder/
            // admin token) may contain; a bare remote caller is read-only, so an
            // exposed dashboard can never be used to inject blocks remotely.
            if !rbac::authorize(
                from_loopback,
                token.as_deref(),
                cert_fp.as_deref(),
                rbac::Action::Contain,
            ) {
                return respond(
                    &mut stream,
                    403,
                    "application/json",
                    "{\"ok\":false,\"error\":\"containment requires responder or admin (loopback, or a bearer token)\"}",
                );
            }
            let ip = qget(query, "ip").unwrap_or_default();
            let result = if route == "/api/contain" {
                let ttl = qget(query, "ttl")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(3600);
                contain::contain(&ip, ttl)
            } else {
                contain::release(&ip)
            };
            let mut w = JsonWriter::with_capacity(160);
            w.begin_object();
            match &result {
                Ok(()) => w.bool_field("ok", true),
                Err(e) => {
                    w.bool_field("ok", false);
                    w.str_field("error", e);
                }
            }
            w.end_object();
            respond(&mut stream, 200, "application/json", &w.finish())
        }
        (_, "/api/fleet") => {
            let body = fleet::fleet_json();
            respond(&mut stream, 200, "application/json", &body)
        }
        ("GET", "/api/pcap") => {
            // Bounded packet capture for the dossier — mutating-adjacent (spawns
            // tcpdump as root), so it is the most privileged action: admin only.
            if !rbac::authorize(
                from_loopback,
                token.as_deref(),
                cert_fp.as_deref(),
                rbac::Action::Capture,
            ) {
                return respond(
                    &mut stream,
                    403,
                    "application/json",
                    "{\"ok\":false,\"error\":\"packet capture requires admin (loopback, or an admin bearer token)\"}",
                );
            }
            let ip = qget(query, "ip").unwrap_or_default();
            let n = qget(query, "n")
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(200);
            match pcap::capture(&ip, n) {
                Ok(bytes) => respond_pcap(&mut stream, &ip, &bytes),
                Err(e) => {
                    let mut w = JsonWriter::with_capacity(160);
                    w.begin_object();
                    w.bool_field("ok", false);
                    w.str_field("error", &e);
                    w.end_object();
                    respond(&mut stream, 200, "application/json", &w.finish())
                }
            }
        }
        ("GET", "/api/autoresponse") => {
            let body = respond::config_json();
            respond(&mut stream, 200, "application/json", &body)
        }
        ("POST", "/api/autoresponse") | ("POST", "/api/autoresponse/rule") => {
            // Mutating configuration: admin only (loopback or an admin token).
            if !rbac::authorize(
                from_loopback,
                token.as_deref(),
                cert_fp.as_deref(),
                rbac::Action::Configure,
            ) {
                return respond(
                    &mut stream,
                    403,
                    "application/json",
                    "{\"ok\":false,\"error\":\"changing auto-response requires admin (loopback, or an admin bearer token)\"}",
                );
            }
            let ok = if route == "/api/autoresponse" {
                match qget(query, "enabled") {
                    Some(v) => respond::set_enabled(is_truthy(&v)).is_ok(),
                    None => false,
                }
            } else {
                match qget(query, "id") {
                    Some(id) => respond::update_rule(
                        &id,
                        qget(query, "enabled").map(|v| is_truthy(&v)),
                        qget(query, "min_severity"),
                        qget(query, "min_count").and_then(|v| v.parse().ok()),
                        qget(query, "min_ports").and_then(|v| v.parse().ok()),
                        qget(query, "public_only").map(|v| is_truthy(&v)),
                        qget(query, "known_bad_only").map(|v| is_truthy(&v)),
                        qget(query, "base_ttl").and_then(|v| v.parse().ok()),
                        qget(query, "escalate").map(|v| is_truthy(&v)),
                    ),
                    None => false,
                }
            };
            let body = format!("{{\"ok\":{ok}}}");
            respond(&mut stream, 200, "application/json", &body)
        }
        ("GET", "/api/honeypot") => {
            // Read-only trap log for the "Traps" page; not gated.
            let body = honeypot::honeypot_json();
            respond(&mut stream, 200, "application/json", &body)
        }
        ("POST", "/api/honeypot/contain") => {
            // Toggling opt-in honeypot auto-contain is admin-only.
            if !rbac::authorize(
                from_loopback,
                token.as_deref(),
                cert_fp.as_deref(),
                rbac::Action::Configure,
            ) {
                return respond(
                    &mut stream,
                    403,
                    "application/json",
                    "{\"ok\":false,\"error\":\"changing honeypot auto-contain requires admin (loopback, or an admin bearer token)\"}",
                );
            }
            let ok = match qget(query, "enabled") {
                Some(v) => honeypot::set_contain_enabled(is_truthy(&v)).is_ok(),
                None => false,
            };
            respond(
                &mut stream,
                200,
                "application/json",
                &format!("{{\"ok\":{ok}}}"),
            )
        }
        // Decoy routes ("dashboard traps"): any hit is an intruder. Matched last,
        // just before 404, so a real route always wins. Ungated by design — the
        // point is to answer an unauthenticated prober with a convincing fake
        // while recording (and, if opted in, containing) the handshake-proven source.
        _ if honeypot::is_decoy(route) => {
            honeypot::record_hit(
                peer_ip,
                cert_fp.as_deref(),
                route,
                user_agent,
                "decoy-route",
            );
            let (ctype, body) = honeypot::fake_body(route);
            respond(&mut stream, 200, ctype, &body)
        }
        _ => respond(&mut stream, 404, "text/plain", "not found\n"),
    }
}

/// A query flag is true unless it is explicitly a false-ish value.
fn is_truthy(v: &str) -> bool {
    !matches!(v, "0" | "false" | "no" | "off" | "")
}

/// Read a single query-string value, percent-decoded. IPs sent by the page are
/// `encodeURIComponent`-escaped (v6 colons become `%3A`), so decode before use.
fn qget(query: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix(&prefix))
        .map(percent_decode)
}

fn percent_decode(s: &str) -> String {
    // Decode over bytes, never by slicing the &str: `s` comes from
    // `String::from_utf8_lossy`, so it can carry multi-byte characters, and
    // `&s[i+1..i+3]` on a boundary that falls inside one panics — which, under
    // `panic = "abort"`, would take the whole dashboard down from one crafted
    // request. Building a byte buffer and decoding it back with
    // `from_utf8_lossy` cannot panic on any input.
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 3 <= b.len() {
            let hi = (b[i + 1] as char).to_digit(16);
            let lo = (b[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Fold an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) down to its IPv4 form.
///
/// A dual-stack listener reports an IPv4 client as `::ffff:<v4>`, which is not
/// `is_loopback()`/`is_private()` under the v6 rules — so loopback and
/// LAN/CGNAT classification must be done on the canonical address, or a local
/// caller looks remote and a private source looks public. (Kept here rather
/// than using the still-unstable `IpAddr::to_canonical` so the MSRV holds.)
pub fn canonical_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => std::net::IpAddr::V4(v4),
            None => std::net::IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Server-Sent Events stream of state snapshots. Runs until the client goes
/// away (a write error), at which point the thread returns and its fd closes.
/// `state_json()` emits a single line, so each snapshot is one SSE `data:` frame.
fn stream_sse<W: Write>(stream: &mut W, interval_ms: u64) -> std::io::Result<()> {
    let head = "HTTP/1.1 200 OK\r\n\
         Content-Type: text/event-stream\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n";
    stream.write_all(head.as_bytes())?;
    // A comment line tells EventSource to keep the connection open immediately.
    stream.write_all(b": ufw-nft live stream\n\n")?;
    loop {
        let body = state_json();
        stream.write_all(b"data: ")?;
        stream.write_all(body.as_bytes())?;
        stream.write_all(b"\n\n")?;
        stream.flush()?;
        std::thread::sleep(std::time::Duration::from_millis(interval_ms));
    }
}

/// A binary download response (a captured pcap). Separate from `respond`, which
/// is text-only, because the body is raw bytes and carries a download filename.
fn respond_pcap<W: Write>(stream: &mut W, ip: &str, bytes: &[u8]) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/vnd.tcpdump.pcap\r\n\
         Content-Length: {}\r\n\
         Content-Disposition: attachment; filename=\"{}\"\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        bytes.len(),
        pcap::filename(ip)
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(bytes)
}

fn respond<W: Write>(stream: &mut W, code: u16, ctype: &str, body: &str) -> std::io::Result<()> {
    let reason = match code {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: {ctype}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())
}

/// Assemble everything the page renders. Every data source is allowed to
/// fail individually; failures land in `errors` instead of taking the whole
/// endpoint down.
fn state_json() -> String {
    let rs = ruleset::load();
    let exposure = exposure::analyze(&rs);
    let (events, mut errors) = events::collect(MAX_EVENTS);
    let attacks = attacks::classify(&events);
    let feeds = threatintel::load();
    let (listeners, conns, svc_errors) = services::snapshot();
    errors.extend(svc_errors);
    if let Some(e) = &rs.error {
        errors.push(e.clone());
    }
    let st = state::load();
    let descriptions: std::collections::BTreeMap<&str, &str> = st
        .as_ref()
        .map(|s| {
            s.descriptions
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect()
        })
        .unwrap_or_default();

    let mut w = JsonWriter::with_capacity(64 * 1024);
    w.begin_object();
    w.u64_field("generated_at", state::now_unix());
    w.str_field("host", &hostname());
    w.bool_field("enforced", rs.loaded);

    match &st {
        Some(s) => {
            w.begin_object_field("policy");
            w.str_field("name", &s.policy_name);
            w.str_field("path", &s.policy_path);
            w.u64_field("revision", s.revision);
            w.str_field("mode", &s.mode);
            w.u64_field("applied_at", s.applied_at);
            w.u64_field("trial_secs", s.trial_secs);
            w.bool_field("restrictive", s.restrictive);
            w.end_object();
        }
        None => w.null_field("policy"),
    }

    // --- ruleset ----------------------------------------------------------
    let mut denied_packets = 0u64;
    let mut denied_bytes = 0u64;
    let mut alert_packets = 0u64;
    let mut accepted_packets = 0u64;
    w.begin_array_field("chains");
    for chain in &rs.chains {
        w.begin_object();
        w.str_field("name", &chain.name);
        w.str_field("policy", &chain.policy);
        w.begin_array_field("rules");
        for r in &chain.rules {
            match r.verdict.as_str() {
                "drop" | "reject" => {
                    denied_packets += r.packets;
                    denied_bytes += r.bytes;
                }
                "alert" => alert_packets += r.packets,
                "accept" => accepted_packets += r.packets,
                _ => {}
            }
            w.begin_object();
            w.str_field("name", &r.name);
            w.str_field("matchers", &r.matchers);
            w.str_field("verdict", &r.verdict);
            w.opt_str_field("log_kind", r.log_kind.as_deref());
            w.u64_field("packets", r.packets);
            w.u64_field("bytes", r.bytes);
            w.opt_str_field("why", descriptions.get(r.name.as_str()).copied());
            w.opt_str_field("rate_limit", r.rate_limit.as_deref());
            w.begin_array_field("services");
            let mut seen = std::collections::BTreeSet::new();
            for p in &r.dports {
                if let Some((name, risk)) = ports::lookup(*p) {
                    if seen.insert(name) {
                        w.begin_object();
                        w.u64_field("port", *p as u64);
                        w.str_field("name", name);
                        w.opt_str_field("risk", risk);
                        w.end_object();
                    }
                }
            }
            w.end_array();
            w.end_object();
        }
        w.end_array();
        w.end_object();
    }
    w.end_array();

    // --- events -----------------------------------------------------------
    w.begin_array_field("events");
    for e in &events {
        w.begin_object();
        w.f64_field("ts", e.ts);
        w.str_field("action", &e.action);
        w.opt_str_field("rule", e.rule.as_deref());
        w.opt_str_field(
            "why",
            e.rule.as_deref().and_then(|r| descriptions.get(r).copied()),
        );
        w.str_field("dir", &e.dir);
        w.str_field("iface", &e.iface);
        w.str_field("src", &e.src);
        w.str_field("dst", &e.dst);
        w.str_field("proto", &e.proto);
        match e.spt {
            Some(p) => w.u64_field("spt", p as u64),
            None => w.null_field("spt"),
        }
        match e.dpt {
            Some(p) => {
                w.u64_field("dpt", p as u64);
                w.str_field("service", &ports::label(p));
                if let Some((_, Some(risk))) = ports::lookup(p) {
                    w.str_field("service_risk", risk);
                }
            }
            None => w.null_field("dpt"),
        }
        if let Some(t) = e.icmp_type {
            w.u64_field("icmp_type", t as u64);
        }
        if !e.flags.is_empty() {
            w.str_array_field("flags", e.flags.iter().map(|s| s.as_str()));
        }
        w.end_object();
    }
    w.end_array();

    // --- attacks ----------------------------------------------------------
    w.begin_array_field("attacks");
    for a in &attacks {
        w.begin_object();
        w.str_field("src", &a.src);
        w.str_field("kind", &a.kind);
        w.str_field("severity", &a.severity);
        w.str_field("title", &a.title);
        w.str_field("detail", &a.detail);
        w.u64_field("count", a.count as u64);
        w.str_array_field("ports", a.ports.iter().map(|s| s.as_str()));
        w.f64_field("first_ts", a.first_ts);
        w.f64_field("last_ts", a.last_ts);
        w.str_array_field("rules", a.rules.iter().map(|s| s.as_str()));
        // Threat-intel: label of the first installed feed this source is on.
        w.opt_str_field("known_bad", feeds.lookup(&a.src));
        w.end_object();
    }
    w.end_array();

    // Threat-intel feed status (offline blocklists), for the console.
    w.begin_object_field("threatintel");
    w.u64_field("entries", feeds.entries() as u64);
    w.begin_array_field("sources");
    for (name, count) in &feeds.sources {
        w.begin_object();
        w.str_field("name", name);
        w.u64_field("entries", *count as u64);
        w.end_object();
    }
    w.end_array();
    w.end_object();

    // Honeypot / deception summary (decoy-route + canary-replay traps).
    let (hp_total, hp_recent) = honeypot::summary();
    w.begin_object_field("honeypot");
    w.u64_field("total", hp_total);
    w.u64_field("recent", hp_recent as u64);
    w.bool_field("auto_contain", honeypot::contain_enabled());
    w.end_object();

    // --- exposure (inbound attack surface) --------------------------------
    w.begin_object_field("exposure");
    w.str_field("grade", &exposure.grade);
    w.u64_field("score", exposure.score as u64);
    w.u64_field("open_world", exposure.open_world as u64);
    w.u64_field("scoped", exposure.scoped as u64);
    w.begin_array_field("findings");
    for f in &exposure.findings {
        w.begin_object();
        w.str_field("severity", &f.severity);
        match f.port {
            Some(p) => w.u64_field("port", p as u64),
            None => w.null_field("port"),
        }
        w.str_field("service", &f.service);
        w.str_field("scope", &f.scope);
        w.str_field("title", &f.title);
        w.str_field("detail", &f.detail);
        w.str_field("rule", &f.rule);
        w.u64_field("packets", f.packets);
        w.end_object();
    }
    w.end_array();
    w.end_object();

    // --- host surface -----------------------------------------------------
    w.begin_array_field("listeners");
    for l in &listeners {
        w.begin_object();
        w.str_field("proto", &l.proto);
        w.str_field("addr", &l.addr);
        w.u64_field("port", l.port as u64);
        w.str_field("service", &ports::label(l.port));
        w.opt_str_field("process", l.process.as_deref());
        match l.pid {
            Some(p) => w.u64_field("pid", p as u64),
            None => w.null_field("pid"),
        }
        w.end_object();
    }
    w.end_array();

    w.begin_array_field("connections");
    for c in &conns {
        w.begin_object();
        w.str_field("proto", &c.proto);
        w.str_field("dir", &c.dir);
        w.str_field("local", &c.laddr);
        w.u64_field("lport", c.lport as u64);
        w.str_field("remote", &c.raddr);
        w.u64_field("rport", c.rport as u64);
        w.str_field(
            "service",
            &ports::label(if c.dir == "in" { c.lport } else { c.rport }),
        );
        w.opt_str_field("process", c.process.as_deref());
        w.end_object();
    }
    w.end_array();

    w.begin_object_field("totals");
    w.u64_field("denied_packets", denied_packets);
    w.u64_field("denied_bytes", denied_bytes);
    w.u64_field("alert_packets", alert_packets);
    w.u64_field("accepted_packets", accepted_packets);
    w.u64_field("events", events.len() as u64);
    let attacker_count = attacks
        .iter()
        .filter(|a| a.src != "this host")
        .map(|a| a.src.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len() as u64;
    w.u64_field("attackers", attacker_count);
    w.end_object();

    w.str_array_field("errors", errors.iter().map(|s| s.as_str()));

    // Sources currently contained (blocked at the kernel), with time to auto-expiry.
    let contained_list = contain::list();
    w.begin_array_field("contained");
    for c in &contained_list {
        w.begin_object();
        w.str_field("ip", &c.ip);
        match c.expires_secs {
            Some(s) => w.u64_field("expires_secs", s),
            None => w.null_field("expires_secs"),
        }
        w.end_object();
    }
    w.end_array();

    // Policy-correctness lint findings over the loaded ruleset.
    w.begin_array_field("lint");
    for f in lint::analyze(&rs.chains) {
        w.begin_object();
        w.str_field("severity", &f.severity);
        w.str_field("chain", &f.chain);
        w.str_field("rule", &f.rule);
        w.str_field("kind", &f.kind);
        w.str_field("detail", &f.detail);
        w.end_object();
    }
    w.end_array();

    // Beaconing detection: regular-interval egress callbacks (possible C2).
    w.begin_array_field("beacons");
    for b in beacon::detect(&events) {
        w.begin_object();
        w.str_field("dst", &b.dst);
        w.u64_field("samples", b.samples as u64);
        w.u64_field("period_secs", b.period_secs as u64);
        w.u64_field("jitter_pct", (b.cv * 100.0) as u64);
        w.f64_field("first_ts", b.first_ts);
        w.f64_field("last_ts", b.last_ts);
        w.end_object();
    }
    w.end_array();

    // IDS signature engine: match the operator's ruleset against the event
    // stream (header-field matching; see ids.rs for the honest scope).
    let sigs = ids::load();
    let ids_hits = ids::evaluate(&sigs, &events);
    w.begin_object_field("ids");
    w.u64_field("rules_loaded", sigs.len() as u64);
    w.begin_array_field("hits");
    for h in &ids_hits {
        w.begin_object();
        w.str_field("sid", &h.sid);
        w.str_field("msg", &h.msg);
        w.str_field("severity", &h.severity);
        w.str_field("action", &h.action);
        w.u64_field("count", h.count);
        w.str_array_field("sources", h.sources.iter().map(|s| s.as_str()));
        w.end_object();
    }
    w.end_array();
    w.end_object();

    // Auto-response engine summary, so the console can show a live indicator.
    let ar_enabled = respond::is_enabled();
    w.begin_object_field("autoresponse");
    w.bool_field("enabled", ar_enabled);
    w.u64_field("recent", respond::recent_count() as u64);
    w.end_object();

    // Publish this host's own summary to the fleet directory (throttled), so a
    // synced fleet can be aggregated on the Fleet page.
    fleet::publish_self(
        &hostname(),
        rs.loaded,
        denied_packets,
        attacker_count,
        contained_list.len() as u64,
        ar_enabled,
    );

    // Live daemon / ufw-waf telemetry, best-effort — lights up the DPI, egress
    // anomaly, WAF, fleet and correlation layers when those processes publish it.
    w.raw_field("daemon", &daemon::read_json());

    w.end_object();
    w.finish()
}

/// Assemble the network manager view: the LAN(s) this host is directly
/// connected to and the devices sharing them. `active` runs the bounded
/// sweep; otherwise the passive neighbour-table view is returned instantly.
fn network_json(active: bool) -> String {
    let view = network::snapshot(active);

    let mut w = JsonWriter::with_capacity(32 * 1024);
    w.begin_object();
    w.u64_field("generated_at", state::now_unix());
    w.str_field("host", &hostname());
    w.bool_field("scanned", view.scanned);
    w.u64_field("scan_ms", view.scan_ms);

    w.begin_array_field("subnets");
    for s in &view.subnets {
        w.begin_object();
        w.str_field("iface", &s.iface);
        w.str_field("network", &s.network.to_string());
        w.u64_field("prefix", s.prefix as u64);
        let host_ip = s.host_ip.map(|a| a.to_string());
        w.opt_str_field("host_ip", host_ip.as_deref());
        let gateway = s.gateway.map(|a| a.to_string());
        w.opt_str_field("gateway", gateway.as_deref());
        w.u64_field("host_count", s.host_count());
        w.end_object();
    }
    w.end_array();

    let mut reachable = 0u64;
    let mut with_services = 0u64;
    w.begin_array_field("devices");
    for d in &view.devices {
        if d.reachable {
            reachable += 1;
        }
        if !d.services.is_empty() {
            with_services += 1;
        }
        w.begin_object();
        w.str_field("ip", &d.ip.to_string());
        w.opt_str_field("mac", d.mac.as_deref());
        w.str_field("mac_kind", d.mac_kind);
        w.opt_str_field("vendor", d.vendor.as_deref());
        w.opt_str_field("hostname", d.hostname.as_deref());
        w.str_field("iface", &d.iface);
        w.bool_field("is_gateway", d.is_gateway);
        w.bool_field("is_self", d.is_self);
        w.bool_field("reachable", d.reachable);
        w.str_field("source", d.source);
        w.str_field("role", d.role);
        w.str_field("summary", &d.summary);
        w.begin_array_field("services");
        for svc in &d.services {
            w.begin_object();
            w.u64_field("port", svc.port as u64);
            w.str_field("name", &svc.name);
            w.opt_str_field("risk", svc.risk);
            w.end_object();
        }
        w.end_array();
        w.end_object();
    }
    w.end_array();

    w.begin_object_field("totals");
    w.u64_field("devices", view.devices.len() as u64);
    w.u64_field("reachable", reachable);
    w.u64_field("with_services", with_services);
    w.end_object();

    w.str_array_field("errors", view.errors.iter().map(|s| s.as_str()));
    w.str_array_field("notes", view.notes.iter().map(|s| s.as_str()));
    w.end_object();
    w.finish()
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "this host".into())
}

#[cfg(test)]
mod router_tests {
    use super::*;

    #[test]
    fn percent_decode_never_panics_on_bad_utf8() {
        // The regression: a '%' right before a multi-byte char sliced the &str
        // mid-codepoint and panicked (fatal under panic="abort").
        let _ = percent_decode("%é");
        let _ = percent_decode("%\u{fffd}x");
        let _ = percent_decode("%");
        let _ = percent_decode("%a");
        let _ = percent_decode("ip=%ff%ff");
        // Ordinary decoding still works.
        assert_eq!(percent_decode("a%20b+c"), "a b c");
        assert_eq!(percent_decode("%41%42"), "AB");
        assert_eq!(percent_decode("allow%2Ddns"), "allow-dns");
    }

    #[test]
    fn canonical_ip_unwraps_v4_mapped() {
        use std::net::IpAddr;
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert_eq!(canonical_ip(mapped), "127.0.0.1".parse::<IpAddr>().unwrap());
        assert!(canonical_ip(mapped).is_loopback());
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(canonical_ip(v6), v6);
    }
}

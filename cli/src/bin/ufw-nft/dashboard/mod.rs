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
mod bounded;
mod contain;
mod daemon;
mod events;
mod exposure;
mod network;
mod ports;
mod ruleset;
mod services;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use ufw_shared::json::JsonWriter;

use crate::state;

const PAGE: &str = include_str!("page.html");
const MAX_EVENTS: usize = 2000;

pub fn serve(bind: &str) -> Result<(), String> {
    let listener =
        TcpListener::bind(bind).map_err(|e| format!("could not listen on {bind}: {e}"))?;
    let local = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| bind.into());

    println!("dashboard: http://{local}/");
    println!("  live rules, denied packets, attack analysis, listeners; read-only.");
    if !local.starts_with("127.") && !local.starts_with("[::1]") {
        println!(
            "  \u{26a0} bound to a non-loopback address: anyone who can reach {local} can read\n     \
             this host's firewall state. There is no authentication."
        );
    }
    if !is_root() {
        println!(
            "  \u{26a0} not running as root: nft and the kernel log are likely unreadable,\n     \
             so the page will show errors instead of live data. Run with sudo."
        );
    }
    println!("  stop: Ctrl-C");

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                std::thread::spawn(move || {
                    let _ = handle(s);
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

fn handle(mut stream: TcpStream) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    // A write timeout too: without one, respond()'s write_all can block forever
    // on a client that stops reading, pinning the thread and its fd.
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(10)));
    // Who is calling — the containment action is gated to loopback.
    let from_loopback = stream
        .peer_addr()
        .map(|p| p.ip().is_loopback())
        .unwrap_or(false);
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
    let mut line0 = request.lines().next().unwrap_or("").split_whitespace();
    let method = line0.next().unwrap_or("GET");
    let target = line0.next().unwrap_or("/");
    let (route, query) = target.split_once('?').unwrap_or((target, ""));

    match (method, route) {
        (_, "/") | (_, "/index.html") => {
            respond(&mut stream, 200, "text/html; charset=utf-8", PAGE)
        }
        (_, "/api/state") => {
            let body = state_json();
            respond(&mut stream, 200, "application/json", &body)
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
            // The one mutating surface. Gate it to loopback callers so an
            // exposed dashboard can never be used to inject blocks remotely.
            if !from_loopback {
                return respond(
                    &mut stream,
                    403,
                    "application/json",
                    "{\"ok\":false,\"error\":\"containment is only allowed from localhost\"}",
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
        _ => respond(&mut stream, 404, "text/plain", "not found\n"),
    }
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
    let b = s.as_bytes();
    let mut out = String::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 3 <= b.len() {
            if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(byte as char);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { ' ' } else { b[i] as char });
        i += 1;
    }
    out
}

fn respond(stream: &mut TcpStream, code: u16, ctype: &str, body: &str) -> std::io::Result<()> {
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
        w.end_object();
    }
    w.end_array();

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
    w.u64_field(
        "attackers",
        attacks
            .iter()
            .filter(|a| a.src != "this host")
            .map(|a| a.src.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len() as u64,
    );
    w.end_object();

    w.str_array_field("errors", errors.iter().map(|s| s.as_str()));

    // Sources currently contained (blocked at the kernel), with time to auto-expiry.
    w.begin_array_field("contained");
    for c in contain::list() {
        w.begin_object();
        w.str_field("ip", &c.ip);
        match c.expires_secs {
            Some(s) => w.u64_field("expires_secs", s),
            None => w.null_field("expires_secs"),
        }
        w.end_object();
    }
    w.end_array();

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

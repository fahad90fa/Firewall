//! What this host is actually offering and talking to, from /proc/net.
//!
//! The event log answers "what was denied"; this answers the other half of
//! the user's question — what services are listening, and which connections
//! are live right now. Both come straight from the kernel's own tables
//! (/proc/net/tcp, tcp6, udp, udp6), with socket inodes resolved to the
//! owning process when we have the privilege to look.
//!
//! The hex address encoding in those files is the kernel's in-memory
//! representation printed with %08X per 32-bit word, i.e. little-endian on
//! every platform Linux calls x86 or ARM; the byte swaps below undo that.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

pub struct Listener {
    pub proto: String,
    pub addr: String,
    pub port: u16,
    pub process: Option<String>,
    pub pid: Option<u32>,
}

pub struct Conn {
    pub proto: String,
    /// "in" when the local port is one this host listens on, else "out".
    pub dir: String,
    pub laddr: String,
    pub lport: u16,
    pub raddr: String,
    pub rport: u16,
    pub process: Option<String>,
}

pub fn snapshot() -> (Vec<Listener>, Vec<Conn>, Vec<String>) {
    let mut errors = Vec::new();
    let owners = socket_owners();

    let mut listeners = Vec::new();
    let mut conns = Vec::new();

    for (path, proto, v6) in [
        ("/proc/net/tcp", "tcp", false),
        ("/proc/net/tcp6", "tcp", true),
        ("/proc/net/udp", "udp", false),
        ("/proc/net/udp6", "udp", true),
    ] {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            // A missing tcp6/udp6 table is a host without IPv6, not a
            // problem worth a banner.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && v6 => continue,
            Err(e) => {
                errors.push(format!("{path}: {e}"));
                continue;
            }
        };
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 {
                continue;
            }
            let Some((laddr, lport)) = parse_endpoint(f[1], v6) else {
                continue;
            };
            let Some((raddr, rport)) = parse_endpoint(f[2], v6) else {
                continue;
            };
            let state = f[3];
            let inode: u64 = f[9].parse().unwrap_or(0);
            let owner = owners.get(&inode);

            // TCP 0A = LISTEN; a UDP socket with no peer (07 = TCP_CLOSE in
            // that table's terms) is its listening equivalent.
            let listening = (proto == "tcp" && state == "0A")
                || (proto == "udp" && state == "07" && rport == 0);
            if listening {
                listeners.push(Listener {
                    proto: proto.into(),
                    addr: laddr,
                    port: lport,
                    process: owner.map(|(_, name)| name.clone()),
                    pid: owner.map(|(pid, _)| *pid),
                });
            } else if state == "01" {
                // ESTABLISHED, both families.
                conns.push(Conn {
                    proto: proto.into(),
                    dir: String::new(), // filled below, once listeners are known
                    laddr,
                    lport,
                    raddr,
                    rport,
                    process: owner.map(|(_, name)| name.clone()),
                });
            }
        }
    }

    let listen_ports: std::collections::BTreeSet<(String, u16)> = listeners
        .iter()
        .map(|l| (l.proto.clone(), l.port))
        .collect();
    for c in &mut conns {
        c.dir = if listen_ports.contains(&(c.proto.clone(), c.lport)) {
            "in".into()
        } else {
            "out".into()
        };
    }

    listeners.sort_by(|a, b| (a.port, &a.proto, &a.addr).cmp(&(b.port, &b.proto, &b.addr)));
    listeners.dedup_by(|a, b| a.port == b.port && a.proto == b.proto && a.addr == b.addr);
    conns.truncate(400);
    (listeners, conns, errors)
}

/// `0100007F:0016` → (127.0.0.1, 22); the 32-hex IPv6 form likewise.
fn parse_endpoint(s: &str, v6: bool) -> Option<(String, u16)> {
    let (addr_hex, port_hex) = s.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if v6 {
        if addr_hex.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (i, chunk) in addr_hex.as_bytes().chunks(8).enumerate() {
            let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
            bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        let ip = Ipv6Addr::from(bytes);
        // Dual-stack listeners show as ::ffff:a.b.c.d; print the v4 form
        // people recognize.
        match ip.to_ipv4_mapped() {
            Some(v4) => Some((v4.to_string(), port)),
            None => Some((ip.to_string(), port)),
        }
    } else {
        let word = u32::from_str_radix(addr_hex, 16).ok()?;
        Some((Ipv4Addr::from(word.swap_bytes()).to_string(), port))
    }
}

/// Socket inode → (pid, process name), by walking /proc/*/fd. Needs root to
/// see other users' processes; without it the tables still render, just
/// without process names.
fn socket_owners() -> HashMap<u64, (u32, String)> {
    let mut map = HashMap::new();
    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return map;
    };
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let fd_dir = entry.path().join("fd");
        let Ok(fds) = std::fs::read_dir(&fd_dir) else {
            continue;
        };
        let comm = std::fs::read_to_string(entry.path().join("comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                if let Some(t) = target.to_str() {
                    if let Some(inode) = t
                        .strip_prefix("socket:[")
                        .and_then(|r| r.strip_suffix(']'))
                        .and_then(|n| n.parse::<u64>().ok())
                    {
                        map.entry(inode).or_insert_with(|| (pid, comm.clone()));
                    }
                }
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_endpoints_decode_the_kernels_byte_order() {
        assert_eq!(
            parse_endpoint("0100007F:0016", false),
            Some(("127.0.0.1".into(), 22))
        );
        assert_eq!(
            parse_endpoint("00000000:1F90", false),
            Some(("0.0.0.0".into(), 8080))
        );
    }

    #[test]
    fn v6_endpoints_decode_word_by_word() {
        // :: (all zeros), port 22.
        assert_eq!(
            parse_endpoint("00000000000000000000000000000000:0016", true),
            Some(("::".into(), 22))
        );
        // ::1 — final word 01000000 little-endian.
        assert_eq!(
            parse_endpoint("00000000000000000000000001000000:0035", true),
            Some(("::1".into(), 53))
        );
    }

    #[test]
    fn v4_mapped_v6_prints_as_v4() {
        // ::ffff:127.0.0.1
        let got = parse_endpoint("0000000000000000FFFF00000100007F:0050", true);
        assert_eq!(got, Some(("127.0.0.1".into(), 80)));
    }

    #[test]
    fn a_live_snapshot_does_not_panic_and_dedupes() {
        // Smoke test on whatever /proc this test host has.
        let (listeners, conns, _errors) = snapshot();
        for l in &listeners {
            assert!(!l.proto.is_empty());
        }
        for c in &conns {
            assert!(c.dir == "in" || c.dir == "out");
        }
    }
}

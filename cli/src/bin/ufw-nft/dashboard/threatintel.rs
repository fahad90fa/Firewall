//! Offline threat intelligence: match a source against locally-installed
//! blocklists, with zero network calls.
//!
//! Operators drop plain-text feeds under `/etc/unified-firewall/threat-intel/`
//! — one IP or CIDR per line, `#` for comments, an optional label after the
//! address. Each file's name is the default label ("tor-exit.txt" ->
//! "tor-exit"). The console flags any attacker that appears on a feed, and the
//! auto-response engine can contain known-bad sources outright. Everything is
//! read from disk; nothing is ever fetched.

use std::net::IpAddr;

const DIR: &str = "/etc/unified-firewall/threat-intel";
/// A sanity cap so a pathological feed cannot exhaust memory.
const MAX_ENTRIES: usize = 500_000;

#[derive(Default)]
pub struct Feeds {
    v4: Vec<(u32, u32, String)>,   // (base, mask, label)
    v6: Vec<(u128, u128, String)>, // (base, mask, label)
    /// Feed file -> entry count, for the console's status line.
    pub sources: Vec<(String, usize)>,
}

impl Feeds {
    pub fn entries(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// The label of the first feed that contains `ip`, or None.
    pub fn lookup(&self, ip: &str) -> Option<&str> {
        match ip.parse::<IpAddr>().ok()? {
            IpAddr::V4(a) => {
                let x = u32::from(a);
                self.v4
                    .iter()
                    .find(|(base, mask, _)| x & mask == *base)
                    .map(|(_, _, l)| l.as_str())
            }
            IpAddr::V6(a) => {
                let x = u128::from(a);
                self.v6
                    .iter()
                    .find(|(base, mask, _)| x & mask == *base)
                    .map(|(_, _, l)| l.as_str())
            }
        }
    }
}

/// Load every feed under the threat-intel directory. Missing directory is not
/// an error — it just means no feeds are installed.
pub fn load() -> Feeds {
    let mut feeds = Feeds::default();
    let Ok(entries) = std::fs::read_dir(DIR) else {
        return feeds;
    };
    let mut files: Vec<_> = entries.flatten().map(|e| e.path()).collect();
    files.sort();
    for path in files {
        if !path.is_file() {
            continue;
        }
        let default_label = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("threat")
            .to_string();
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let before = feeds.entries();
        for line in text.lines() {
            if feeds.entries() >= MAX_ENTRIES {
                break;
            }
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut it = line.split_whitespace();
            let Some(cidr) = it.next() else { continue };
            let label = it.next().unwrap_or(&default_label).to_string();
            add_cidr(&mut feeds, cidr, label);
        }
        let added = feeds.entries() - before;
        if added > 0 {
            feeds.sources.push((default_label, added));
        }
    }
    feeds
}

fn add_cidr(feeds: &mut Feeds, cidr: &str, label: String) {
    let (addr_str, prefix) = match cidr.split_once('/') {
        Some((a, p)) => (a, p.parse::<u32>().ok()),
        None => (cidr, None),
    };
    match addr_str.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => {
            let p = prefix.unwrap_or(32);
            if p > 32 {
                return;
            }
            let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
            let base = u32::from(a) & mask;
            feeds.v4.push((base, mask, label));
        }
        Ok(IpAddr::V6(a)) => {
            let p = prefix.unwrap_or(128);
            if p > 128 {
                return;
            }
            let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
            let base = u128::from(a) & mask;
            feeds.v6.push((base, mask, label));
        }
        Err(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feeds_from(lines: &[(&str, &str)]) -> Feeds {
        let mut f = Feeds::default();
        for (cidr, label) in lines {
            add_cidr(&mut f, cidr, label.to_string());
        }
        f
    }

    #[test]
    fn matches_ipv4_cidr() {
        let f = feeds_from(&[("203.0.113.0/24", "badnet")]);
        assert_eq!(f.lookup("203.0.113.9"), Some("badnet"));
        assert_eq!(f.lookup("203.0.114.9"), None);
    }

    #[test]
    fn matches_bare_ipv4() {
        let f = feeds_from(&[("198.51.100.7", "scanner")]);
        assert_eq!(f.lookup("198.51.100.7"), Some("scanner"));
        assert_eq!(f.lookup("198.51.100.8"), None);
    }

    #[test]
    fn matches_ipv6_cidr() {
        let f = feeds_from(&[("2001:db8::/32", "v6bad")]);
        assert_eq!(f.lookup("2001:db8:1234::1"), Some("v6bad"));
        assert_eq!(f.lookup("2001:db9::1"), None);
    }

    #[test]
    fn slash_zero_matches_everything() {
        let f = feeds_from(&[("0.0.0.0/0", "all")]);
        assert_eq!(f.lookup("8.8.8.8"), Some("all"));
    }

    #[test]
    fn rejects_bad_input() {
        let f = feeds_from(&[("not-an-ip", "x"), ("10.0.0.0/99", "y")]);
        assert_eq!(f.entries(), 0);
        assert_eq!(f.lookup("10.0.0.1"), None);
    }
}

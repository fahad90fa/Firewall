//! Well-known ports, named for people.
//!
//! The dashboard's job is to say "Telnet probe" instead of "TCP/23". This is
//! the lookup that does it: service name plus, for the ports attackers
//! actually hunt, a one-line note on why traffic to them matters. It is a
//! curation, not a copy of /etc/services — only entries that help an
//! operator read a firewall event earn a place.

/// Name a port, with an optional risk note for the notorious ones.
pub fn lookup(port: u16) -> Option<(&'static str, Option<&'static str>)> {
    let (name, risk) = match port {
        20 => ("ftp-data", Some("FTP transfers data in cleartext")),
        21 => ("ftp", Some("cleartext logins; credential capture target")),
        22 => ("ssh", Some("the most brute-forced service on the internet")),
        23 => (
            "telnet",
            Some("cleartext shell; botnets scan for it constantly"),
        ),
        25 => ("smtp", Some("open relays and spam abuse")),
        53 => ("dns", None),
        67 | 68 => ("dhcp", None),
        69 => (
            "tftp",
            Some("no authentication at all; config exfil target"),
        ),
        79 => ("finger", Some("legacy user enumeration")),
        80 => ("http", None),
        88 => ("kerberos", None),
        110 => ("pop3", Some("cleartext mail logins")),
        111 => ("rpcbind", Some("NFS/RPC enumeration step")),
        123 => ("ntp", None),
        135 => ("msrpc", Some("Windows RPC; lateral-movement staple")),
        137 => ("netbios-ns", Some("Windows name service; recon target")),
        138 => ("netbios-dgm", Some("Windows datagram service")),
        139 => ("netbios-ssn", Some("SMB over NetBIOS; lateral movement")),
        143 => ("imap", Some("cleartext mail logins")),
        161 | 162 => ("snmp", Some("default communities leak device data")),
        179 => ("bgp", None),
        389 => (
            "ldap",
            Some("directory enumeration; credential relay target"),
        ),
        443 => ("https", None),
        445 => (
            "smb",
            Some("EternalBlue/worm territory; top lateral-movement port"),
        ),
        465 => ("smtps", None),
        512 => ("rexec", Some("legacy remote exec, cleartext credentials")),
        513 => ("rlogin", Some("legacy remote login, host-trust bypasses")),
        514 => ("rsh/syslog", Some("legacy remote shell, no crypto")),
        587 => ("submission", None),
        631 => ("ipp", Some("printer service; occasional RCE history")),
        636 => ("ldaps", None),
        853 => ("dns-over-tls", None),
        873 => (
            "rsync",
            Some("unauthenticated module listing when misconfigured"),
        ),
        993 => ("imaps", None),
        995 => ("pop3s", None),
        1080 => ("socks", Some("open proxy abuse")),
        1433 => (
            "mssql",
            Some("database brute-force and ransomware entry point"),
        ),
        1521 => ("oracle-db", Some("database attack target")),
        1723 => ("pptp", Some("broken VPN crypto")),
        2049 => ("nfs", Some("world-readable exports leak filesystems")),
        2375 => ("docker", Some("unauthenticated Docker API = instant root")),
        2376 => ("docker-tls", None),
        3128 => ("squid", Some("open proxy abuse")),
        3306 => ("mysql", Some("database brute-force target")),
        3389 => ("rdp", Some("top ransomware entry vector; scanned nonstop")),
        4444 => ("metasploit", Some("default reverse-shell port; strong IOC")),
        5060 | 5061 => ("sip", Some("toll-fraud scanning")),
        5353 => ("mdns", None),
        5432 => ("postgres", Some("database brute-force target")),
        5900..=5910 => ("vnc", Some("often password-less; remote-desktop takeover")),
        5985 => ("winrm", Some("Windows remote management; lateral movement")),
        5986 => ("winrm-tls", None),
        6379 => (
            "redis",
            Some("unauthenticated by default; cryptominer magnet"),
        ),
        6667 => ("irc", Some("classic botnet command channel")),
        8000 | 8008 | 8080 | 8888 => ("http-alt", None),
        8443 => ("https-alt", None),
        9000 => ("php-fpm", Some("FastCGI exposure leads to RCE")),
        9090 => ("prometheus/cockpit", None),
        9100 => ("jetdirect", Some("raw printer port; print-bombing")),
        9200 => ("elasticsearch", Some("unauthenticated data-theft target")),
        11211 => ("memcached", Some("UDP amplification and data exposure")),
        27017 => ("mongodb", Some("unauthenticated databases get ransomed")),
        51820 => ("wireguard", None),
        _ => return None,
    };
    Some((name, risk))
}

/// "23 (telnet)" or just "4970" when nobody has named it.
pub fn label(port: u16) -> String {
    match lookup(port) {
        Some((name, _)) => format!("{port} ({name})"),
        None => port.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notorious_ports_carry_risk_notes() {
        for p in [23u16, 445, 3389, 5901, 6379] {
            let (_, risk) = lookup(p).expect("known port");
            assert!(risk.is_some(), "port {p} should explain its risk");
        }
    }

    #[test]
    fn labels_name_what_they_can() {
        assert_eq!(label(22), "22 (ssh)");
        assert_eq!(label(4970), "4970");
    }
}

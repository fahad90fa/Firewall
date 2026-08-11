//! The network manager: discover the devices sharing this host's LAN, and
//! report what each one exposes to the network.
//!
//! # What this can and cannot see, honestly
//!
//! A host firewall observes the network, not the inside of other machines.
//! From here we can enumerate the devices on the same layer-2 network and, by
//! connecting to them the way any client would, learn which service ports they
//! leave open — a printer answering on 9100, a NAS on 445, a router's web UI
//! on 80. That is a genuine, useful inventory: it is how you find the forgotten
//! device, the unexpected open service, the thing that should not be on the
//! network at all.
//!
//! It cannot show what a person is *doing* on their device — which sites they
//! visit, which apps they run, what is on their screen. Seeing that would mean
//! sitting in the middle of their traffic (being the gateway, or ARP-spoofing
//! your way there) or running software on their machine. This tool does
//! neither; it reports only what a device chooses to answer on the network.
//!
//! # Scope of the scan
//!
//! Only the subnets this host is *directly connected to* are ever scanned —
//! its own LAN, by definition — and only when they are small enough to sweep
//! quickly. Nothing reaches past the local network. Discovery is passive by
//! default (the kernel's neighbour table); the active sweep is opt-in and
//! bounded in breadth and time.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::ports;

/// A directly-connected IPv4 network this host sits on.
pub struct Subnet {
    pub iface: String,
    pub network: Ipv4Addr,
    pub prefix: u8,
    pub host_ip: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
}

impl Subnet {
    fn mask(&self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix as u32)
        }
    }
    /// Usable host count (excludes network and broadcast for prefix < 31).
    pub fn host_count(&self) -> u64 {
        match self.prefix {
            32 => 1,
            31 => 2,
            p => (1u64 << (32 - p as u32)).saturating_sub(2),
        }
    }
}

/// One open service on a device.
pub struct Service {
    pub port: u16,
    pub name: String,
    pub risk: Option<&'static str>,
}

/// A device discovered on the LAN.
pub struct Device {
    pub ip: Ipv4Addr,
    pub mac: Option<String>,
    pub mac_kind: &'static str, // "global" | "local" (randomised/virtual) | ""
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub iface: String,
    pub is_gateway: bool,
    pub is_self: bool,
    pub reachable: bool,
    pub source: &'static str, // "neighbour" | "scan" | "self"
    pub services: Vec<Service>,
    pub role: &'static str,
    pub summary: String,
}

pub struct NetworkView {
    pub subnets: Vec<Subnet>,
    pub devices: Vec<Device>,
    pub scanned: bool,
    pub scan_ms: u64,
    pub errors: Vec<String>,
    pub notes: Vec<String>,
}

/// Ports worth probing on a LAN device: enough to fingerprint the common
/// roles (router, PC, phone, printer, NAS, media, IoT) without turning into a
/// full port scan.
const SCAN_PORTS: &[u16] = &[
    21, 22, 23, 53, 80, 135, 139, 443, 445, 515, 548, 554, 631, 1883, 3000, 3389, 5000, 5060, 5353,
    5432, 5900, 7000, 8000, 8008, 8080, 8123, 8443, 8888, 9000, 9100, 32400, 62078,
];
/// A quick liveness subset — a host answering (open or refused) on any of
/// these is up.
const LIVENESS_PORTS: &[u16] = &[80, 443, 22, 445, 53];

const MAX_SCAN_HOSTS: u64 = 1024; // refuse to sweep anything bigger than /22
const CONNECT_TIMEOUT: Duration = Duration::from_millis(320);
const WORKERS: usize = 96;
const SCAN_DEADLINE: Duration = Duration::from_secs(25);

/// Build the network view. `active` runs the bounded sweep; otherwise only the
/// passive neighbour table is used.
pub fn snapshot(active: bool) -> NetworkView {
    let mut errors = Vec::new();
    let mut notes = Vec::new();

    let subnets = local_subnets(&mut errors);
    let neighbours = arp_neighbours(&mut errors);

    // Map every neighbour to a device shell first (passive, instant).
    let mut devmap: BTreeMap<Ipv4Addr, Device> = BTreeMap::new();
    for sub in &subnets {
        if let Some(hip) = sub.host_ip {
            devmap
                .entry(hip)
                .or_insert_with(|| Device::shell(hip, &sub.iface, "self"));
        }
    }
    // Every neighbour becomes a device, whether or not it falls inside a subnet
    // we recognise — a device answering ARP on our wire is on our network.
    for (ip, mac, iface, complete) in &neighbours {
        let d = devmap
            .entry(*ip)
            .or_insert_with(|| Device::shell(*ip, iface, "neighbour"));
        d.mac = Some(mac.clone());
        d.mac_kind = mac_kind(mac);
        d.vendor = vendor_for(mac);
        d.reachable = *complete;
    }

    let started = Instant::now();
    let mut scanned = false;
    if active {
        let scannable: Vec<&Subnet> = subnets
            .iter()
            .filter(|s| s.host_count() <= MAX_SCAN_HOSTS && s.prefix >= 22)
            .collect();
        if scannable.is_empty() {
            if subnets.is_empty() {
                notes.push("No directly-connected IPv4 subnet was found to scan.".into());
            } else {
                notes.push(format!(
                    "Directly-connected subnet(s) are larger than /22 ({} host(s)); skipping the \
                     active sweep to stay quick and quiet. The neighbour table is still shown.",
                    subnets.iter().map(|s| s.host_count()).sum::<u64>()
                ));
            }
        }
        for sub in scannable {
            sweep_subnet(sub, &mut devmap, started);
            scanned = true;
        }
    } else {
        notes.push(
            "Passive view from the kernel's neighbour table. Run a scan to actively discover \
             devices and the services they expose."
                .into(),
        );
    }

    // Finalise each device: gateway flag, hostname, role, summary.
    let gateways: Vec<Ipv4Addr> = subnets.iter().filter_map(|s| s.gateway).collect();
    let mut devices: Vec<Device> = devmap.into_values().collect();
    for d in &mut devices {
        d.is_gateway = gateways.contains(&d.ip);
        if d.hostname.is_none() {
            d.hostname = reverse_dns(d.ip);
        }
        d.role = infer_role(d);
        d.summary = summarise(d);
    }
    devices.sort_by_key(|d| u32::from(d.ip));

    NetworkView {
        subnets,
        devices,
        scanned,
        scan_ms: started.elapsed().as_millis() as u64,
        errors,
        notes,
    }
}

impl Device {
    fn shell(ip: Ipv4Addr, iface: &str, source: &'static str) -> Device {
        Device {
            ip,
            mac: None,
            mac_kind: "",
            vendor: None,
            hostname: None,
            iface: iface.to_string(),
            is_gateway: false,
            is_self: source == "self",
            reachable: source == "self",
            source,
            services: Vec::new(),
            role: "unknown",
            summary: String::new(),
        }
    }
}

// --- /proc/net/route: directly-connected subnets + default gateway ---------

fn local_subnets(errors: &mut Vec<String>) -> Vec<Subnet> {
    let text = match std::fs::read_to_string("/proc/net/route") {
        Ok(t) => t,
        Err(e) => {
            errors.push(format!("/proc/net/route: {e}"));
            return Vec::new();
        }
    };
    let mut gateway_by_iface: BTreeMap<String, Ipv4Addr> = BTreeMap::new();
    let mut subs: Vec<Subnet> = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        let iface = f[0].to_string();
        let (Some(dest), Some(gw), Some(mask)) =
            (route_addr(f[1]), route_addr(f[2]), route_addr(f[7]))
        else {
            continue;
        };
        let dest_bits = u32::from(dest);
        let mask_bits = u32::from(mask);
        if dest_bits == 0 && mask_bits == 0 {
            // Default route — remember its gateway.
            if u32::from(gw) != 0 {
                gateway_by_iface.insert(iface, gw);
            }
            continue;
        }
        if u32::from(gw) != 0 || mask_bits == 0 {
            // Only directly-connected nets (no via-gateway) with a real mask.
            continue;
        }
        let prefix = mask_bits.count_ones() as u8;
        if iface == "lo" {
            continue;
        }
        subs.push(Subnet {
            iface,
            network: dest,
            prefix,
            host_ip: None,
            gateway: None,
        });
    }
    for s in &mut subs {
        s.gateway = gateway_by_iface.get(&s.iface).copied();
        s.host_ip = source_ip_for(s);
    }
    subs
}

/// A `/proc/net/route` hex field (little-endian bytes) to an `Ipv4Addr`.
fn route_addr(hex: &str) -> Option<Ipv4Addr> {
    let v = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(v.swap_bytes()))
}

/// The source address the kernel would use to reach this subnet — i.e. this
/// host's own IP on it. A connected UDP socket never sends a packet, so this
/// is a pure lookup.
fn source_ip_for(sub: &Subnet) -> Option<Ipv4Addr> {
    let target = sub
        .gateway
        .filter(|g| u32::from(*g) != 0)
        .unwrap_or_else(|| Ipv4Addr::from(u32::from(sub.network) + 1));
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect(SocketAddr::new(IpAddr::V4(target), 9)).ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
        _ => None,
    }
}

#[cfg(test)]
fn in_any_subnet(ip: Ipv4Addr, subs: &[Subnet]) -> bool {
    subs.iter()
        .any(|s| (u32::from(ip) & s.mask()) == (u32::from(s.network) & s.mask()))
}

// --- /proc/net/arp: the neighbour table ------------------------------------

fn arp_neighbours(errors: &mut Vec<String>) -> Vec<(Ipv4Addr, String, String, bool)> {
    let text = match std::fs::read_to_string("/proc/net/arp") {
        Ok(t) => t,
        Err(e) => {
            errors.push(format!("/proc/net/arp: {e}"));
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 {
            continue;
        }
        let Ok(ip) = f[0].parse::<Ipv4Addr>() else {
            continue;
        };
        let flags = u32::from_str_radix(f[2].trim_start_matches("0x"), 16).unwrap_or(0);
        let mac = f[3].to_string();
        let iface = f[5].to_string();
        if mac == "00:00:00:00:00:00" {
            continue;
        }
        // flag 0x2 == ATF_COM: a completed, resolved entry.
        out.push((ip, mac, iface, flags & 0x2 != 0));
    }
    out
}

// --- active sweep ----------------------------------------------------------

fn sweep_subnet(sub: &Subnet, devmap: &mut BTreeMap<Ipv4Addr, Device>, started: Instant) {
    let net = u32::from(sub.network);
    let mask = sub.mask();
    let broadcast = net | !mask;
    // Candidate host addresses.
    let mut targets: Vec<Ipv4Addr> = Vec::new();
    if sub.prefix >= 31 {
        for a in net..=broadcast {
            targets.push(Ipv4Addr::from(a));
        }
    } else {
        for a in (net + 1)..broadcast {
            targets.push(Ipv4Addr::from(a));
        }
    }
    // Phase 1: liveness. Hosts already in the neighbour table are known-up.
    let known_up: Vec<Ipv4Addr> = devmap
        .values()
        .filter(|d| d.reachable && (u32::from(d.ip) & mask) == (net & mask))
        .map(|d| d.ip)
        .collect();
    let live_probe: Vec<Ipv4Addr> = targets
        .iter()
        .copied()
        .filter(|ip| !known_up.contains(ip))
        .collect();
    let mut up: Vec<Ipv4Addr> = known_up;
    up.extend(parallel_liveness(&live_probe, started));
    up.sort_by_key(|ip| u32::from(*ip));
    up.dedup();

    // Phase 2: service probe on the hosts that are up.
    let results = parallel_services(&up, started);
    for (ip, services) in results {
        let d = devmap
            .entry(ip)
            .or_insert_with(|| Device::shell(ip, &sub.iface, "scan"));
        d.reachable = true;
        d.services = services;
    }
    // Fill MACs the sweep just populated in the neighbour table.
    let mut errs = Vec::new();
    for (ip, mac, iface, complete) in arp_neighbours(&mut errs) {
        if let Some(d) = devmap.get_mut(&ip) {
            if d.mac.is_none() {
                d.mac = Some(mac.clone());
                d.mac_kind = mac_kind(&mac);
                d.vendor = vendor_for(&mac);
                d.iface = iface;
            }
            d.reachable = d.reachable || complete;
        }
    }
}

/// Return the hosts from `targets` that answer on any liveness port. A refused
/// connection counts as up — the host sent a RST, so it exists.
fn parallel_liveness(targets: &[Ipv4Addr], started: Instant) -> Vec<Ipv4Addr> {
    let hits = Mutex::new(Vec::new());
    run_pool(targets.len(), |i| {
        if started.elapsed() > SCAN_DEADLINE {
            return;
        }
        let ip = targets[i];
        for &p in LIVENESS_PORTS {
            match probe(ip, p) {
                Probe::Open | Probe::Refused => {
                    hits.lock().unwrap().push(ip);
                    return;
                }
                Probe::Down => {}
            }
        }
    });
    hits.into_inner().unwrap()
}

/// Scan `SCAN_PORTS` on each up host, returning the open ones as services.
fn parallel_services(hosts: &[Ipv4Addr], started: Instant) -> Vec<(Ipv4Addr, Vec<Service>)> {
    let out = Mutex::new(Vec::new());
    run_pool(hosts.len(), |i| {
        if started.elapsed() > SCAN_DEADLINE {
            return;
        }
        let ip = hosts[i];
        let mut svcs = Vec::new();
        for &p in SCAN_PORTS {
            if let Probe::Open = probe(ip, p) {
                let (name, risk) = ports::lookup(p).unwrap_or(("service", None));
                svcs.push(Service {
                    port: p,
                    name: name.to_string(),
                    risk,
                });
            }
        }
        out.lock().unwrap().push((ip, svcs));
    });
    out.into_inner().unwrap()
}

/// A fixed-size worker pool over indices `0..n`, each processed by `job`.
fn run_pool(n: usize, job: impl Fn(usize) + Sync) {
    if n == 0 {
        return;
    }
    let next = AtomicUsize::new(0);
    let workers = WORKERS.min(n).max(1);
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= n {
                    break;
                }
                job(i);
            });
        }
    });
}

enum Probe {
    Open,
    Refused,
    Down,
}

fn probe(ip: Ipv4Addr, port: u16) -> Probe {
    match TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(ip), port), CONNECT_TIMEOUT) {
        Ok(_) => Probe::Open,
        Err(e) => match e.kind() {
            std::io::ErrorKind::ConnectionRefused => Probe::Refused,
            _ => Probe::Down,
        },
    }
}

// --- enrichment ------------------------------------------------------------

/// The locally-administered bit (0x02 of the first octet) marks a MAC that is
/// randomised or virtual — a phone with MAC privacy, a VM, a container — where
/// an OUI vendor lookup is meaningless.
fn mac_kind(mac: &str) -> &'static str {
    match first_octet(mac) {
        Some(b) if b & 0x02 != 0 => "local",
        Some(_) => "global",
        None => "",
    }
}

fn first_octet(mac: &str) -> Option<u8> {
    u8::from_str_radix(mac.split(':').next()?, 16).ok()
}

/// Curated OUI → vendor. A full registry is ~30k rows; this is the handful of
/// vendors whose gear actually turns up on a home or office LAN, in keeping
/// with the ports table's "curation, not a copy" approach. A locally-
/// administered MAC is reported as randomised instead.
fn vendor_for(mac: &str) -> Option<String> {
    if mac_kind(mac) == "local" {
        return Some("randomised / virtual".into());
    }
    let prefix = mac
        .split(':')
        .take(3)
        .map(|s| s.to_ascii_uppercase())
        .collect::<Vec<_>>()
        .join(":");
    let v = match prefix.as_str() {
        "00:03:93" | "00:0A:95" | "00:1B:63" | "00:1E:C2" | "00:23:12" | "00:25:00"
        | "00:26:BB" | "3C:07:54" | "A4:5E:60" | "F0:18:98" | "AC:BC:32" | "DC:A9:04"
        | "F0:D1:A9" | "88:66:5A" | "F4:0F:24" => "Apple",
        "00:15:5D" | "00:03:FF" | "00:50:F2" | "00:1D:D8" | "7C:1E:52" => "Microsoft",
        "00:1A:11" | "3C:5A:B4" | "F4:F5:E8" | "DA:A1:19" | "94:EB:2C" => "Google",
        "FC:FB:FB" | "00:16:6C" | "34:BE:00" | "5C:0A:5B" | "8C:77:12" | "78:BD:BC" => "Samsung",
        "B8:27:EB" | "DC:A6:32" | "E4:5F:01" | "28:CD:C1" => "Raspberry Pi",
        "00:11:32" | "00:24:B7" | "24:5E:BE" => "Synology",
        "50:C7:BF" | "C0:C9:E3" | "AC:84:C6" | "14:CC:20" | "98:DA:C4" => "TP-Link",
        "00:18:0A" | "68:72:51" | "44:D9:E7" | "78:8A:20" | "F0:9F:C2" | "FC:EC:DA" => "Ubiquiti",
        "00:05:5D" | "00:1B:11" | "C8:3A:35" | "1C:BD:B9" => "D-Link",
        "00:14:BF" | "20:AA:4B" | "A0:21:B7" | "44:94:FC" => "Netgear",
        "00:12:17" | "00:1C:10" | "68:7F:74" => "Cisco/Linksys",
        "00:04:F2" | "64:16:66" => "Polycom",
        "00:00:74" | "00:26:73" => "Ricoh",
        "00:00:48" | "08:00:37" | "00:1E:8F" => "Epson",
        "00:15:99" | "00:1E:8C" | "3C:2A:F4" | "00:1B:A9" => "Brother/printer",
        "00:80:77" | "9C:93:4E" => "HP/printer",
        "52:54:00" => "QEMU/KVM virtual",
        "08:00:27" => "VirtualBox virtual",
        "00:0C:29" | "00:50:56" | "00:05:69" => "VMware virtual",
        "02:42:AC" => "Docker container",
        _ => return None,
    };
    Some(v.to_string())
}

/// Best-effort reverse DNS via `getent hosts`, which honours /etc/hosts, mDNS
/// and the configured resolver without this tool linking a resolver of its own.
fn reverse_dns(ip: Ipv4Addr) -> Option<String> {
    let out = std::process::Command::new("getent")
        .arg("hosts")
        .arg(ip.to_string())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let line = String::from_utf8_lossy(&out.stdout);
    let name = line.split_whitespace().nth(1)?.to_string();
    if name.is_empty() || name == ip.to_string() {
        None
    } else {
        Some(name)
    }
}

/// Infer a device role from its open services and vendor — enough to answer
/// "what is this thing?" at a glance.
fn infer_role(d: &Device) -> &'static str {
    let has = |p: u16| d.services.iter().any(|s| s.port == p);
    let vendor = d.vendor.as_deref().unwrap_or("");
    if d.is_gateway {
        return "router / gateway";
    }
    if d.is_self {
        return "this host";
    }
    if has(9100)
        || has(515)
        || has(631)
        || vendor.contains("printer")
        || vendor == "Ricoh"
        || vendor == "Epson"
    {
        return "printer";
    }
    if has(32400) || has(554) || has(8123) || has(1883) {
        return "media / IoT";
    }
    if has(62078) || (vendor == "Apple" && !has(22)) {
        return "phone / tablet";
    }
    if has(445) && (has(3389) || has(139) || has(135)) {
        return "Windows PC";
    }
    if has(548) || (has(445) && (vendor == "Synology" || has(5000))) {
        return "NAS / file server";
    }
    if has(80) || has(443) || has(8080) || has(8443) {
        return "web service / appliance";
    }
    if has(22) {
        return "Linux / server";
    }
    "device"
}

fn summarise(d: &Device) -> String {
    if d.is_self {
        return "This machine — where the firewall and this dashboard run.".into();
    }
    if !d.reachable && d.services.is_empty() {
        return "Seen in the neighbour table; run a scan to probe its exposed services.".into();
    }
    if d.services.is_empty() {
        return "Reachable, but exposes none of the common service ports — well closed up.".into();
    }
    let named: Vec<String> = d
        .services
        .iter()
        .take(6)
        .map(|s| format!("{} ({})", s.name, s.port))
        .collect();
    let mut msg = format!("Exposes {}", named.join(", "));
    if d.services.len() > 6 {
        msg.push_str(&format!(" and {} more", d.services.len() - 6));
    }
    msg.push('.');
    if d.services.iter().any(|s| s.risk.is_some()) {
        msg.push_str(" Some of these are worth a second look — see the risk notes.");
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_hex_decodes_little_endian() {
        // /proc/net/route stores addresses as little-endian hex.
        assert_eq!(route_addr("000200C0").unwrap(), Ipv4Addr::new(192, 0, 2, 0)); // network
        assert_eq!(route_addr("010200C0").unwrap(), Ipv4Addr::new(192, 0, 2, 1)); // gateway
        assert_eq!(
            route_addr("00FFFFFF").unwrap(),
            Ipv4Addr::new(255, 255, 255, 0)
        ); // mask
        assert_eq!(route_addr("00000000").unwrap(), Ipv4Addr::new(0, 0, 0, 0)); // default
    }

    #[test]
    fn subnet_math_is_right() {
        let s = Subnet {
            iface: "eth0".into(),
            network: Ipv4Addr::new(192, 168, 1, 0),
            prefix: 24,
            host_ip: None,
            gateway: None,
        };
        assert_eq!(s.mask(), 0xFFFF_FF00);
        assert_eq!(s.host_count(), 254);
        assert!(in_any_subnet(
            Ipv4Addr::new(192, 168, 1, 55),
            std::slice::from_ref(&s)
        ));
        assert!(!in_any_subnet(
            Ipv4Addr::new(192, 168, 2, 55),
            std::slice::from_ref(&s)
        ));
    }

    #[test]
    fn host_count_edges() {
        let mk = |p| Subnet {
            iface: "e".into(),
            network: Ipv4Addr::new(10, 0, 0, 0),
            prefix: p,
            host_ip: None,
            gateway: None,
        };
        assert_eq!(mk(32).host_count(), 1);
        assert_eq!(mk(31).host_count(), 2);
        assert_eq!(mk(30).host_count(), 2);
        assert_eq!(mk(24).host_count(), 254);
        assert_eq!(mk(22).host_count(), 1022);
        assert!(mk(21).host_count() > MAX_SCAN_HOSTS);
    }

    #[test]
    fn locally_administered_mac_is_flagged_and_not_oui_looked_up() {
        // 0x02 low bit set on the first octet.
        assert_eq!(mac_kind("02:fc:00:00:00:05"), "local");
        assert_eq!(
            vendor_for("02:fc:00:00:00:05").as_deref(),
            Some("randomised / virtual")
        );
        // A globally-unique Apple prefix resolves to the vendor.
        assert_eq!(mac_kind("00:03:93:11:22:33"), "global");
        assert_eq!(vendor_for("00:03:93:11:22:33").as_deref(), Some("Apple"));
        // Docker and VM ranges are named.
        assert_eq!(
            vendor_for("02:42:ac:11:00:02").as_deref(),
            Some("randomised / virtual")
        );
        assert_eq!(
            vendor_for("08:00:27:aa:bb:cc").as_deref(),
            Some("VirtualBox virtual")
        );
    }

    #[test]
    fn arp_line_parsing() {
        let mut errs = Vec::new();
        // Reads the real /proc/net/arp on the test host; must not panic and
        // every row must be a parseable v4 address with a MAC.
        let n = arp_neighbours(&mut errs);
        for (ip, mac, _iface, _c) in &n {
            assert!(!ip.is_unspecified());
            assert!(mac.contains(':'));
        }
    }

    #[test]
    fn role_inference() {
        let mk = |ports: &[u16], gw: bool| {
            let mut d = Device::shell(Ipv4Addr::new(10, 0, 0, 9), "e", "scan");
            d.is_self = false;
            d.is_gateway = gw;
            d.services = ports
                .iter()
                .map(|&p| Service {
                    port: p,
                    name: "x".into(),
                    risk: None,
                })
                .collect();
            infer_role(&d)
        };
        assert_eq!(mk(&[80, 443], true), "router / gateway");
        assert_eq!(mk(&[9100], false), "printer");
        assert_eq!(mk(&[445, 3389], false), "Windows PC");
        assert_eq!(mk(&[22], false), "Linux / server");
        assert_eq!(mk(&[32400], false), "media / IoT");
        assert_eq!(mk(&[], false), "device");
    }

    #[test]
    fn a_live_passive_snapshot_never_panics() {
        let v = snapshot(false);
        // On the test host this at least finds the directly-connected subnet.
        for d in &v.devices {
            assert!(!d.ip.is_unspecified());
        }
    }
}

//! On-host flood and DoS resistance — and an honest account of its ceiling.
//!
//! # What a host firewall can and cannot do about a flood
//!
//! It cannot **absorb a volumetric DDoS.** By the time a packet reaches this
//! host it has already crossed the network and consumed the very bandwidth a
//! flood is trying to exhaust; dropping it here does not un-send it. Absorbing a
//! volumetric flood needs capacity *upstream* of the host — a scrubbing centre,
//! a CDN, the provider's edge — and no amount of code on the origin changes
//! that. Anyone who tells you a host firewall stops a real DDoS is selling
//! something.
//!
//! What it *can* do is refuse to fall over from the classes of flood that are
//! about **state and connection rate rather than raw bandwidth** — a SYN flood
//! that fills the connection table, a single source opening thousands of
//! sockets, a burst of malformed/out-of-state packets, an ICMP storm. Those are
//! handled in the kernel's own conntrack path, cheaply, before the packet
//! reaches policy evaluation. This raises the volume an attacker needs and stops
//! the small-and-medium floods outright; it is a real, worthwhile layer, and it
//! is not a substitute for upstream scrubbing.
//!
//! # Shape
//!
//! A standalone `table inet ufw_edge` at hook priority **-150**, ahead of the
//! policy table (priority 0), so flood traffic is dropped before anything spends
//! cycles deciding it. Every rule is a **drop-what-exceeds** rule: `ct state
//! invalid drop`, `limit rate over … drop` for new-connection SYNs and ICMP
//! echoes, and a per-source concurrent-connection cap via `ct count`. Nothing
//! here *accepts* terminally — within-rate traffic simply falls through to the
//! policy table, so this layer only ever *removes* flood traffic and can never
//! change what the policy permits. It is installed via `nft -f -` over stdin
//! (no temp file), the same way the fail-closed barrier is.

use std::fmt::Write as _;

/// The nftables table name for the flood layer. Distinct from `ufw` (the policy
/// table) and `ufw_failsafe` (the emergency barrier) so installing or removing
/// one never touches another.
pub const EDGE_TABLE: &str = "ufw_edge";

/// Tunables for the flood layer. Defaults are deliberately generous — the point
/// is to survive a flood, not to throttle legitimate bursty traffic — and are
/// clamped by [`FloodOpts::sanitized`] so a config file cannot invert them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloodOpts {
    /// New TCP connections per second (a SYN-flood dampener), then `burst`.
    pub syn_rate_per_sec: u32,
    pub syn_burst: u32,
    /// Concurrent connections a single source IP may hold before new ones are
    /// dropped — stops one host exhausting the connection table.
    pub conns_per_source: u32,
    /// ICMP echo-requests per second (ping-flood dampener), then `burst`.
    pub icmp_rate_per_sec: u32,
    pub icmp_burst: u32,
}

impl Default for FloodOpts {
    fn default() -> Self {
        FloodOpts {
            syn_rate_per_sec: 200,
            syn_burst: 50,
            conns_per_source: 100,
            icmp_rate_per_sec: 20,
            icmp_burst: 10,
        }
    }
}

impl FloodOpts {
    /// Clamp to values that stay coherent regardless of the config. A rate of
    /// zero would drop *all* new connections (a self-inflicted outage), so every
    /// limit has a floor.
    pub fn sanitized(mut self) -> Self {
        self.syn_rate_per_sec = self.syn_rate_per_sec.max(1);
        self.syn_burst = self.syn_burst.max(1);
        self.conns_per_source = self.conns_per_source.max(1);
        self.icmp_rate_per_sec = self.icmp_rate_per_sec.max(1);
        self.icmp_burst = self.icmp_burst.max(1);
        self
    }
}

/// The flood-mitigation ruleset, as loadable nftables text.
pub fn flood_hardening_ruleset(opts: &FloodOpts) -> String {
    let o = opts.sanitized();
    let mut s = String::new();
    let _ = write!(
        s,
        "#!/usr/sbin/nft -f\n\
         # Unified Firewall edge flood-hardening layer.\n\
         # Runs at hook priority -150, ahead of the policy table, and only ever\n\
         # DROPS flood/invalid traffic — within-rate traffic falls through to the\n\
         # policy, so this never changes what the policy permits. It mitigates\n\
         # state/connection-rate floods; it does NOT absorb a volumetric DDoS,\n\
         # which must be handled upstream of this host.\n\
         table inet {table} {{\n\
         \x20   chain prefilter {{\n\
         \x20       type filter hook input priority -150; policy accept;\n\
         \x20       ct state invalid drop\n\
         \x20       iifname \"lo\" accept\n\
         \x20       tcp flags syn / fin,syn,rst,ack ct state new limit rate over {syn_rate}/second burst {syn_burst} packets drop\n\
         \x20       ct state new meter ufw_conn_v4 {{ ip saddr ct count over {conns} }} drop\n\
         \x20       ct state new meter ufw_conn_v6 {{ ip6 saddr ct count over {conns} }} drop\n\
         \x20       ip protocol icmp icmp type echo-request limit rate over {icmp_rate}/second burst {icmp_burst} packets drop\n\
         \x20       ip6 nexthdr ipv6-icmp icmpv6 type echo-request limit rate over {icmp_rate}/second burst {icmp_burst} packets drop\n\
         \x20   }}\n\
         }}\n",
        table = EDGE_TABLE,
        syn_rate = o.syn_rate_per_sec,
        syn_burst = o.syn_burst,
        conns = o.conns_per_source,
        icmp_rate = o.icmp_rate_per_sec,
        icmp_burst = o.icmp_burst,
    );
    s
}

/// Install the flood layer by loading [`flood_hardening_ruleset`] with `nft`,
/// feeding the ruleset over stdin (no temp file). Best-effort and loud: returns
/// the error text on any failure so the caller can log why the host was not
/// hardened.
pub fn install_flood_hardening(opts: &FloodOpts) -> Result<(), String> {
    let ruleset = flood_hardening_ruleset(opts);
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not run nft to install flood hardening: {e}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "nft stdin was not available".to_string())?
        .write_all(ruleset.as_bytes())
        .map_err(|e| format!("could not write the flood ruleset to nft: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("nft did not complete: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "nft rejected the flood layer: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Remove the flood layer.
pub fn remove_flood_hardening() -> Result<(), String> {
    let out = std::process::Command::new("nft")
        .arg("delete")
        .arg("table")
        .arg("inet")
        .arg(EDGE_TABLE)
        .output();
    match out {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            if err.contains("No such file") || err.contains("does not exist") {
                Ok(())
            } else {
                Err(format!(
                    "nft could not delete the flood layer: {}",
                    err.trim()
                ))
            }
        }
        Err(e) => Err(format!("could not run nft to remove the flood layer: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ruleset_only_drops_never_terminally_accepts_policy_traffic() {
        let r = flood_hardening_ruleset(&FloodOpts::default());
        // The only `accept` is loopback; everything else is a drop-what-exceeds
        // rule, so the layer can never widen what the policy permits.
        assert_eq!(r.matches(" accept\n").count(), 1, "unexpected accept:\n{r}");
        assert!(r.contains("iifname \"lo\" accept"));
        assert!(r.contains("ct state invalid drop"));
        assert!(
            r.contains("policy accept;"),
            "the chain must fall through, not default-drop"
        );
    }

    #[test]
    fn the_flood_rules_are_present_and_parameterized() {
        let opts = FloodOpts {
            syn_rate_per_sec: 500,
            syn_burst: 20,
            conns_per_source: 42,
            icmp_rate_per_sec: 5,
            icmp_burst: 3,
        };
        let r = flood_hardening_ruleset(&opts);
        assert!(r.contains("limit rate over 500/second burst 20 packets drop"));
        assert!(r.contains("ct count over 42 } drop"));
        assert!(r.contains("icmp type echo-request limit rate over 5/second burst 3 packets drop"));
    }

    #[test]
    fn zero_rates_are_clamped_so_the_layer_cannot_self_dos() {
        let opts = FloodOpts {
            syn_rate_per_sec: 0,
            syn_burst: 0,
            conns_per_source: 0,
            icmp_rate_per_sec: 0,
            icmp_burst: 0,
        };
        let r = flood_hardening_ruleset(&opts);
        // A rate of 0 would drop every new connection; the floor prevents it.
        assert!(r.contains("limit rate over 1/second burst 1 packets drop"));
        assert!(r.contains("ct count over 1 } drop"));
        assert!(!r.contains("over 0/second"));
    }

    #[test]
    fn it_sits_ahead_of_the_policy_table() {
        let r = flood_hardening_ruleset(&FloodOpts::default());
        assert!(
            r.contains("priority -150"),
            "must run before the policy table (priority 0)"
        );
    }
}

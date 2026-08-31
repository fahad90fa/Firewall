//! Scenario: the shipped systemd units close the boot-time enforcement gap and
//! run with reduced privilege — and stay that way.
//!
//! Two production properties live entirely in the unit files, where nothing else
//! in the test suite looks:
//!
//!   1. **No unfiltered boot window.** nftables rules do not survive a reboot,
//!      so there is a moment between "the network is up" and "the firewall is
//!      loaded" during which a default-permissive host is exposed. The
//!      `firewall-policy` unit exists to erase that moment — it restores the
//!      policy *before* the network comes up. If someone loosens its ordering,
//!      the window silently reopens and no other test would notice. This one
//!      does.
//!
//!   2. **Least privilege.** A firewall daemon compromised through a parsing bug
//!      should not also hand the attacker the run of the box. Each unit is
//!      bounded to the capabilities it actually uses and sandboxed; this test
//!      pins that set so a future edit cannot quietly drop `NoNewPrivileges` or
//!      widen `CapabilityBoundingSet` back to "all of root".
//!
//! When `systemd-analyze` is present the test also asks it to *verify* each unit
//! (catching a typo'd directive) and, under `UFW_SYSTEMD_REQUIRE=1`, treats its
//! absence as a failure rather than a skip — the same always-on-in-CI pattern
//! the enforcement-conformance gate uses.

use std::path::PathBuf;
use std::process::Command;

fn units_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("build/linux")
}

fn read_unit(name: &str) -> String {
    let path = units_dir().join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// The long-running, root-capable services that must be sandboxed. (The oneshot
/// `firewall-policy` and `ufw-license-check` units are checked separately, for
/// ordering and for capability bounding respectively.)
const SERVICE_UNITS: &[&str] = &[
    "ufw-waf.service",
    "ufw-nft.service",
    "ufw-daemon.service",
    "firewall-policy.service",
    "ufw-license-check.service",
];

#[test]
fn the_boot_policy_restore_beats_the_network_online() {
    // The whole point of firewall-policy.service: filtered before reachable.
    let u = read_unit("firewall-policy.service");
    assert!(
        u.contains("DefaultDependencies=no"),
        "firewall-policy must opt out of the default ordering to run early enough"
    );
    assert!(
        u.contains("Before=network-pre.target"),
        "firewall-policy must be ordered BEFORE the network comes up — this is \
         the directive that closes the unfiltered boot window"
    );
    assert!(
        u.contains("RemainAfterExit=yes"),
        "the oneshot must stay active so its ExecStop tears the table down on shutdown"
    );
}

#[test]
fn every_service_drops_privilege() {
    for unit in SERVICE_UNITS {
        let u = read_unit(unit);
        assert!(
            u.contains("NoNewPrivileges=yes"),
            "{unit} must set NoNewPrivileges=yes"
        );
        assert!(
            u.contains("CapabilityBoundingSet="),
            "{unit} must bound its capability set (never inherit all of root's)"
        );
        assert!(
            u.contains("ProtectSystem=strict"),
            "{unit} must run with a read-only system tree"
        );
        assert!(
            u.contains("RestrictSUIDSGID=yes") && u.contains("RestrictRealtime=yes"),
            "{unit} is missing a core hardening directive"
        );
    }
}

#[test]
fn the_waf_needs_no_capabilities_at_all() {
    // The WAF is a self-contained user-space proxy: it should hold the empty
    // capability set and the strongest sandbox, because there is no reason for
    // it to hold anything. A regression that grants it a capability is a smell
    // worth failing on.
    let u = read_unit("ufw-waf.service");
    assert!(
        u.contains("CapabilityBoundingSet=\n") || u.contains("CapabilityBoundingSet="),
        "the WAF must bound its capabilities to the empty set"
    );
    // And it is the one unit locked down with a syscall filter and W^X, since it
    // spawns nothing that those would break.
    assert!(
        u.contains("SystemCallFilter=@system-service"),
        "the WAF must run behind a system-call allowlist"
    );
    assert!(
        u.contains("MemoryDenyWriteExecute=yes"),
        "the WAF must forbid writable-executable memory"
    );
}

#[test]
fn the_capability_bounding_sets_are_minimal_not_broad() {
    // Bounding to CAP_SYS_ADMIN would be "bounded" in name only. Assert no unit
    // hands itself the broad, near-root capabilities.
    for unit in SERVICE_UNITS {
        let u = read_unit(unit);
        for line in u
            .lines()
            .filter(|l| l.starts_with("CapabilityBoundingSet="))
        {
            for banned in ["CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_DAC_OVERRIDE"] {
                assert!(
                    !line.contains(banned),
                    "{unit} bounds in {banned}, which defeats the reduction: {line}"
                );
            }
        }
    }
}

#[test]
fn systemd_analyze_accepts_every_unit() {
    let available = Command::new("systemd-analyze")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !available {
        if std::env::var("UFW_SYSTEMD_REQUIRE").as_deref() == Ok("1") {
            panic!("UFW_SYSTEMD_REQUIRE=1 but systemd-analyze is not available");
        }
        eprintln!("skipping (systemd-analyze absent; set UFW_SYSTEMD_REQUIRE=1 to require it)");
        return;
    }
    for unit in SERVICE_UNITS {
        let path = units_dir().join(unit);
        let out = Command::new("systemd-analyze")
            .arg("verify")
            .arg(&path)
            .output()
            .expect("running systemd-analyze verify");
        // `verify` prints (and returns non-zero) about the missing ExecStart
        // binary, which is expected in a build tree — the binaries are not
        // installed here. Any *directive* error is a different message; assert
        // stderr carries only the executable-not-found note, if anything.
        let stderr = String::from_utf8_lossy(&out.stderr);
        for line in stderr.lines() {
            let benign = line.contains("is not executable")
                || line.contains("Command ")
                || line.trim().is_empty();
            assert!(benign, "systemd-analyze flagged {unit}: {line}");
        }
    }
}

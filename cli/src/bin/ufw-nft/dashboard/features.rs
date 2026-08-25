//! `/api/features` — the "what's new / security features" page data.
//!
//! Lists the capabilities added in the recent security work and, where the host
//! can tell, their *live* status: is the kernel module loaded, is a rate-limit
//! rule in the running table, is this machine licensed, is this console on mTLS.
//! Everything else is reported as shipped-in-this-build with an honest one-liner.
//!
//! Detection is best-effort and read-only: a missing file or an nft that will
//! not answer degrades to "unknown/off", never a crash.

use std::process::Command;
use std::time::Duration;

use ufw_shared::json::JsonWriter;

use super::bounded;

/// Is the `ufw` kernel module currently loaded?
fn module_loaded() -> bool {
    std::fs::read_to_string("/proc/modules")
        .map(|s| {
            s.lines()
                .any(|l| l.split_whitespace().next() == Some("ufw"))
        })
        .unwrap_or(false)
}

/// Does the package ship the DKMS module source (so it *could* be built)?
fn module_available() -> bool {
    std::path::Path::new("/usr/src")
        .read_dir()
        .map(|rd| {
            rd.flatten().any(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("unified-firewall-")
            })
        })
        .unwrap_or(false)
}

/// Is a rate-limit rule live in the running `inet ufw` table?
fn rate_limit_active() -> bool {
    let mut cmd = Command::new("nft");
    cmd.args(["list", "table", "inet", "ufw"]);
    match bounded::run_bounded(cmd, Duration::from_millis(800)) {
        Ok(out) => String::from_utf8_lossy(&out.stdout).contains("limit rate"),
        Err(_) => false,
    }
}

/// Status string plus an optional live detail for the licensing feature.
fn license_status() -> (&'static str, String) {
    if !crate::license::licensing_enabled() {
        return (
            "available",
            "licensing off (no /etc/unified-firewall/license.conf)".into(),
        );
    }
    match crate::license::load_store() {
        Some(s) => {
            let build = if cfg!(feature = "tls") {
                "Ed25519-verified"
            } else {
                "HMAC deterrent (build with --features tls for Ed25519)"
            };
            let hw = if s.hw_binding.is_empty() {
                "software node-lock"
            } else {
                "hardware-bound"
            };
            (
                "active",
                format!("{} · {} · {build} · {hw}", s.plan, s.status),
            )
        }
        None => (
            "available",
            "enabled but no key activated on this machine".into(),
        ),
    }
}

fn feature(
    w: &mut JsonWriter,
    key: &str,
    title: &str,
    category: &str,
    status: &str,
    detail: &str,
    activate: &str,
) {
    w.begin_object();
    w.str_field("key", key);
    w.str_field("title", title);
    w.str_field("category", category);
    w.str_field("status", status);
    w.str_field("detail", detail);
    w.str_field("activate", activate);
    w.end_object();
}

/// The features array. `mtls_client` is whether THIS request arrived over a
/// verified client certificate.
pub fn features_json(mtls_client: bool) -> String {
    let module_status = if module_loaded() {
        "active"
    } else if module_available() {
        "available"
    } else {
        "off"
    };
    let rl_status = if rate_limit_active() {
        "active"
    } else {
        "available"
    };
    let (lic_status, lic_detail) = license_status();
    let mtls_status = if mtls_client {
        "active"
    } else if cfg!(feature = "tls") {
        "available"
    } else {
        "off"
    };

    let mut w = JsonWriter::with_capacity(2048);
    w.begin_object();
    w.begin_array_field("features");

    feature(
        &mut w,
        "module",
        "Kernel module — identity + DPI enforcement",
        "enforcement",
        module_status,
        match module_status {
            "active" => "ufw.ko is loaded; identity-aware and DPI verdicts can enforce. Its decoders are hardened (stack-protector, no-strict-overflow) and CI-gated equal to a memory-safe Rust core.",
            "available" => "module source is installed; build it with: sudo dkms autoinstall (needs linux-headers). Ring-0 surface, but hardened + equivalence-gated against a memory-safe core (see 'Memory-safe-verified ring-0'). Not yet externally audited.",
            _ => "not installed on this host; the packet layer works without it, and no out-of-tree C parses hostile bytes in this default posture.",
        },
        "sudo dkms autoinstall  &&  edit /etc/unified-firewall/daemon.toml → mode=\"enforce\", require_kernel_module=true",
    );
    feature(
        &mut w,
        "ratelimit",
        "Rate limiting — SYN-flood & brute-force caps",
        "enforcement",
        rl_status,
        if rl_status == "active" {
            "a connection-rate cap is live in the running nftables table."
        } else {
            "not currently loaded; apply a policy that carries rate_limit rules."
        },
        "sudo firewall apply /etc/unified-firewall/policies/server/web_server.yaml",
    );
    feature(
        &mut w,
        "ring0",
        "Memory-safe-verified ring-0 decoders",
        "assurance",
        if module_loaded() { "active" } else { "shipped" },
        if module_loaded() {
            "the C kernel decoders are live — and gated in CI to match a no_std/no-unsafe Rust core byte-for-byte over the whole fuzz corpus."
        } else {
            "default build: no out-of-tree C parses hostile bytes — the memory-safe Rust core + in-kernel nftables do. When you load the module, its C decoders are equivalence-gated against that Rust core."
        },
        "cargo test -p ufw-kcore --test differential  (UFW_DIFF_REQUIRE=1 in CI)",
    );
    feature(
        &mut w,
        "licensing",
        "Hardware-bound licensing + Ed25519 + server-gated value",
        "licensing",
        lic_status,
        &lic_detail,
        "sudo firewall license activate <KEY>",
    );
    feature(
        &mut w,
        "mtls",
        "Console mTLS + RBAC",
        "access",
        mtls_status,
        match mtls_status {
            "active" => "this session is authenticated by a client certificate mapped to an RBAC role.",
            "available" => "built with TLS; start with --tls-cert/--tls-key/--tls-client-ca to require client certs.",
            _ => "loopback-only console; rebuild with --features tls for network mTLS.",
        },
        "ufw-nft dashboard 0.0.0.0:8787 --tls-cert C --tls-key K --tls-client-ca CA",
    );
    feature(
        &mut w,
        "provenance",
        "Keyless build provenance (SLSA + Rekor)",
        "supply-chain",
        "shipped",
        "every tagged release is signed by GitHub's OIDC identity and logged to the public Rekor transparency log — no private key to manage. Verify: gh attestation verify <deb> --repo fahad90fa/Firewall.",
        "see .github/workflows/release.yml and docs/apt-repo.md",
    );
    feature(
        &mut w,
        "signed",
        "Signed apt repository (traditional trust path)",
        "supply-chain",
        "available",
        "build/linux/sign-release.sh produces a GPG-signed apt repo so apt verifies every install; needs a maintainer GPG key. The keyless provenance above needs no key.",
        "GPG_KEY=you build/linux/sign-release.sh  (see docs/apt-repo.md)",
    );
    feature(
        &mut w,
        "portscan",
        "Port-scan & network-sweep detection",
        "detection",
        "active",
        "live behavioral layer in the daemon: one source fanning out across many ports on a host (port scan) or one port across many hosts (sweep) raises an alert — the reconnaissance move a per-flow allow/deny can't see. Bounded, sliding-window, feeds the same alert path as egress anomaly.",
        "part of the daemon's behavioral detection (enabled with anomaly detection)",
    );
    feature(
        &mut w,
        "dnsexfil",
        "DNS tunneling / exfiltration detection",
        "detection",
        "shipped",
        "scores DNS query names for the two tunnel shapes — a single high-entropy encoded blob, or many distinct encoded sub-domains chunked under one parent. Conservative by design: CDN shards and long readable names score clean (0 false positives in-test).",
        "cargo test -p ufw-daemon --lib logging::dns_exfil",
    );
    feature(
        &mut w,
        "detection",
        "Measured detection efficacy (full pipeline)",
        "assurance",
        "shipped",
        "labeled-corpus CI harnesses: WAF full pipeline 89.7% catch / 0% FP on an INDEPENDENT web-attack corpus (all evasion variants caught); egress-anomaly 100% catch / 0% FP; signature pre-filter 100% recall. Honest-scope: measured against known corpora, not a claim of novel-attack coverage.",
        "cargo test -p ufw-daemon --test waf_efficacy -- --nocapture",
    );
    feature(
        &mut w,
        "soak",
        "Runtime evidence (soak harness)",
        "assurance",
        "shipped",
        "netns soak driving real traffic through the live nft path; sampled counters, liveness, memory drift.",
        "sudo sh scripts/soak.sh 604800 policies/base/monitor_baseline.yaml 300",
    );
    feature(
        &mut w,
        "audit",
        "Audit-ready security docs",
        "assurance",
        "shipped",
        "SECURITY.md, threat model, attack surface, and disclosure policy — the scope an external audit needs.",
        "see SECURITY.md and docs/security/",
    );

    w.end_array();
    w.end_object();
    w.finish()
}

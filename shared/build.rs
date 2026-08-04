//! Build script for platform-conditional compilation.
//!
//! Two jobs:
//!
//! 1. Emit `ufw_platform_*` cfg flags so downstream crates can write
//!    `#[cfg(ufw_platform_linux)]` instead of repeating the `target_os`
//!    triples that the project supports. Exactly one of the three flags is
//!    set on a supported host; none are set on an unsupported host, which is
//!    what makes the "unsupported platform" compile error in
//!    `daemon/src/ipc/mod.rs` fire.
//!
//! 2. Export the ABI revision of the kernel/user shared structures so the C
//!    and Swift kernel components can be checked against the Rust definitions
//!    at handshake time rather than crashing on a layout mismatch.

use std::env;

/// Bumped whenever the binary layout in `policy_types.rs` or `protocol.rs`
/// changes in a way that is not backward compatible. Must be kept in lockstep
/// with `UFW_ABI_REVISION` in `kernel/*/inc/policy_structs.h`.
const ABI_REVISION: u32 = 2;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/protocol.rs");
    println!("cargo:rerun-if-changed=src/policy_types.rs");

    // Older toolchains warn about unknown `cfg` values unless they are
    // declared. `check-cfg` is ignored by toolchains that predate it.
    for flag in [
        "ufw_platform_windows",
        "ufw_platform_linux",
        "ufw_platform_macos",
    ] {
        println!("cargo:rustc-check-cfg=cfg({flag})");
    }

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    match target_os.as_str() {
        "windows" => println!("cargo:rustc-cfg=ufw_platform_windows"),
        "linux" | "android" => println!("cargo:rustc-cfg=ufw_platform_linux"),
        "macos" | "ios" => println!("cargo:rustc-cfg=ufw_platform_macos"),
        other => {
            // Not a hard error: the policy compiler and its test-suite are
            // useful on any host, even one that can never enforce policy.
            println!(
                "cargo:warning=unified-firewall: target_os `{other}` has no kernel backend; \
                 building compiler/analysis components only"
            );
        }
    }

    println!("cargo:rustc-env=UFW_ABI_REVISION={ABI_REVISION}");
    println!(
        "cargo:rustc-env=UFW_BUILD_TARGET={}",
        env::var("TARGET").unwrap_or_else(|_| "unknown".into())
    );
}

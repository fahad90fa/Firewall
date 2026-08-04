//! Cross-component shared definitions for the Unified Firewall.
//!
//! Everything in this crate is a *contract*: a type, a wire format or a
//! constant that at least two of the four subsystems (policy compiler, daemon,
//! kernel modules, CLI) must agree on. Nothing here does I/O and nothing here
//! is platform-specific beyond the cfg flags emitted by `build.rs`.
//!
//! # Module map
//!
//! | Module | Contract |
//! |---|---|
//! | [`constants`] | Magic numbers, limits, endpoint names — mirrored in the C and Swift kernel components |
//! | [`policy_types`] | Compiled policy representation **and the reference semantics every backend must reproduce** |
//! | [`identity_types`] | The normalized application identity model |
//! | [`log_types`] | The unified log event schema |
//! | [`protocol`] | Daemon ↔ kernel IPC framing and messages |
//! | [`hash`] | SHA-256, used for binary hashing and ruleset fingerprints |
//! | [`json`] | Minimal JSON emitter/parser used by logging, the REST API and the CLI |
//!
//! `hash` and `json` are implementation support rather than external contracts,
//! but they live here because all four subsystems need them and the project
//! takes no third-party dependencies.
//!
//! # The one thing to read first
//!
//! [`policy_types::CompiledPolicy::evaluate`] is the authoritative definition
//! of what a policy means. The Windows, Linux and macOS backends each
//! reimplement it in their native filtering API, and
//! `policy-lang`'s equivalence verifier exists to prove they agree.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod constants;
pub mod hash;
pub mod identity_types;
pub mod json;
pub mod log_types;
pub mod policy_types;
pub mod protocol;

/// The platform a component is built for or a policy is compiled for.
///
/// Distinct from `cfg!(target_os)`: the compiler generates artifacts for all
/// three platforms regardless of where it is running, so it needs a runtime
/// value, not a compile-time one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Platform {
    Windows,
    Linux,
    MacOS,
}

impl Platform {
    pub const ALL: [Platform; 3] = [Platform::Windows, Platform::Linux, Platform::MacOS];

    pub fn as_str(self) -> &'static str {
        match self {
            Platform::Windows => "windows",
            Platform::Linux => "linux",
            Platform::MacOS => "macos",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "windows" | "win" | "win32" => Platform::Windows,
            "linux" => Platform::Linux,
            "macos" | "darwin" | "osx" => Platform::MacOS,
            _ => return None,
        })
    }

    /// Whether paths on this platform compare case-insensitively. Drives
    /// [`policy_types::PathPattern::case_insensitive`].
    ///
    /// macOS is listed as case-insensitive because APFS is case-insensitive by
    /// default; a policy that relied on case to distinguish two binaries would
    /// be relying on a non-default filesystem configuration.
    pub fn paths_are_case_insensitive(self) -> bool {
        matches!(self, Platform::Windows | Platform::MacOS)
    }

    /// The platform this binary is running on, if it is one of the three.
    pub fn host() -> Option<Platform> {
        #[cfg(ufw_platform_windows)]
        {
            return Some(Platform::Windows);
        }
        #[cfg(ufw_platform_linux)]
        {
            return Some(Platform::Linux);
        }
        #[cfg(ufw_platform_macos)]
        {
            return Some(Platform::MacOS);
        }
        #[allow(unreachable_code)]
        {
            None
        }
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// ABI revision this build was compiled with, from `build.rs`.
pub const BUILD_ABI_REVISION: &str = env!("UFW_ABI_REVISION");

/// Target triple this build was compiled for, from `build.rs`.
pub const BUILD_TARGET: &str = env!("UFW_BUILD_TARGET");

/// Current wall-clock time in microseconds since the UNIX epoch.
///
/// Used for log timestamps and cache expiry. Panic-free: a clock before the
/// epoch yields 0 rather than unwinding inside a logging path.
pub fn now_us() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_parsing_and_aliases() {
        assert_eq!(Platform::parse("darwin"), Some(Platform::MacOS));
        assert_eq!(Platform::parse("win32"), Some(Platform::Windows));
        assert_eq!(Platform::parse("linux"), Some(Platform::Linux));
        assert_eq!(Platform::parse("plan9"), None);
        for p in Platform::ALL {
            assert_eq!(Platform::parse(p.as_str()), Some(p));
        }
    }

    #[test]
    fn case_sensitivity_matches_platform_conventions() {
        assert!(Platform::Windows.paths_are_case_insensitive());
        assert!(Platform::MacOS.paths_are_case_insensitive());
        assert!(!Platform::Linux.paths_are_case_insensitive());
    }

    #[test]
    fn clock_is_monotonic_enough_for_ordering() {
        let a = now_us();
        let b = now_us();
        assert!(b >= a);
        assert!(a > 1_600_000_000_000_000, "clock should be past 2020");
    }

    #[test]
    fn abi_revision_matches_constant() {
        assert_eq!(
            BUILD_ABI_REVISION.parse::<u32>().unwrap(),
            constants::ABI_REVISION
        );
    }
}

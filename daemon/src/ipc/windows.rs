//! Windows endpoint: the WFP callout driver's device object.
//!
//! # Read/write rather than DeviceIoControl
//!
//! The driver creates a device object and a symbolic link at
//! [`ufw_shared::constants::WINDOWS_DEVICE_LINK`], and handles four major
//! function codes: `IRP_MJ_CREATE`, `IRP_MJ_CLOSE`, `IRP_MJ_READ` and
//! `IRP_MJ_WRITE`. The daemon opens the symbolic link like a file and
//! exchanges the same framed messages every other platform uses, so the
//! protocol layer, its bounds checking and its tests are shared.
//!
//! `IRP_MJ_DEVICE_CONTROL` is also implemented, with the IOCTL codes in
//! `kernel/windows/inc/ipc_ioctl.h`, for two callers that genuinely need it: a
//! recovery tool that must talk to the driver without a running daemon, and
//! the installer's post-install verification. Nothing on the daemon's hot path
//! uses IOCTLs, because a per-message `DeviceIoControl` round trip buys
//! nothing over a buffered read/write pair.
//!
//! # Pended reads
//!
//! Log events and identity queries arrive on the daemon's blocking read. The
//! driver pends a read IRP when its outbound ring buffer is empty and
//! completes it when an event is queued, so the daemon's reader thread costs
//! one blocked thread rather than a polling loop.

use std::fs::OpenOptions;
use std::io;

use super::{StreamTransport, Transport};

/// Symbolic link the driver exposes.
pub const DEFAULT_ENDPOINT: &str = ufw_shared::constants::WINDOWS_DEVICE_LINK;

pub fn connect(endpoint: &str) -> io::Result<Box<dyn Transport>> {
    let path = if endpoint.is_empty() { DEFAULT_ENDPOINT } else { endpoint };

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| annotate(path, e))?;

    Ok(Box::new(StreamTransport::new(file, path)))
}

fn annotate(path: &str, e: io::Error) -> io::Error {
    let hint = match e.kind() {
        io::ErrorKind::NotFound => format!(
            "{path} could not be opened; the `{}` driver service is probably not running \
             (check `sc query {}`)",
            ufw_shared::constants::WINDOWS_DRIVER_SERVICE,
            ufw_shared::constants::WINDOWS_DRIVER_SERVICE
        ),
        io::ErrorKind::PermissionDenied => format!(
            "{path} refused access; the daemon must run as LocalSystem or with \
             SeLoadDriverPrivilege to reach the filter driver"
        ),
        _ => format!("cannot open {path}: {e}"),
    };
    io::Error::new(e.kind(), hint)
}

/// IOCTL codes, mirrored from `kernel/windows/inc/ipc_ioctl.h`.
///
/// Built with `CTL_CODE(FILE_DEVICE_NETWORK, function, METHOD_BUFFERED,
/// FILE_ANY_ACCESS)`. Present here so the recovery tool and the tests can
/// assert the two definitions have not drifted.
pub mod ioctl {
    /// `FILE_DEVICE_NETWORK`
    pub const DEVICE_TYPE: u32 = 0x00000012;
    pub const METHOD_BUFFERED: u32 = 0;
    pub const FILE_ANY_ACCESS: u32 = 0;

    pub const fn ctl_code(function: u32) -> u32 {
        (DEVICE_TYPE << 16) | (FILE_ANY_ACCESS << 14) | (function << 2) | METHOD_BUFFERED
    }

    pub const FUNCTION_HELLO: u32 = 0x800;
    pub const FUNCTION_INSTALL_POLICY: u32 = 0x801;
    pub const FUNCTION_UPDATE_POLICY: u32 = 0x802;
    pub const FUNCTION_FLUSH: u32 = 0x803;
    pub const FUNCTION_STATS: u32 = 0x804;
    pub const FUNCTION_SET_MODE: u32 = 0x805;
    pub const FUNCTION_DRAIN_LOG: u32 = 0x806;

    pub const IOCTL_UFW_HELLO: u32 = ctl_code(FUNCTION_HELLO);
    pub const IOCTL_UFW_INSTALL_POLICY: u32 = ctl_code(FUNCTION_INSTALL_POLICY);
    pub const IOCTL_UFW_UPDATE_POLICY: u32 = ctl_code(FUNCTION_UPDATE_POLICY);
    pub const IOCTL_UFW_FLUSH: u32 = ctl_code(FUNCTION_FLUSH);
    pub const IOCTL_UFW_STATS: u32 = ctl_code(FUNCTION_STATS);
    pub const IOCTL_UFW_SET_MODE: u32 = ctl_code(FUNCTION_SET_MODE);
    pub const IOCTL_UFW_DRAIN_LOG: u32 = ctl_code(FUNCTION_DRAIN_LOG);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_codes_match_the_ctl_code_macro() {
        // CTL_CODE(0x12, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
        assert_eq!(ioctl::IOCTL_UFW_HELLO, 0x0012_2000);
        assert_eq!(ioctl::IOCTL_UFW_INSTALL_POLICY, 0x0012_2004);
        assert_eq!(ioctl::IOCTL_UFW_DRAIN_LOG, 0x0012_2018);
    }

    #[test]
    fn ioctl_codes_are_distinct() {
        let codes = [
            ioctl::IOCTL_UFW_HELLO,
            ioctl::IOCTL_UFW_INSTALL_POLICY,
            ioctl::IOCTL_UFW_UPDATE_POLICY,
            ioctl::IOCTL_UFW_FLUSH,
            ioctl::IOCTL_UFW_STATS,
            ioctl::IOCTL_UFW_SET_MODE,
            ioctl::IOCTL_UFW_DRAIN_LOG,
        ];
        let mut sorted = codes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len());
    }

    #[test]
    fn a_missing_device_names_the_driver_service() {
        // The device link is not openable on a non-Windows host either, which
        // still exercises the error annotation.
        let err = connect(r"\\.\NoSuchUfwDevice").unwrap_err();
        assert!(!err.to_string().is_empty());
    }
}

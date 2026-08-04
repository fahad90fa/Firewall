//! macOS endpoint: the socket in the shared app-group container.
//!
//! # Why a socket and not raw XPC
//!
//! The Network Extension and the daemon are members of the same application
//! group, which gives them a shared container directory. Two channels are
//! available across that boundary:
//!
//! * **A mach XPC service** (`com.unifiedfirewall.policy.xpc`) — the
//!   documented, Apple-blessed mechanism, and what
//!   `NetworkExtension/IPCBridge.swift` advertises.
//! * **A UNIX domain socket in the group container** — permitted from inside
//!   the Network Extension sandbox, and a plain byte stream.
//!
//! The extension listens on both. The daemon uses the socket, because it makes
//! the framing, multiplexing and bounds checking identical to the other two
//! platforms — one implementation, one set of tests, one place for a framing
//! bug to hide. The XPC listener remains for clients that cannot open a socket
//! in the container, notably a management tool running outside the group.
//!
//! # Container path
//!
//! `~/Library/Group Containers/<group>/ufw-control.sock` for a launchd *agent*,
//! `/Library/Group Containers/<group>/ufw-control.sock` for a system daemon.
//! The daemon tries the system path first and falls back to the user one, so
//! the same binary works in both deployment shapes.

use std::io;
use std::path::PathBuf;

use super::Transport;

/// System-wide container path. Overridable through `ipc.endpoint`.
pub const DEFAULT_ENDPOINT: &str =
    "/Library/Group Containers/group.com.unifiedfirewall/ufw-control.sock";

pub fn connect(endpoint: &str) -> io::Result<Box<dyn Transport>> {
    let candidates: Vec<PathBuf> = if endpoint.is_empty() {
        default_candidates()
    } else {
        vec![PathBuf::from(endpoint)]
    };

    let mut last: Option<io::Error> = None;
    for path in &candidates {
        match open_socket(path) {
            Ok(t) => return Ok(t),
            Err(e) => last = Some(e),
        }
    }

    let tried = candidates
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let kind = last
        .as_ref()
        .map(|e| e.kind())
        .unwrap_or(io::ErrorKind::NotFound);
    Err(io::Error::new(
        kind,
        format!(
            "could not reach the Network Extension (tried {tried}); check that the system \
             extension is activated with `systemextensionsctl list` and approved in \
             System Settings > Privacy & Security"
        ),
    ))
}

fn default_candidates() -> Vec<PathBuf> {
    let group = ufw_shared::constants::MACOS_APP_GROUP;
    let mut out = vec![PathBuf::from(DEFAULT_ENDPOINT)];
    if let Ok(home) = std::env::var("HOME") {
        out.push(
            PathBuf::from(home)
                .join("Library/Group Containers")
                .join(group)
                .join("ufw-control.sock"),
        );
    }
    out
}

#[cfg(unix)]
fn open_socket(path: &std::path::Path) -> io::Result<Box<dyn Transport>> {
    use super::StreamTransport;
    let stream = std::os::unix::net::UnixStream::connect(path)?;
    Ok(Box::new(StreamTransport::new(
        stream,
        path.display().to_string(),
    )))
}

#[cfg(not(unix))]
fn open_socket(path: &std::path::Path) -> io::Result<Box<dyn Transport>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "{} is a UNIX domain socket, which this host cannot open",
            path.display()
        ),
    ))
}

/// XPC service name, for the alternative channel and for diagnostics.
pub const XPC_SERVICE: &str = ufw_shared::constants::MACOS_XPC_SERVICE;

/// The bundle identifier of the system extension, used by `ufwctl status` to
/// report activation state.
pub const SYSTEM_EXTENSION_ID: &str = "com.unifiedfirewall.extension";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_socket_points_at_the_extension_approval_step() {
        let err = connect("/nonexistent/ufw-control.sock").unwrap_err();
        assert!(
            err.to_string().contains("systemextensionsctl"),
            "the error should tell an operator where to look: {err}"
        );
    }

    #[test]
    fn the_default_candidates_include_the_system_container() {
        let candidates = default_candidates();
        assert!(candidates
            .iter()
            .any(|p| p.to_string_lossy().starts_with("/Library/Group Containers")));
        for p in &candidates {
            assert!(p.to_string_lossy().ends_with("ufw-control.sock"));
        }
    }

    #[test]
    fn the_error_names_every_path_it_tried() {
        let err = connect("").unwrap_err();
        let text = err.to_string();
        assert!(text.contains("/Library/Group Containers"), "{text}");
    }
}

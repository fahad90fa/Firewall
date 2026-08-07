//! Linux endpoint: the kernel module's control character device.
//!
//! # Why a character device rather than netlink
//!
//! The Linux kernel module exposes two interfaces, and they carry different
//! kinds of traffic:
//!
//! * **`/dev/ufw-control`** — a misc character device implementing
//!   `IRP`-equivalent read/write file operations over the framed protocol in
//!   `ufw_shared::protocol`. This is the control channel: handshake, policy
//!   install and update, identity queries and answers, statistics.
//!
//! * **Generic netlink family `ufw_policy`, multicast group `ufw_log`** — a
//!   fan-out channel for log events, so that observers other than the daemon
//!   (a debugging tool, a second collector) can subscribe without contending
//!   for the control device.
//!
//! The daemon uses the character device for everything, including log events,
//! which the module mirrors to both. That choice buys three things worth more
//! than the netlink socket's fan-out: the control path needs no `libc`
//! dependency and therefore no unsafe code in the daemon; framing is identical
//! on all three platforms so it is written and tested once; and a blocking
//! `read(2)` on a device is trivially interruptible by closing the file
//! descriptor, which is how the reader thread is stopped.
//!
//! The eBPF maps are *not* driven through this channel. The daemon updates
//! them through the pinned objects under
//! [`ufw_shared::constants::LINUX_BPF_PIN_DIR`], which is what the pinning
//! exists for.

use std::fs::OpenOptions;
use std::io;

use super::{StreamTransport, Transport};

/// Character device the kernel module registers.
pub const DEFAULT_ENDPOINT: &str = "/dev/ufw-control";

/// Open the control endpoint.
///
/// Two kinds of endpoint carry the same framed protocol:
///
/// * a **character device** (`/dev/ufw-control`), which is what the loaded
///   kernel module registers, and
/// * a **Unix-domain socket**, which is what a userspace peer serving the
///   control protocol exposes — the kernel-module simulator (`ufw-kmod-sim`),
///   or a test harness pointed at with `ipc.endpoint`.
///
/// The distinction is only in the syscall that opens the endpoint; everything
/// above the transport is identical. The socket case exists so the daemon and
/// its dashboard can be exercised end to end — handshake, policy install,
/// stats, mode changes — without loading a kernel module, which is the only
/// way to do that on a host where loading one is not an option.
pub fn connect(endpoint: &str) -> io::Result<Box<dyn Transport>> {
    let path = if endpoint.is_empty() {
        DEFAULT_ENDPOINT
    } else {
        endpoint
    };

    if let Some(result) = connect_socket(path) {
        return result;
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| annotate(path, e))?;

    Ok(Box::new(StreamTransport::new(file, path)))
}

/// Connect to `path` as a Unix-domain socket, or `None` when it is not one.
///
/// The endpoint is treated as a socket only when it already exists *and* is a
/// socket; anything else (a char device, a missing path) falls through to the
/// device open, so the "module not loaded" diagnostic on `/dev/ufw-control` is
/// unchanged.
#[cfg(unix)]
fn connect_socket(path: &str) -> Option<io::Result<Box<dyn Transport>>> {
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::net::UnixStream;

    let is_socket = std::fs::metadata(path)
        .map(|m| m.file_type().is_socket())
        .unwrap_or(false);
    if !is_socket {
        return None;
    }

    Some(match UnixStream::connect(path) {
        Ok(stream) => Ok(Box::new(StreamTransport::new(stream, path))),
        Err(e) => Err(annotate(path, e)),
    })
}

#[cfg(not(unix))]
fn connect_socket(_path: &str) -> Option<io::Result<Box<dyn Transport>>> {
    None
}

/// Turn the raw `open` failure into something an operator can act on. "No such
/// file or directory" on this path almost always means the module is not
/// loaded, and saying so saves a support round trip.
fn annotate(path: &str, e: io::Error) -> io::Error {
    let hint = match e.kind() {
        io::ErrorKind::NotFound => format!(
            "{path} does not exist; the kernel module is probably not loaded \
             (try `modprobe ufw` or check `dmesg` for a load failure)"
        ),
        io::ErrorKind::PermissionDenied => format!(
            "{path} is not writable by this process; the daemon needs CAP_NET_ADMIN \
             and access to the control device"
        ),
        _ => format!("cannot open {path}: {e}"),
    };
    io::Error::new(e.kind(), hint)
}

/// Where the daemon expects to find pinned eBPF objects.
pub fn bpf_pin_paths() -> Vec<String> {
    let base = ufw_shared::constants::LINUX_BPF_PIN_DIR;
    ["rules", "conntrack", "counters", "prog_ingress"]
        .iter()
        .map(|name| format!("{base}/{name}"))
        .collect()
}

/// Whether the pinned eBPF objects are present.
///
/// Their absence is not fatal — the netfilter table enforces the whole policy
/// on its own — but it means the fast path is not active, which is worth
/// reporting rather than leaving as an unexplained performance difference.
pub fn fast_path_available() -> bool {
    bpf_pin_paths()
        .iter()
        .all(|p| std::path::Path::new(p).exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_device_explains_that_the_module_is_not_loaded() {
        let err = connect("/nonexistent/ufw-control").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(
            err.to_string()
                .contains("kernel module is probably not loaded"),
            "{err}"
        );
    }

    #[test]
    fn the_default_endpoint_is_used_when_none_is_configured() {
        let err = connect("").unwrap_err();
        assert!(err.to_string().contains(DEFAULT_ENDPOINT), "{err}");
    }

    #[test]
    fn pin_paths_live_under_the_documented_directory() {
        let paths = bpf_pin_paths();
        assert_eq!(paths.len(), 4);
        for p in paths {
            assert!(p.starts_with(ufw_shared::constants::LINUX_BPF_PIN_DIR));
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_socket_endpoint_is_opened_as_a_stream_not_a_device() {
        use std::os::unix::net::UnixListener;
        use std::sync::atomic::{AtomicU32, Ordering};

        // A unique, self-cleaning socket path — no device node, so this proves
        // the connect path takes the socket branch rather than `open(2)` on a
        // char device.
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "ufw-linux-connect-{}-{}.sock",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind");

        let transport = connect(path.to_str().unwrap()).expect("connect to socket");
        assert_eq!(transport.endpoint(), path.to_string_lossy());

        drop(listener);
        let _ = std::fs::remove_file(&path);
    }
}

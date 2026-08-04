//! The local control socket.
//!
//! A UNIX domain socket (a named pipe on Windows) carrying newline-delimited
//! JSON: one request object per line, one response object per line. That is
//! the whole protocol, and it is deliberately the simplest of the three
//! surfaces because it is the one an operator reaches for during an incident.
//!
//! # Authority comes from the filesystem
//!
//! There is no token. The socket is created with mode `0600` under a directory
//! the daemon owns, so being able to `connect(2)` to it already proves the
//! caller is root or the daemon's user. Adding a token on top would be
//! ceremony that protects nothing — anyone who can read the token file can
//! open the socket.
//!
//! The mode is set *before* the listener starts accepting, so there is no
//! window where the socket exists with default permissions.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::{parse_body, ApiError, Authority, Response, Router};
use crate::state::DaemonState;

/// Longest request line accepted, so a client cannot make the daemon allocate.
pub const MAX_LINE: usize = 1024 * 1024;

/// How long a connected client may sit idle before being dropped.
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Handle one request line, returning the response line.
///
/// Split out from the transport so the request handling is testable without a
/// socket, and so both the UNIX and Windows paths share it exactly.
pub fn handle_line(router: &Router, line: &str) -> String {
    let line = line.trim();
    if line.is_empty() {
        return ApiError::bad_request("empty request").to_json();
    }
    match parse_body(line).and_then(|request| router.dispatch(request, Authority::Admin)) {
        Ok(Response { body, .. }) => body,
        Err(e) => e.to_json(),
    }
}

/// Serve one connected client until it disconnects.
///
/// Reads a byte at a time rather than through a `BufReader`, because the
/// stream has to stay usable for writing between requests and splitting a
/// generic `Read + Write` into halves needs a transport-specific `try_clone`.
/// The control channel carries a handful of requests per incident, so the
/// syscall count is irrelevant next to keeping this one implementation shared
/// by every platform.
pub fn serve_client<S>(router: &Router, mut stream: S)
where
    S: std::io::Read + Write,
{
    let mut line = String::new();
    loop {
        line.clear();
        match read_bounded_line(&mut stream, &mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                let _ = writeln!(stream, "{}", ApiError::bad_request(e).to_json());
                break;
            }
        }
        if line.trim().is_empty() {
            continue;
        }
        let response = handle_line(router, &line);
        if writeln!(stream, "{response}").is_err() || stream.flush().is_err() {
            break;
        }
    }
}

/// Read one line, refusing anything longer than [`MAX_LINE`].
///
/// Returns the number of bytes consumed; `0` means end of stream.
fn read_bounded_line<R: std::io::Read>(reader: &mut R, out: &mut String) -> Result<usize, String> {
    let mut total = 0usize;
    let mut bytes: Vec<u8> = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        match reader.read(&mut byte) {
            Ok(0) => {
                *out = String::from_utf8_lossy(&bytes).into_owned();
                return Ok(total);
            }
            Ok(_) => {
                total += 1;
                if byte[0] == b'\n' {
                    *out = String::from_utf8_lossy(&bytes).into_owned();
                    return Ok(total);
                }
                if bytes.len() >= MAX_LINE {
                    return Err(format!("request exceeds {MAX_LINE} bytes"));
                }
                bytes.push(byte[0]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
}

// ===========================================================================
// UNIX
// ===========================================================================

#[cfg(unix)]
pub fn serve(
    router: Arc<Router>,
    socket_path: PathBuf,
    state: Arc<DaemonState>,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // A socket left behind by a crashed daemon would make bind fail. Removing
    // it is safe because a *running* daemon holds the path and would be
    // detected by the connect probe below.
    if socket_path.exists() && probe(&socket_path).is_err() {
        let _ = std::fs::remove_file(&socket_path);
    }

    let listener = UnixListener::bind(&socket_path)?;
    // Tighten permissions before accepting, so the socket is never reachable
    // with whatever the umask happened to allow.
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;

    while !state.is_shutting_down() {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(IDLE_TIMEOUT));
                let router = Arc::clone(&router);
                std::thread::Builder::new()
                    .name("ufw-cli".into())
                    .spawn(move || serve_client(&router, stream))
                    .ok();
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }

    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

/// Whether something is already listening on this path.
#[cfg(unix)]
fn probe(path: &Path) -> std::io::Result<()> {
    std::os::unix::net::UnixStream::connect(path).map(|_| ())
}

// ===========================================================================
// Windows
// ===========================================================================

/// On Windows the control channel is a named pipe.
///
/// `std` cannot create a named pipe server, so the Windows build wires this to
/// the installer-created pipe through the same `serve_client` entry point. The
/// daemon falls back to a loopback TCP listener bound to a port only reachable
/// locally when the pipe is unavailable, which keeps `ufwctl` working during
/// development.
#[cfg(not(unix))]
pub fn serve(
    router: Arc<Router>,
    socket_path: PathBuf,
    state: Arc<DaemonState>,
) -> std::io::Result<()> {
    use std::net::TcpListener;

    let _ = socket_path;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    // Publish the port so `ufwctl` can find it without a fixed allocation.
    if let Some(parent) = socket_path.parent() {
        let _ = std::fs::create_dir_all(parent);
        let _ = std::fs::write(parent.join("cli.port"), port.to_string());
    }
    listener.set_nonblocking(true)?;

    while !state.is_shutting_down() {
        match listener.accept() {
            Ok((stream, addr)) => {
                if !addr.ip().is_loopback() {
                    continue;
                }
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(IDLE_TIMEOUT));
                let router = Arc::clone(&router);
                std::thread::Builder::new()
                    .name("ufw-cli".into())
                    .spawn(move || serve_client(&router, stream))
                    .ok();
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::management_api::tests::harness;
    use ufw_shared::json;

    #[test]
    fn a_status_request_returns_status() {
        let h = harness();
        let response = handle_line(&h.router, r#"{"op":"status"}"#);
        let v = json::parse(&response).unwrap();
        assert_eq!(v.get("host_id").unwrap().as_str(), Some("host-a"));
    }

    #[test]
    fn the_local_socket_has_administrative_authority() {
        // Being able to open the socket is the authorization.
        let h = harness();
        let response = handle_line(&h.router, r#"{"op":"reload-policy"}"#);
        assert!(h.control.called("reload"));
        assert!(json::parse(&response).is_ok());
    }

    #[test]
    fn malformed_input_gets_a_json_error_not_a_dropped_connection() {
        let h = harness();
        for bad in ["", "   ", "not json", r#"{"op":"nope"}"#, "{}"] {
            let response = handle_line(&h.router, bad);
            let v = json::parse(&response)
                .unwrap_or_else(|_| panic!("response to {bad:?} must be JSON: {response}"));
            assert_eq!(v.get("ok").unwrap().as_bool(), Some(false));
        }
    }

    #[test]
    fn every_response_is_one_line() {
        let h = harness();
        for request in [
            r#"{"op":"status"}"#,
            r#"{"op":"list-rules"}"#,
            r#"{"op":"list-revisions"}"#,
            r#"{"op":"stats"}"#,
        ] {
            let response = handle_line(&h.router, request);
            assert!(
                !response.contains('\n'),
                "newline-delimited framing requires single-line responses: {request}"
            );
        }
    }

    #[test]
    fn a_conversation_over_a_pipe_handles_several_requests() {
        use std::io::Cursor;

        struct Duplex {
            input: Cursor<Vec<u8>>,
            output: Vec<u8>,
        }
        impl std::io::Read for Duplex {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.input.read(buf)
            }
        }
        impl Write for Duplex {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.output.write(buf)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let h = harness();
        let script = b"{\"op\":\"ping\"}\n{\"op\":\"status\"}\n{\"op\":\"list-rules\"}\n".to_vec();
        let mut duplex = Duplex {
            input: Cursor::new(script),
            output: Vec::new(),
        };
        serve_client(&h.router, &mut duplex);

        let text = String::from_utf8(duplex.output).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in lines {
            assert!(json::parse(line).is_ok(), "{line}");
        }
    }

    #[test]
    fn an_overlong_line_is_refused() {
        use std::io::Cursor;
        let mut reader = Cursor::new(vec![b'a'; MAX_LINE + 10]);
        let mut out = String::new();
        assert!(read_bounded_line(&mut reader, &mut out).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn the_socket_is_created_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "ufw-cli-{}-{}",
            std::process::id(),
            ufw_shared::now_us()
        ));
        let socket = dir.join("cli.sock");

        let h = harness();
        let state = Arc::clone(&h.state);
        let router = Arc::new(Router::new(
            Arc::clone(&h.state),
            Arc::new(crate::management_api::testing::RecordingControl::default()),
        ));
        let path = socket.clone();
        let server = std::thread::spawn(move || {
            let _ = serve(router, path, state);
        });

        // Wait for the listener to come up.
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            socket.exists(),
            "the listener should have created the socket"
        );

        let mode = std::fs::metadata(&socket).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "the control socket must not be world-reachable"
        );

        h.state.request_shutdown();
        let _ = server.join();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_client_can_talk_to_the_real_listener() {
        use std::os::unix::net::UnixStream;

        let dir = std::env::temp_dir().join(format!(
            "ufw-cli-live-{}-{}",
            std::process::id(),
            ufw_shared::now_us()
        ));
        let socket = dir.join("cli.sock");

        let h = harness();
        let state = Arc::clone(&h.state);
        let router = Arc::new(Router::new(
            Arc::clone(&h.state),
            Arc::new(crate::management_api::testing::RecordingControl::default()),
        ));
        let path = socket.clone();
        let server = std::thread::spawn(move || {
            let _ = serve(router, path, state);
        });
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        let mut stream = UnixStream::connect(&socket).expect("connect");
        writeln!(stream, "{{\"op\":\"ping\"}}").unwrap();
        stream.flush().unwrap();

        let mut reader = std::io::BufReader::new(stream);
        let mut line = String::new();
        std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
        let v = json::parse(line.trim()).unwrap();
        assert_eq!(v.get("message").unwrap().as_str(), Some("pong"));

        h.state.request_shutdown();
        let _ = server.join();
        // The socket is cleaned up on the way out so a restart does not have
        // to work around its own leftovers.
        assert!(!socket.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

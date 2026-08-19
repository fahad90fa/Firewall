//! Transport to the daemon's control socket.
//!
//! Newline-delimited JSON over a UNIX domain socket, matching
//! `daemon/src/management_api/cli.rs`. The [`Transport`] trait exists so the
//! command implementations can be tested against a scripted daemon rather than
//! a running one — which is what makes the CLI's own behaviour (argument
//! handling, formatting, exit codes) testable at all.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::Duration;

use ufw_shared::json::{self, Json, JsonWriter};

use crate::{CliError, GlobalOptions};

/// A round trip to the daemon.
pub trait Transport {
    /// Send one request line, return the response line.
    fn call(&mut self, request: &str) -> Result<String, CliError>;
}

/// The real socket.
#[derive(Debug)]
pub struct SocketTransport {
    #[cfg(unix)]
    stream: std::os::unix::net::UnixStream,
    #[cfg(not(unix))]
    stream: std::net::TcpStream,
}

impl SocketTransport {
    #[cfg(unix)]
    pub fn connect(path: &Path, timeout: Duration) -> Result<Self, CliError> {
        let stream = std::os::unix::net::UnixStream::connect(path)
            .map_err(|e| CliError::Unreachable(format!("{}: {e}", path.display())))?;
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));
        Ok(SocketTransport { stream })
    }

    /// On Windows the daemon publishes a loopback port beside the configured
    /// socket path, because `std` cannot create a named-pipe server.
    #[cfg(not(unix))]
    pub fn connect(path: &Path, timeout: Duration) -> Result<Self, CliError> {
        let port_file = path
            .parent()
            .map(|p| p.join("cli.port"))
            .ok_or_else(|| CliError::Unreachable("no control socket directory".into()))?;
        let port: u16 = std::fs::read_to_string(&port_file)
            .map_err(|e| CliError::Unreachable(format!("{}: {e}", port_file.display())))?
            .trim()
            .parse()
            .map_err(|_| CliError::Unreachable("malformed control port file".into()))?;
        let stream = std::net::TcpStream::connect(("127.0.0.1", port))
            .map_err(|e| CliError::Unreachable(format!("127.0.0.1:{port}: {e}")))?;
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));
        Ok(SocketTransport { stream })
    }
}

impl Transport for SocketTransport {
    fn call(&mut self, request: &str) -> Result<String, CliError> {
        writeln!(self.stream, "{request}")
            .and_then(|()| self.stream.flush())
            .map_err(|e| CliError::Unreachable(e.to_string()))?;

        let mut reader = BufReader::new(&mut self.stream);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| CliError::Unreachable(e.to_string()))?;
        if line.trim().is_empty() {
            return Err(CliError::Unreachable(
                "the daemon closed the connection without answering".into(),
            ));
        }
        Ok(line.trim().to_string())
    }
}

/// Build the transport for a set of global options.
pub fn connect(options: &GlobalOptions) -> Result<SocketTransport, CliError> {
    SocketTransport::connect(&options.socket, Duration::from_secs(options.timeout_secs))
}

/// A transport that connects on first use.
///
/// Argument validation lives inside the command functions, where the argument's
/// meaning is known. Connecting before dispatch would therefore report
/// `ufwctl policy rollback soon` as an unreachable daemon — exit code 3, and a
/// diagnosis pointing at the wrong machine — on any host where the daemon
/// happens to be down. Deferring the connect until a request is actually sent
/// keeps every failure attributable to the thing that caused it, and costs
/// nothing: a command that reaches the daemon connects at the same moment it
/// would have anyway.
#[derive(Debug)]
pub struct LazyTransport {
    options: GlobalOptions,
    inner: Option<SocketTransport>,
}

impl LazyTransport {
    pub fn new(options: &GlobalOptions) -> Self {
        LazyTransport {
            options: options.clone(),
            inner: None,
        }
    }

    /// Whether a connection was ever opened. Used by the tests to assert that
    /// a usage error never touches the socket.
    pub fn connected(&self) -> bool {
        self.inner.is_some()
    }
}

impl Transport for LazyTransport {
    fn call(&mut self, request: &str) -> Result<String, CliError> {
        if self.inner.is_none() {
            self.inner = Some(connect(&self.options)?);
        }
        self.inner.as_mut().expect("just connected").call(request)
    }
}

/// A request builder, so command modules do not hand-write JSON.
#[derive(Debug)]
pub struct RequestBuilder {
    writer: JsonWriter,
}

impl RequestBuilder {
    pub fn new(op: &str) -> Self {
        let mut writer = JsonWriter::new();
        writer.begin_object();
        writer.str_field("op", op);
        RequestBuilder { writer }
    }

    pub fn str(mut self, key: &str, value: &str) -> Self {
        self.writer.str_field(key, value);
        self
    }

    pub fn opt_str(self, key: &str, value: Option<&str>) -> Self {
        match value {
            Some(v) => self.str(key, v),
            None => self,
        }
    }

    pub fn num(mut self, key: &str, value: u64) -> Self {
        self.writer.u64_field(key, value);
        self
    }

    pub fn str_list(mut self, key: &str, values: &[String]) -> Self {
        self.writer
            .str_array_field(key, values.iter().map(|s| s.as_str()));
        self
    }

    pub fn finish(mut self) -> String {
        self.writer.end_object();
        self.writer.finish()
    }
}

/// Send a request and return the raw response, turning a daemon-side error
/// into a [`CliError`].
pub fn call(transport: &mut dyn Transport, request: String) -> Result<String, CliError> {
    let raw = transport.call(&request)?;
    let parsed = json::parse(&raw)
        .map_err(|e| CliError::Local(format!("the daemon sent malformed JSON: {e}\n{raw}")))?;

    // The daemon marks failures with `ok: false` and a status; anything else
    // is a successful payload, which may legitimately have no `ok` field.
    if parsed.get("ok").and_then(|v| v.as_bool()) == Some(false) {
        return Err(CliError::Daemon {
            status: parsed.get("status").and_then(|v| v.as_u64()).unwrap_or(500) as u16,
            message: parsed
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("the daemon reported a failure")
                .to_string(),
        });
    }
    Ok(raw)
}

/// Parse a response for a command that needs to inspect it.
pub fn parse(raw: &str) -> Result<Json, CliError> {
    json::parse(raw).map_err(|e| CliError::Local(e.to_string()))
}

#[cfg(test)]
pub mod testing {
    use super::*;

    /// A daemon that answers from a script.
    #[derive(Debug, Default)]
    pub struct ScriptedTransport {
        pub responses: Vec<String>,
        pub requests: Vec<String>,
    }

    impl ScriptedTransport {
        pub fn new(responses: impl IntoIterator<Item = impl Into<String>>) -> Self {
            ScriptedTransport {
                responses: responses.into_iter().map(Into::into).collect(),
                requests: Vec::new(),
            }
        }

        pub fn last_request(&self) -> Option<&str> {
            self.requests.last().map(String::as_str)
        }
    }

    impl Transport for ScriptedTransport {
        fn call(&mut self, request: &str) -> Result<String, CliError> {
            self.requests.push(request.to_string());
            if self.responses.is_empty() {
                return Err(CliError::Unreachable("no scripted response".into()));
            }
            Ok(self.responses.remove(0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::ScriptedTransport;
    use super::*;

    #[test]
    fn requests_serialize_the_documented_shape() {
        let request = RequestBuilder::new("list-rules")
            .str("filter", "dns")
            .finish();
        assert_eq!(request, r#"{"op":"list-rules","filter":"dns"}"#);

        let request = RequestBuilder::new("rollback").num("revision", 7).finish();
        assert_eq!(request, r#"{"op":"rollback","revision":7}"#);

        let request = RequestBuilder::new("status")
            .opt_str("filter", None)
            .finish();
        assert_eq!(request, r#"{"op":"status"}"#);
    }

    #[test]
    fn a_successful_response_comes_back_verbatim() {
        let mut t = ScriptedTransport::new([r#"{"ok":true,"host_id":"web-01"}"#]);
        let raw = call(&mut t, RequestBuilder::new("status").finish()).unwrap();
        assert_eq!(raw, r#"{"ok":true,"host_id":"web-01"}"#);
        assert_eq!(t.last_request(), Some(r#"{"op":"status"}"#));
    }

    #[test]
    fn a_daemon_error_becomes_a_cli_error_with_its_status() {
        let mut t = ScriptedTransport::new([
            r#"{"ok":false,"status":403,"error":"requires administrative authority"}"#,
        ]);
        let err = call(&mut t, RequestBuilder::new("flush-policy").finish()).unwrap_err();
        assert_eq!(err.exit_code(), 1);
        match &err {
            CliError::Daemon { status, message } => {
                assert_eq!(*status, 403);
                assert!(message.contains("administrative"));
            }
            other => panic!("expected a daemon error, got {other:?}"),
        }
    }

    #[test]
    fn a_payload_without_an_ok_field_is_still_a_success() {
        // `status` answers with the state object, which has no `ok`.
        let mut t = ScriptedTransport::new([r#"{"health":"enforcing"}"#]);
        assert!(call(&mut t, RequestBuilder::new("status").finish()).is_ok());
    }

    #[test]
    fn malformed_json_from_the_daemon_is_reported_with_the_payload() {
        let mut t = ScriptedTransport::new(["}{"]);
        let err = call(&mut t, RequestBuilder::new("status").finish()).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("malformed JSON"), "{text}");
        assert!(text.contains("}{"), "the raw payload should be shown");
    }

    #[test]
    fn a_lazy_transport_does_not_connect_until_a_request_is_sent() {
        let options = GlobalOptions {
            socket: "/nonexistent/ufw.sock".into(),
            ..Default::default()
        };
        let mut t = LazyTransport::new(&options);
        assert!(!t.connected());
        // The first request is what fails, and it fails as unreachable.
        let err = t.call(r#"{"op":"status"}"#).unwrap_err();
        assert_eq!(err.exit_code(), 3);
        assert!(!t.connected(), "a failed connect leaves nothing cached");
    }

    #[test]
    fn an_unreachable_daemon_exits_with_its_own_code() {
        let mut t = ScriptedTransport::default();
        let err = call(&mut t, RequestBuilder::new("status").finish()).unwrap_err();
        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains("ufwd is running"));
    }
}

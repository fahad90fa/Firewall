//! `ufwctl` — the Unified Firewall management CLI.
//!
//! The CLI is a thin client. It parses arguments, sends one JSON request to
//! the daemon's control socket, and formats the reply. Every decision about
//! *what an operation means* lives in the daemon, which is what keeps the
//! three management surfaces consistent.
//!
//! The one thing it does locally is compile a policy: `ufwctl policy validate`
//! and `ufwctl policy compile` link the same compiler the daemon uses, so a
//! policy can be checked in CI on a machine with no daemon, no kernel module
//! and no privileges.

pub mod client;
pub mod commands;
pub mod output;

use output::Format;

/// Global options, parsed before the subcommand.
#[derive(Debug, Clone)]
pub struct GlobalOptions {
    /// Path to the daemon's control socket.
    pub socket: std::path::PathBuf,
    pub format: Format,
    /// Seconds to wait for the daemon.
    pub timeout_secs: u64,
    /// Suppress non-essential output.
    pub quiet: bool,
}

impl Default for GlobalOptions {
    fn default() -> Self {
        GlobalOptions {
            socket: std::path::PathBuf::from(ufw_shared::constants::DEFAULT_CLI_SOCKET_UNIX),
            format: Format::Table,
            timeout_secs: 10,
            quiet: false,
        }
    }
}

/// What went wrong.
#[derive(Debug)]
pub enum CliError {
    /// Bad arguments. Exit code 2, like a UNIX usage error.
    Usage(String),
    /// The daemon could not be reached.
    Unreachable(String),
    /// The daemon answered with an error.
    Daemon { status: u16, message: String },
    /// A local operation failed (compiling a policy, writing a file).
    Local(String),
}

impl CliError {
    /// Exit code, following the convention: 0 success, 1 operation failed,
    /// 2 usage error, 3 daemon unreachable.
    pub fn exit_code(&self) -> u8 {
        match self {
            CliError::Usage(_) => 2,
            CliError::Unreachable(_) => 3,
            CliError::Daemon { .. } | CliError::Local(_) => 1,
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Usage(m) => write!(f, "{m}\n\nTry `ufwctl --help`."),
            CliError::Unreachable(m) => write!(
                f,
                "cannot reach the daemon: {m}\n\n\
                 Check that ufwd is running and that this user can open its control socket."
            ),
            CliError::Daemon { status, message } => write!(f, "{message} (status {status})"),
            CliError::Local(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for CliError {}

pub type CliResult = Result<String, CliError>;

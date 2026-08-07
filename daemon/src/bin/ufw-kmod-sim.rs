//! `ufw-kmod-sim` — a userspace kernel-module simulator for the Unified
//! Firewall daemon.
//!
//! It serves the module half of the daemon ↔ kernel control protocol over a
//! Unix-domain socket, so a daemon pointed at that socket connects, installs
//! its policy, reports statistics and answers `ufwctl status` and the dashboard
//! as though a kernel module were loaded — **without loading one, and without
//! filtering any traffic.** See `ufw_daemon::ipc::simulator` for exactly what it
//! does and does not do.
//!
//! ```text
//!   ufw-kmod-sim --endpoint /tmp/ufw-control.sock
//!   ufwd --config with  ipc.endpoint = "/tmp/ufw-control.sock"
//! ```

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    use std::os::unix::net::UnixListener;
    use std::path::Path;

    use ufw_daemon::ipc::simulator;
    use ufw_shared::constants;

    const DEFAULT_ENDPOINT: &str = "/tmp/ufw-control.sock";

    // --- arguments -------------------------------------------------------
    let mut endpoint = DEFAULT_ENDPOINT.to_string();
    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage(DEFAULT_ENDPOINT);
                return std::process::ExitCode::SUCCESS;
            }
            "-V" | "--version" => {
                println!("ufw-kmod-sim {}", constants::VERSION);
                return std::process::ExitCode::SUCCESS;
            }
            "-e" | "--endpoint" => match argv.next() {
                Some(v) => endpoint = v,
                None => {
                    eprintln!("ufw-kmod-sim: --endpoint needs a path");
                    return std::process::ExitCode::FAILURE;
                }
            },
            other => {
                eprintln!("ufw-kmod-sim: unknown argument `{other}` (try --help)");
                return std::process::ExitCode::FAILURE;
            }
        }
    }

    // --- socket ----------------------------------------------------------
    let path = Path::new(&endpoint);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!(
                    "ufw-kmod-sim: cannot create {}: {e}",
                    parent.display()
                );
                return std::process::ExitCode::FAILURE;
            }
        }
    }

    // A stale socket file from a previous run makes bind fail with
    // "address already in use"; the endpoint is ours to own, so clear it.
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            use std::os::unix::fs::FileTypeExt;
            if meta.file_type().is_socket() {
                let _ = std::fs::remove_file(path);
            } else {
                eprintln!(
                    "ufw-kmod-sim: {} exists and is not a socket; refusing to remove it",
                    path.display()
                );
                return std::process::ExitCode::FAILURE;
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            eprintln!("ufw-kmod-sim: cannot stat {}: {e}", path.display());
            return std::process::ExitCode::FAILURE;
        }
    }

    let listener = match UnixListener::bind(path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ufw-kmod-sim: cannot bind {}: {e}", path.display());
            return std::process::ExitCode::FAILURE;
        }
    };

    // --- banner ----------------------------------------------------------
    eprintln!("ufw-kmod-sim {} — USERSPACE SIMULATOR", constants::VERSION);
    eprintln!("  listening on : {}", path.display());
    eprintln!("  platform     : {}", simulator::PLATFORM);
    eprintln!();
    eprintln!("  This is NOT a firewall. It filters no traffic and enforces no");
    eprintln!("  policy. It makes the daemon's control channel connect so the");
    eprintln!("  management surface can be exercised without a kernel module.");
    eprintln!();
    eprintln!("  Point the daemon at it with, in the daemon's config:");
    eprintln!();
    eprintln!("      [ipc]");
    eprintln!("      endpoint = \"{}\"", path.display());
    eprintln!();
    eprintln!("  Stop with Ctrl-C.");

    // --- serve -----------------------------------------------------------
    let result = simulator::serve(&listener);

    // Best-effort cleanup on a clean exit; a signal-terminated process leaves
    // the socket behind, which the stale-socket handling above clears next run.
    let _ = std::fs::remove_file(path);

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ufw-kmod-sim: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(unix)]
fn print_usage(default_endpoint: &str) {
    println!(
        "\
ufw-kmod-sim — userspace kernel-module simulator for the Unified Firewall daemon

USAGE:
    ufw-kmod-sim [OPTIONS]

OPTIONS:
    -e, --endpoint <PATH>   Unix socket to listen on
                            [default: {default_endpoint}]
    -V, --version           Print the version and exit
    -h, --help              Print this help and exit

It serves the daemon ↔ kernel control protocol over the socket so the daemon
connects and the management surface works without a loaded kernel module. It
filters no traffic and enforces no policy. Point the daemon at it by setting
`ipc.endpoint` to the same path in the daemon's configuration."
    );
}

#[cfg(not(unix))]
fn main() {
    eprintln!("ufw-kmod-sim: the simulator uses Unix-domain sockets and is only available on Unix");
    std::process::exit(1);
}

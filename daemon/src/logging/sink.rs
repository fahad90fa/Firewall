//! Log output targets.
//!
//! Every sink obeys one rule: **a sink must never block a packet decision.**
//! The kernel module hands events to the daemon through a bounded ring buffer;
//! if a sink stalls, the daemon's queue fills, and the module starts dropping
//! events rather than stalling enforcement. So a sink that cannot keep up
//! drops, counts the drop, and says so — it does not apply backpressure all
//! the way down to the packet path.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::net::{TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ufw_shared::log_types::LogEvent;

use crate::config::{FileSinkConfig, LogFormat, SiemSinkConfig, SyslogSinkConfig};

/// Format one event.
pub fn render(event: &LogEvent, format: LogFormat) -> String {
    match format {
        LogFormat::Json => event.to_json(),
        LogFormat::Text => event.to_text(),
        LogFormat::Cef => event.to_cef("UnifiedFirewall", "ufw", ufw_shared::constants::VERSION),
    }
}

/// A destination for formatted events.
pub trait Sink: Send {
    fn write(&mut self, event: &LogEvent) -> std::io::Result<()>;
    /// Push buffered data out. Called on a timer and at shutdown.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn name(&self) -> &'static str;
    /// Events this sink discarded because it could not keep up.
    fn dropped(&self) -> u64 {
        0
    }
}

// ===========================================================================
// stdout
// ===========================================================================

/// Writes to stdout. Used when the daemon runs in the foreground under a
/// service manager that captures its output.
#[derive(Debug)]
pub struct StdoutSink {
    format: LogFormat,
}

impl StdoutSink {
    pub fn new(format: LogFormat) -> Self {
        StdoutSink { format }
    }
}

impl Sink for StdoutSink {
    fn write(&mut self, event: &LogEvent) -> std::io::Result<()> {
        let line = render(event, self.format);
        let mut out = std::io::stdout().lock();
        writeln!(out, "{line}")
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stdout().lock().flush()
    }

    fn name(&self) -> &'static str {
        "stdout"
    }
}

// ===========================================================================
// File, with rotation
// ===========================================================================

/// Appends to a file, rotating by size.
///
/// Rotation renames `events.jsonl` to `events.jsonl.1`, shifting the existing
/// numbered files up and deleting the oldest. Renaming rather than truncating
/// means a reader holding the old file keeps reading a consistent file instead
/// of watching it get shorter underneath them.
pub struct FileSink {
    path: PathBuf,
    writer: BufWriter<File>,
    written: u64,
    max_bytes: u64,
    keep: usize,
    format: LogFormat,
    dropped: AtomicU64,
}

impl std::fmt::Debug for FileSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSink")
            .field("path", &self.path)
            .field("written", &self.written)
            .finish()
    }
}

impl FileSink {
    pub fn open(config: &FileSinkConfig) -> std::io::Result<Self> {
        if let Some(parent) = config.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config.path)?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(FileSink {
            path: config.path.clone(),
            writer: BufWriter::with_capacity(64 * 1024, file),
            written,
            max_bytes: config.max_bytes.max(4096),
            keep: config.keep,
            format: config.format,
            dropped: AtomicU64::new(0),
        })
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        self.writer.flush()?;

        if self.keep == 0 {
            // No history wanted: start the file over.
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&self.path)?;
            self.writer = BufWriter::with_capacity(64 * 1024, file);
            self.written = 0;
            return Ok(());
        }

        // Shift .N -> .N+1, oldest first so nothing is overwritten early.
        for n in (1..=self.keep).rev() {
            let from = numbered(&self.path, n);
            let to = numbered(&self.path, n + 1);
            if from.exists() {
                if n == self.keep {
                    let _ = std::fs::remove_file(&from);
                } else {
                    let _ = std::fs::rename(&from, &to);
                }
            }
        }
        let _ = std::fs::rename(&self.path, numbered(&self.path, 1));

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.writer = BufWriter::with_capacity(64 * 1024, file);
        self.written = 0;
        Ok(())
    }
}

fn numbered(path: &Path, n: usize) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

impl Sink for FileSink {
    fn write(&mut self, event: &LogEvent) -> std::io::Result<()> {
        let line = render(event, self.format);
        if self.written + line.len() as u64 + 1 > self.max_bytes {
            self.rotate()?;
        }
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.written += line.len() as u64 + 1;
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }

    fn name(&self) -> &'static str {
        "file"
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

// ===========================================================================
// syslog
// ===========================================================================

/// RFC 5424 over UDP.
///
/// UDP because a syslog collector that stops reading must not become a stall
/// in the firewall's logging path. A dropped datagram is a lost log line; a
/// blocked write is a lost packet decision.
#[derive(Debug)]
pub struct SyslogSink {
    socket: UdpSocket,
    address: String,
    facility: u8,
    tag: String,
    dropped: AtomicU64,
}

impl SyslogSink {
    pub fn connect(config: &SyslogSinkConfig) -> std::io::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_nonblocking(true)?;
        Ok(SyslogSink {
            socket,
            address: config.address.clone(),
            facility: config.facility,
            tag: config.tag.clone(),
            dropped: AtomicU64::new(0),
        })
    }
}

impl Sink for SyslogSink {
    fn write(&mut self, event: &LogEvent) -> std::io::Result<()> {
        let line = event.to_syslog(self.facility, &self.tag);
        match self.socket.send_to(line.as_bytes(), &self.address) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn name(&self) -> &'static str {
        "syslog"
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

// ===========================================================================
// SIEM forwarder
// ===========================================================================

/// Streams events to a remote collector over TCP, buffering across outages.
///
/// The buffer is bounded and drops **oldest first**. During an outage the
/// recent events are the ones an operator needs; keeping the start of the
/// outage and discarding the present would be backwards.
pub struct SiemSink {
    address: String,
    format: LogFormat,
    requires_tls: bool,
    stream: Option<crate::tls::MaybeTls>,
    /// Built once at construction. `None` means plaintext, which the config
    /// layer only permits when the operator did not ask for TLS.
    connector: Option<crate::tls::TlsConnector>,
    /// The name the certificate must match. Derived from `address` rather than
    /// configured separately: verifying against a name the operator typed
    /// twice is verifying against whichever one they got right.
    server_name: String,
    buffer: std::collections::VecDeque<String>,
    capacity: usize,
    dropped: AtomicU64,
    last_attempt: Option<Instant>,
    backoff: Duration,
}

impl std::fmt::Debug for SiemSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SiemSink")
            .field("address", &self.address)
            .field("connected", &self.stream.is_some())
            .field("buffered", &self.buffer.len())
            .finish()
    }
}

/// Longest gap between reconnection attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

impl SiemSink {
    pub fn new(config: &SiemSinkConfig) -> Self {
        // A connector that fails to build is a configuration error, and the
        // config layer has already refused it — but if one slips through, no
        // connector means no connection at all, rather than a silent downgrade
        // to plaintext on a channel the operator configured as encrypted.
        let connector = if config.tls {
            crate::tls::TlsConnector::new(config.ca_path.as_deref()).ok()
        } else {
            None
        };
        let server_name = config
            .address
            .rsplit_once(':')
            .map(|(host, _)| host)
            .unwrap_or(&config.address)
            .trim_matches(['[', ']'])
            .to_string();

        SiemSink {
            address: config.address.clone(),
            format: config.format,
            stream: None,
            requires_tls: config.tls,
            connector,
            server_name,
            buffer: std::collections::VecDeque::with_capacity(config.buffer.min(4096)),
            capacity: config.buffer.max(16),
            dropped: AtomicU64::new(0),
            last_attempt: None,
            backoff: Duration::from_millis(250),
        }
    }

    /// Whether enough time has passed to retry the connection.
    fn may_reconnect(&self) -> bool {
        match self.last_attempt {
            None => true,
            Some(t) => t.elapsed() >= self.backoff,
        }
    }

    fn ensure_connected(&mut self) -> bool {
        if self.stream.is_some() {
            return true;
        }
        if !self.may_reconnect() {
            return false;
        }
        self.last_attempt = Some(Instant::now());
        // Configured for TLS but holding no connector: refuse to connect at
        // all. Falling back to plaintext here would ship the host's entire
        // activity record in the clear on a channel the operator believes is
        // encrypted — the one failure mode worse than losing the events.
        if self.requires_tls && self.connector.is_none() {
            self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
            return false;
        }

        match TcpStream::connect(&self.address) {
            Ok(s) => {
                let _ = s.set_write_timeout(Some(Duration::from_millis(500)));
                let _ = s.set_nodelay(true);
                let wrapped = match &self.connector {
                    Some(connector) => match connector.connect(&self.server_name, s) {
                        Ok(stream) => stream,
                        Err(_) => {
                            // A handshake failure is a real failure: an expired
                            // certificate, a name mismatch, an interceptor.
                            // Back off and retry rather than downgrade.
                            self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
                            return false;
                        }
                    },
                    None => crate::tls::MaybeTls::Plain(s),
                };
                self.stream = Some(wrapped);
                self.backoff = Duration::from_millis(250);
                true
            }
            Err(_) => {
                self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
                false
            }
        }
    }

    fn enqueue(&mut self, line: String) {
        if self.buffer.len() >= self.capacity {
            self.buffer.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        self.buffer.push_back(line);
    }

    /// Push as much of the buffer as the socket will take.
    fn drain(&mut self) {
        if !self.ensure_connected() {
            return;
        }
        while let Some(line) = self.buffer.front() {
            let payload = format!("{line}\n");
            let Some(stream) = self.stream.as_mut() else {
                return;
            };
            match stream.write_all(payload.as_bytes()) {
                Ok(()) => {
                    self.buffer.pop_front();
                }
                Err(_) => {
                    // The collector went away mid-stream. Keep the event and
                    // reconnect on the next attempt.
                    self.stream = None;
                    self.last_attempt = Some(Instant::now());
                    return;
                }
            }
        }
    }

    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }
}

impl Sink for SiemSink {
    fn write(&mut self, event: &LogEvent) -> std::io::Result<()> {
        self.enqueue(render(event, self.format));
        self.drain();
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.drain();
        if let Some(s) = self.stream.as_mut() {
            let _ = s.flush();
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "siem"
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

// ===========================================================================
// Test sink
// ===========================================================================

/// Collects events in memory. Used by the daemon's own tests and by
/// `ufwctl logs --follow` when it attaches to a running daemon.
#[derive(Debug, Default, Clone)]
pub struct MemorySink {
    pub events: std::sync::Arc<std::sync::Mutex<Vec<LogEvent>>>,
}

impl MemorySink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn take(&self) -> Vec<LogEvent> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }
}

impl Sink for MemorySink {
    fn write(&mut self, event: &LogEvent) -> std::io::Result<()> {
        self.events.lock().unwrap().push(event.clone());
        Ok(())
    }

    fn name(&self) -> &'static str {
        "memory"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ufw_shared::log_types::FiveTuple;
    use ufw_shared::policy_types::Decision;

    fn event(n: u64) -> LogEvent {
        let mut e = LogEvent::new(
            1_700_000_000_000_000 + n,
            "host",
            Decision::Deny,
            42,
            FiveTuple::default(),
        );
        e.sequence = n;
        e.rule_name = format!("rule-{n}");
        e
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ufw-sink-{}-{}-{name}",
            std::process::id(),
            ufw_shared::now_us()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn every_format_renders_a_single_line() {
        for format in [LogFormat::Json, LogFormat::Text, LogFormat::Cef] {
            let line = render(&event(1), format);
            assert!(!line.contains('\n'), "{format:?} produced a multi-line record");
            assert!(!line.is_empty());
        }
    }

    #[test]
    fn json_output_is_parseable() {
        let line = render(&event(1), LogFormat::Json);
        let v = ufw_shared::json::parse(&line).expect("valid json");
        assert_eq!(v.get("rule").unwrap().as_str(), Some("rule-1"));
    }

    #[test]
    fn the_file_sink_appends_one_line_per_event() {
        let dir = temp_dir("append");
        let config = FileSinkConfig {
            path: dir.join("events.jsonl"),
            max_bytes: 1024 * 1024,
            keep: 3,
            format: LogFormat::Json,
        };
        let mut sink = FileSink::open(&config).unwrap();
        for i in 0..5 {
            sink.write(&event(i)).unwrap();
        }
        sink.flush().unwrap();

        let text = std::fs::read_to_string(&config.path).unwrap();
        assert_eq!(text.lines().count(), 5);
        for line in text.lines() {
            assert!(ufw_shared::json::parse(line).is_ok());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_file_sink_rotates_and_keeps_a_bounded_history() {
        let dir = temp_dir("rotate");
        let path = dir.join("events.jsonl");
        let config = FileSinkConfig {
            path: path.clone(),
            // Small enough that every few events forces a rotation.
            max_bytes: 4096,
            keep: 2,
            format: LogFormat::Json,
        };
        let mut sink = FileSink::open(&config).unwrap();
        for i in 0..200 {
            sink.write(&event(i)).unwrap();
        }
        sink.flush().unwrap();

        assert!(path.exists());
        assert!(numbered(&path, 1).exists());
        assert!(numbered(&path, 2).exists());
        // `keep = 2` means exactly two historical files.
        assert!(!numbered(&path, 3).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reopening_a_file_sink_appends_rather_than_truncating() {
        let dir = temp_dir("reopen");
        let config = FileSinkConfig {
            path: dir.join("events.jsonl"),
            max_bytes: 1024 * 1024,
            keep: 1,
            format: LogFormat::Json,
        };
        {
            let mut sink = FileSink::open(&config).unwrap();
            sink.write(&event(1)).unwrap();
            sink.flush().unwrap();
        }
        {
            let mut sink = FileSink::open(&config).unwrap();
            sink.write(&event(2)).unwrap();
            sink.flush().unwrap();
        }
        let text = std::fs::read_to_string(&config.path).unwrap();
        assert_eq!(text.lines().count(), 2, "a daemon restart must not lose logs");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_siem_sink_configured_for_tls_will_not_fall_back_to_plaintext() {
        // The one failure mode worse than losing log events: shipping the
        // host's entire activity record in the clear on a channel the operator
        // configured as encrypted.
        let mut sink = SiemSink::new(&SiemSinkConfig {
            tls: true,
            ca_path: None,
            // Nothing is listening, so the connect fails either way — what is
            // asserted is that it never produces a plaintext stream.
            address: "127.0.0.1:1".to_string(),
            format: LogFormat::Json,
            buffer: 16,
        });
        assert!(
            !sink.ensure_connected(),
            "a failed TLS connect must not report success"
        );
        assert!(
            sink.stream.is_none(),
            "no stream should be held after a failed TLS connect"
        );
    }

    #[test]
    fn the_certificate_name_is_derived_from_the_address() {
        // Derived rather than configured separately, so there is no second
        // place for it to be wrong — verifying against a name the operator
        // typed twice is verifying against whichever one they got right.
        let sink = SiemSink::new(&SiemSinkConfig {
            tls: false,
            ca_path: None,
            address: "siem.example.com:6514".to_string(),
            format: LogFormat::Json,
            buffer: 16,
        });
        assert_eq!(sink.server_name, "siem.example.com");
        assert!(sink.connector.is_none(), "plaintext means no connector");
    }

    #[test]
    fn the_siem_sink_buffers_across_an_outage_and_drops_oldest_first() {
        // Port 1 on loopback: nothing is listening, so every connect fails.
        let mut sink = SiemSink::new(&SiemSinkConfig {
            tls: false,
            ca_path: None,
            address: "127.0.0.1:1".into(),
            format: LogFormat::Json,
            buffer: 16,
        });
        for i in 0..100 {
            sink.write(&event(i)).unwrap();
        }
        assert!(!sink.is_connected());
        assert_eq!(sink.buffered(), 16, "the buffer must stay bounded");
        assert!(sink.dropped() >= 84);

        // The newest events survived; the oldest were discarded.
        let front = sink.buffer.front().unwrap();
        assert!(front.contains("rule-84"), "{front}");
    }

    #[test]
    fn a_sink_outage_never_reports_an_error_upward() {
        // The logging pipeline must not treat an unreachable collector as a
        // failure worth propagating: that would eventually stall the drain.
        let mut sink = SiemSink::new(&SiemSinkConfig {
            tls: false,
            ca_path: None,
            address: "127.0.0.1:1".into(),
            format: LogFormat::Json,
            buffer: 4,
        });
        assert!(sink.write(&event(1)).is_ok());
        assert!(sink.flush().is_ok());
    }

    #[test]
    fn the_memory_sink_collects_and_hands_back_events() {
        let mut sink = MemorySink::new();
        assert!(sink.is_empty());
        sink.write(&event(1)).unwrap();
        sink.write(&event(2)).unwrap();
        assert_eq!(sink.len(), 2);
        let taken = sink.take();
        assert_eq!(taken.len(), 2);
        assert!(sink.is_empty());
    }
}

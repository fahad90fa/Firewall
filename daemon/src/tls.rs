//! TLS termination for the network-facing surfaces.
//!
//! # Why this is a build-time option rather than always on
//!
//! The workspace is otherwise dependency-free, because everything in it lands
//! in the trusted computing base of a kernel-mode filtering decision and a
//! compromise in a transitive dependency would be a compromise of what the
//! machine is allowed to talk to.
//!
//! TLS is the one place that reasoning does not survive contact with reality.
//! The alternative to a vetted library is a hand-written one, and hand-rolled
//! crypto in a security product is strictly worse than no TLS at all — it looks
//! like protection and is not. So the choice is pushed to the operator:
//!
//! ```text
//! cargo build                    zero dependencies, loopback or a proxy
//! cargo build --features tls     rustls, TLS terminated in the daemon
//! ```
//!
//! Both are supported deployments. What is *not* supported is configuring TLS
//! and silently getting plaintext: a binary built without the feature refuses
//! to start when the configuration asks for TLS, naming the feature.
//!
//! # What it protects
//!
//! The management API can install policy, which makes it a remote code path
//! into the kernel. Bearer-token authentication over plaintext protects the
//! token from nothing — anyone on the path reads it and then owns the machine's
//! filtering policy.
//!
//! The SIEM sink is the other direction: log events carry process paths, remote
//! addresses and which rules fired, which is a description of everything the
//! host does. Shipping that in the clear is an inventory for whoever is
//! listening.

use std::io::{self, Read, Write};
use std::path::PathBuf;

/// How a listener should be wrapped.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsConfig {
    /// PEM certificate chain, leaf first.
    pub cert_path: Option<PathBuf>,
    /// PEM private key: PKCS#8, PKCS#1 or SEC1.
    pub key_path: Option<PathBuf>,
    /// Require a client certificate signed by one of these CAs.
    ///
    /// Optional, and worth using: a bearer token authenticates whoever holds
    /// it, while a client certificate authenticates a key that cannot be
    /// copied out of a log file or a shell history.
    pub client_ca_path: Option<PathBuf>,
}

impl TlsConfig {
    /// Whether the operator asked for TLS at all.
    pub fn is_enabled(&self) -> bool {
        self.cert_path.is_some() || self.key_path.is_some()
    }

    /// Validate the combination, without reading the files.
    ///
    /// A half-configured TLS block is the dangerous case: a certificate with no
    /// key would, under a more forgiving design, fall back to plaintext on the
    /// port the operator believes is encrypted.
    pub fn validate(&self) -> Result<(), String> {
        match (&self.cert_path, &self.key_path) {
            (None, None) => Ok(()),
            (Some(_), None) => Err("api.tls_cert is set but api.tls_key is not; a certificate \
                 without a key cannot serve TLS, and falling back to plaintext \
                 on a port you believe is encrypted is worse than refusing"
                .into()),
            (None, Some(_)) => Err("api.tls_key is set but api.tls_cert is not".into()),
            (Some(cert), Some(key)) => {
                if !cert.exists() {
                    return Err(format!("api.tls_cert: {} does not exist", cert.display()));
                }
                if !key.exists() {
                    return Err(format!("api.tls_key: {} does not exist", key.display()));
                }
                if let Some(ca) = &self.client_ca_path {
                    if !ca.exists() {
                        return Err(format!(
                            "api.tls_client_ca: {} does not exist",
                            ca.display()
                        ));
                    }
                }
                Ok(())
            }
        }
    }
}

/// Whether this binary can terminate TLS.
pub const fn available() -> bool {
    cfg!(feature = "tls")
}

/// The message shown when configuration asks for something the build cannot do.
///
/// Named rather than generic: "TLS is not available" sends an operator looking
/// for a missing library, when the answer is a build flag.
pub fn unavailable_message() -> String {
    format!(
        "this build cannot terminate TLS, but the configuration asks for it.\n\
         \n\
         Either rebuild with TLS support:\n\
             cargo build --release --features tls\n\
         \n\
         or remove api.tls_cert / api.tls_key and terminate TLS in front of the\n\
         daemon (see docs/deployment/), or keep the API on loopback.\n\
         \n\
         Refusing to start rather than serving plaintext on a port configured\n\
         for TLS.\n\
         (built {} TLS support)",
        if available() { "with" } else { "without" }
    )
}

/// A stream that may or may not be wrapped.
///
/// The servers are written against `Read + Write` and do not know which they
/// have — which is what keeps the TLS path from being a second, subtly
/// different copy of the request handling.
pub enum MaybeTls {
    Plain(std::net::TcpStream),
    #[cfg(feature = "tls")]
    Tls(Box<rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream>>),
    #[cfg(feature = "tls")]
    TlsClient(Box<rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>>),
}

impl Read for MaybeTls {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            MaybeTls::Plain(s) => s.read(buf),
            #[cfg(feature = "tls")]
            MaybeTls::Tls(s) => s.read(buf),
            #[cfg(feature = "tls")]
            MaybeTls::TlsClient(s) => s.read(buf),
        }
    }
}

impl Write for MaybeTls {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            MaybeTls::Plain(s) => s.write(buf),
            #[cfg(feature = "tls")]
            MaybeTls::Tls(s) => s.write(buf),
            #[cfg(feature = "tls")]
            MaybeTls::TlsClient(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            MaybeTls::Plain(s) => s.flush(),
            #[cfg(feature = "tls")]
            MaybeTls::Tls(s) => s.flush(),
            #[cfg(feature = "tls")]
            MaybeTls::TlsClient(s) => s.flush(),
        }
    }
}

impl MaybeTls {
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        match self {
            MaybeTls::Plain(s) => s.peer_addr(),
            #[cfg(feature = "tls")]
            MaybeTls::Tls(s) => s.get_ref().peer_addr(),
            #[cfg(feature = "tls")]
            MaybeTls::TlsClient(s) => s.get_ref().peer_addr(),
        }
    }

    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> io::Result<()> {
        match self {
            MaybeTls::Plain(s) => s.set_read_timeout(timeout),
            #[cfg(feature = "tls")]
            MaybeTls::Tls(s) => s.get_ref().set_read_timeout(timeout),
            #[cfg(feature = "tls")]
            MaybeTls::TlsClient(s) => s.get_ref().set_read_timeout(timeout),
        }
    }
}

// ---------------------------------------------------------------------------
// With the feature
// ---------------------------------------------------------------------------

#[cfg(feature = "tls")]
mod imp {
    use super::*;
    use std::path::Path;
    use std::sync::Arc;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::server::WebPkiClientVerifier;
    use rustls::{RootCertStore, ServerConfig};

    /// A prepared server configuration.
    #[derive(Clone)]
    pub struct TlsAcceptor {
        config: Arc<ServerConfig>,
    }

    impl std::fmt::Debug for TlsAcceptor {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TlsAcceptor").finish()
        }
    }

    impl TlsAcceptor {
        /// Load the certificate, key and optional client CA.
        ///
        /// Everything is read and validated *here*, at startup, rather than on
        /// the first connection. A daemon that starts, reports healthy, and
        /// then fails every request because the key is malformed is far harder
        /// to diagnose than one that refuses to start and says which file.
        pub fn from_config(config: &TlsConfig) -> Result<Self, String> {
            let cert_path = config
                .cert_path
                .as_ref()
                .ok_or("no certificate configured")?;
            let key_path = config.key_path.as_ref().ok_or("no key configured")?;

            let certs = load_certs(cert_path)?;
            if certs.is_empty() {
                return Err(format!(
                    "{}: no certificates found. The file must be PEM with at \
                     least one CERTIFICATE block, leaf first.",
                    cert_path.display()
                ));
            }
            let key = load_key(key_path)?;

            let builder = match &config.client_ca_path {
                Some(ca_path) => {
                    let mut roots = RootCertStore::empty();
                    for ca in load_certs(ca_path)? {
                        roots
                            .add(ca)
                            .map_err(|e| format!("{}: {e}", ca_path.display()))?;
                    }
                    if roots.is_empty() {
                        return Err(format!(
                            "{}: no CA certificates found, so no client could \
                             ever authenticate",
                            ca_path.display()
                        ));
                    }
                    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                        .build()
                        .map_err(|e| format!("building the client verifier: {e}"))?;
                    ServerConfig::builder().with_client_cert_verifier(verifier)
                }
                None => ServerConfig::builder().with_no_client_auth(),
            };

            let mut server_config = builder
                .with_single_cert(certs, key)
                .map_err(|e| format!("certificate and key do not match: {e}"))?;

            // The management API is machine-to-machine. No browser is going to
            // negotiate HTTP/2 here, and advertising it would invite a client
            // to speak a protocol the hand-written HTTP/1.1 server does not
            // implement — which presents as a hang, not an error.
            server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

            Ok(TlsAcceptor {
                config: Arc::new(server_config),
            })
        }

        /// Wrap an accepted connection.
        pub fn accept(&self, stream: std::net::TcpStream) -> io::Result<MaybeTls> {
            let connection = rustls::ServerConnection::new(Arc::clone(&self.config))
                .map_err(|e| io::Error::other(e.to_string()))?;
            Ok(MaybeTls::Tls(Box::new(rustls::StreamOwned::new(
                connection, stream,
            ))))
        }
    }

    /// The client half, for shipping log events to a SIEM.
    ///
    /// Certificate verification is on and there is no option to turn it off.
    /// A `--insecure` flag on a log shipper is a flag somebody sets during an
    /// outage and nobody unsets, and the events it carries — process paths,
    /// remote addresses, which rules fired — are a description of everything
    /// the host does.
    #[derive(Clone)]
    pub struct TlsConnector {
        config: Arc<rustls::ClientConfig>,
    }

    impl std::fmt::Debug for TlsConnector {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TlsConnector").finish()
        }
    }

    impl TlsConnector {
        /// Trust the platform roots, plus an optional private CA.
        ///
        /// The private CA matters: a SIEM collector inside a corporate network
        /// is usually signed by an internal authority, and the alternative to
        /// supporting that is operators disabling verification.
        pub fn new(extra_ca: Option<&Path>) -> Result<Self, String> {
            let mut roots = RootCertStore::empty();
            // `add_parsable_certificates` rather than `add` in a loop: a
            // system bundle contains hundreds of certificates and a handful
            // are routinely expired or use an algorithm rustls declines. One
            // unparsable entry must not empty the trust store.
            let (added, _ignored) = roots.add_parsable_certificates(webpki_roots_or_empty());
            let _ = added;

            if let Some(path) = extra_ca {
                let certs = load_certs(path)?;
                if certs.is_empty() {
                    return Err(format!("{}: no CA certificates found", path.display()));
                }
                for ca in certs {
                    roots
                        .add(ca)
                        .map_err(|e| format!("{}: {e}", path.display()))?;
                }
            }

            if roots.is_empty() {
                return Err("no trust anchors available: neither platform roots nor a \
                     configured logging.siem_ca_path. Refusing to ship log \
                     events to an unverifiable peer."
                    .into());
            }

            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            Ok(TlsConnector {
                config: Arc::new(config),
            })
        }

        pub fn connect(
            &self,
            server_name: &str,
            stream: std::net::TcpStream,
        ) -> io::Result<MaybeTls> {
            let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("`{server_name}` is not a valid server name for certificate verification"),
                    )
                })?;
            let connection = rustls::ClientConnection::new(Arc::clone(&self.config), name)
                .map_err(|e| io::Error::other(e.to_string()))?;
            Ok(MaybeTls::TlsClient(Box::new(rustls::StreamOwned::new(
                connection, stream,
            ))))
        }
    }

    /// Platform trust anchors.
    ///
    /// rustls does not ship a root store, and `webpki-roots` would be another
    /// dependency. Reading the system bundle keeps the tree small and, more
    /// usefully, means the daemon trusts what the rest of the machine trusts —
    /// including an enterprise root an administrator installed.
    fn webpki_roots_or_empty() -> Vec<CertificateDer<'static>> {
        const CANDIDATES: [&str; 5] = [
            "/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Alpine
            "/etc/pki/tls/certs/ca-bundle.crt",   // Fedora, RHEL
            "/etc/ssl/ca-bundle.pem",             // openSUSE
            "/etc/ssl/cert.pem",                  // macOS, Alpine
            "/usr/local/share/certs/ca-root-nss.crt", // FreeBSD
        ];
        for path in CANDIDATES {
            if let Ok(certs) = load_certs(Path::new(path)) {
                if !certs.is_empty() {
                    return certs;
                }
            }
        }
        Vec::new()
    }

    fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
        let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut reader = std::io::BufReader::new(&data[..]);
        rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
        let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut reader = std::io::BufReader::new(&data[..]);

        // PKCS#8, PKCS#1 and SEC1, in that order. Accepting all three because
        // which one an operator has depends on the tool that generated it, and
        // "your key is in the wrong ASN.1 wrapper" is not a useful error.
        rustls_pemfile::private_key(&mut reader)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .ok_or_else(|| {
                format!(
                    "{}: no private key found. Expected a PEM PRIVATE KEY, \
                     RSA PRIVATE KEY or EC PRIVATE KEY block.",
                    path.display()
                )
            })
    }
}

#[cfg(feature = "tls")]
pub use imp::{TlsAcceptor, TlsConnector};

// ---------------------------------------------------------------------------
// Without the feature
// ---------------------------------------------------------------------------

/// A stand-in so the servers compile identically either way.
///
/// Construction always fails, with the message that names the build flag. The
/// servers therefore have one code path, and the difference between the two
/// builds is a construction that succeeds or one that does not — rather than
/// two versions of the request loop that can drift.
#[cfg(not(feature = "tls"))]
#[derive(Debug, Clone)]
pub struct TlsAcceptor {
    _private: (),
}

/// The client-side stand-in. Same contract as [`TlsAcceptor`]: constructing it
/// fails, naming the build flag, so the SIEM sink has one code path.
#[cfg(not(feature = "tls"))]
#[derive(Debug, Clone)]
pub struct TlsConnector {
    _private: (),
}

#[cfg(not(feature = "tls"))]
impl TlsConnector {
    pub fn new(_extra_ca: Option<&std::path::Path>) -> Result<Self, String> {
        Err(unavailable_message())
    }

    pub fn connect(
        &self,
        _server_name: &str,
        _stream: std::net::TcpStream,
    ) -> io::Result<MaybeTls> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this build cannot terminate TLS",
        ))
    }
}

#[cfg(not(feature = "tls"))]
impl TlsAcceptor {
    pub fn from_config(_config: &TlsConfig) -> Result<Self, String> {
        Err(unavailable_message())
    }

    pub fn accept(&self, _stream: std::net::TcpStream) -> io::Result<MaybeTls> {
        // Unreachable: `from_config` never returns an acceptor in this build.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this build cannot terminate TLS",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_tls_configuration_is_valid() {
        assert!(TlsConfig::default().validate().is_ok());
        assert!(!TlsConfig::default().is_enabled());
    }

    #[test]
    fn a_certificate_without_a_key_is_refused() {
        // The dangerous half-configuration. A forgiving design would fall back
        // to plaintext on the port the operator believes is encrypted.
        let config = TlsConfig {
            cert_path: Some(PathBuf::from("/tmp/cert.pem")),
            key_path: None,
            client_ca_path: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("tls_key"), "{err}");
        assert!(err.contains("worse than refusing"), "{err}");
        assert!(
            config.is_enabled(),
            "a half-configuration still counts as asking for TLS"
        );
    }

    #[test]
    fn a_key_without_a_certificate_is_refused() {
        let config = TlsConfig {
            cert_path: None,
            key_path: Some(PathBuf::from("/tmp/key.pem")),
            client_ca_path: None,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_missing_file_is_named() {
        let config = TlsConfig {
            cert_path: Some(PathBuf::from("/nonexistent/cert.pem")),
            key_path: Some(PathBuf::from("/nonexistent/key.pem")),
            client_ca_path: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("/nonexistent/cert.pem"), "{err}");
    }

    #[test]
    fn the_unavailable_message_names_the_build_flag() {
        // An operator reading "TLS is not available" goes looking for a missing
        // library. The answer is a build flag, so the message says so.
        let message = unavailable_message();
        assert!(message.contains("--features tls"), "{message}");
        assert!(message.contains("loopback"), "{message}");
    }

    #[test]
    fn a_build_without_the_feature_refuses_to_construct_an_acceptor() {
        let config = TlsConfig {
            cert_path: Some(PathBuf::from("/tmp/cert.pem")),
            key_path: Some(PathBuf::from("/tmp/key.pem")),
            client_ca_path: None,
        };
        let result = TlsAcceptor::from_config(&config);

        if available() {
            // With the feature the files are actually read, so this fails for
            // a different reason — the point is that it does not silently
            // succeed and serve plaintext.
            assert!(result.is_err(), "nonexistent files should not load");
        } else {
            let err = result.unwrap_err();
            assert!(err.contains("--features tls"), "{err}");
        }
    }
}

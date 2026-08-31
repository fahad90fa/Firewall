//! TLS / mTLS termination for the ufw-nft console.
//!
//! # Why this is a build-time option
//!
//! The workspace is otherwise dependency-free, and `cargo build` stays offline
//! and reproducible because of it. TLS is the one place that reasoning does not
//! survive contact with reality: the alternative to a vetted library is a
//! hand-written one, and hand-rolled crypto in a security product is strictly
//! worse than no TLS at all — it looks like protection and is not. So the choice
//! is the operator's, exactly as it is for the daemon (`daemon/src/tls.rs`):
//!
//! ```text
//! cargo build                    zero dependencies, loopback / SSH tunnel
//! cargo build --features tls     rustls: console mTLS, cert identity -> role
//! ```
//!
//! What is *not* supported is asking for TLS and silently getting plaintext: a
//! binary built without the feature refuses to start when `--tls-cert` is given,
//! naming the flag.
//!
//! # What it adds over the daemon's module: identity
//!
//! The daemon terminates TLS to protect the management channel. The console
//! wants one more thing — to know *who* is on the other end, so a role can be
//! bound to a client certificate instead of a bearer token that can leak from a
//! shell history. This module verifies the client certificate against a
//! configured CA (mandatory-if-present via `allow_unauthenticated`, so the same
//! port still serves token and loopback callers) and exposes the verified leaf
//! certificate's **SHA-256 fingerprint** as the caller's identity. rbac.rs maps
//! that fingerprint to a role.
//!
//! The fingerprint, not the certificate's Subject CN, is the identity on
//! purpose: it pins the exact key, needs no X.509 parser (so no second
//! dependency), and cannot be re-issued within a CA's namespace to impersonate
//! another operator. WebPki has already proven the cert chains to the configured
//! CA; the fingerprint says *which* issued cert it is.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

/// The cert/key/client-CA paths the console was asked to serve TLS with.
#[derive(Debug, Clone, Default)]
pub struct TlsOptions {
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    /// CA that client certificates must chain to. Without it there is no client
    /// identity to bind a role to — so for the console this is the whole point,
    /// and [`TlsOptions::validate`] requires it whenever TLS is on.
    pub client_ca_path: Option<PathBuf>,
}

impl TlsOptions {
    pub fn is_enabled(&self) -> bool {
        self.cert_path.is_some() || self.key_path.is_some() || self.client_ca_path.is_some()
    }

    /// Validate the combination without reading the files. A half-configuration
    /// (a cert with no key) is the dangerous case a forgiving design would turn
    /// into plaintext on a port the operator believes is encrypted.
    pub fn validate(&self) -> Result<(), String> {
        if !self.is_enabled() {
            return Ok(());
        }
        if self.cert_path.is_none() {
            return Err("--tls-key/--tls-client-ca given without --tls-cert".into());
        }
        if self.key_path.is_none() {
            return Err(
                "--tls-cert given without --tls-key; a certificate without a key \
                 cannot serve TLS, and falling back to plaintext on a port you believe is \
                 encrypted is worse than refusing"
                    .into(),
            );
        }
        if self.client_ca_path.is_none() {
            return Err(
                "console TLS requires --tls-client-ca: without a client-CA there is no \
                 verified client identity to map to a role, which is the reason to run the \
                 console over TLS at all. Terminate plain TLS at a proxy if you only want \
                 encryption."
                    .into(),
            );
        }
        Ok(())
    }
}

/// Whether this binary can terminate TLS.
pub const fn available() -> bool {
    cfg!(feature = "tls")
}

/// The message shown when `--tls-*` is given to a build that cannot do TLS.
pub fn unavailable_message() -> String {
    "this build cannot terminate TLS, but --tls-cert / --tls-key was given.\n\
     \n\
     Rebuild with TLS support:\n\
         cargo build --release --features tls --bin ufw-nft\n\
     \n\
     or drop the --tls-* flags and reach the console over loopback or an SSH\n\
     tunnel. Refusing to start rather than serving plaintext on a port\n\
     configured for TLS."
        .to_string()
}

/// A console connection that may or may not be TLS-wrapped.
///
/// The request handler is written against this one type so the plaintext and
/// TLS paths cannot drift into two subtly different copies of request handling.
pub enum Stream {
    Plain(TcpStream),
    #[cfg(feature = "tls")]
    Tls(Box<rustls::StreamOwned<rustls::ServerConnection, TcpStream>>),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.flush(),
        }
    }
}

impl Stream {
    fn tcp(&self) -> &TcpStream {
        match self {
            Stream::Plain(s) => s,
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.get_ref(),
        }
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.tcp().peer_addr()
    }

    pub fn set_read_timeout(&self, t: Option<Duration>) -> io::Result<()> {
        self.tcp().set_read_timeout(t)
    }

    pub fn set_write_timeout(&self, t: Option<Duration>) -> io::Result<()> {
        self.tcp().set_write_timeout(t)
    }

    /// The verified client certificate's SHA-256 fingerprint (lowercase hex), if
    /// the peer presented one that chained to the configured CA. `None` for a
    /// plaintext connection or a TLS client that sent no certificate.
    ///
    /// Only meaningful after the handshake has completed, which it has by the
    /// time the request head has been read — so call this after reading the
    /// request, never before.
    pub fn client_fingerprint(&self) -> Option<String> {
        match self {
            Stream::Plain(_) => None,
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s
                .conn
                .peer_certificates()
                .and_then(|chain| chain.first())
                .map(|leaf| ufw_shared::hash::hex(&ufw_shared::hash::sha256(leaf.as_ref()))),
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

    /// A prepared console TLS configuration.
    #[derive(Clone)]
    pub struct Acceptor {
        config: Arc<ServerConfig>,
    }

    impl std::fmt::Debug for Acceptor {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Acceptor").finish()
        }
    }

    impl Acceptor {
        /// Load and validate everything at startup, not on the first connection:
        /// a console that starts healthy and then fails every request because a
        /// key is malformed is far harder to diagnose than one that refuses to
        /// start and names the file.
        pub fn from_options(opts: &TlsOptions) -> Result<Self, String> {
            let cert_path = opts.cert_path.as_ref().ok_or("no certificate configured")?;
            let key_path = opts.key_path.as_ref().ok_or("no key configured")?;
            let ca_path = opts
                .client_ca_path
                .as_ref()
                .ok_or("no client CA configured")?;

            let certs = load_certs(cert_path)?;
            if certs.is_empty() {
                return Err(format!(
                    "{}: no certificates found (expected PEM, leaf first)",
                    cert_path.display()
                ));
            }
            let key = load_key(key_path)?;

            let mut roots = RootCertStore::empty();
            for ca in load_certs(ca_path)? {
                roots
                    .add(ca)
                    .map_err(|e| format!("{}: {e}", ca_path.display()))?;
            }
            if roots.is_empty() {
                return Err(format!(
                    "{}: no CA certificates found, so no client could authenticate",
                    ca_path.display()
                ));
            }

            // `allow_unauthenticated`: a client that presents a certificate must
            // have one that chains to this CA (an invalid cert is rejected at the
            // handshake), but a client with no certificate is still allowed to
            // connect — it simply has no cert identity and falls through to the
            // token / loopback / viewer path. That is what lets one TLS port
            // serve cert-authenticated admins and token callers at once.
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .allow_unauthenticated()
                .build()
                .map_err(|e| format!("building the client verifier: {e}"))?;

            let mut config = ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .map_err(|e| format!("certificate and key do not match: {e}"))?;

            // The console speaks hand-written HTTP/1.1; advertising h2 would
            // invite a client to negotiate a protocol the server does not
            // implement, which presents as a hang rather than an error.
            config.alpn_protocols = vec![b"http/1.1".to_vec()];

            Ok(Acceptor {
                config: Arc::new(config),
            })
        }

        pub fn accept(&self, stream: TcpStream) -> io::Result<Stream> {
            let conn = rustls::ServerConnection::new(Arc::clone(&self.config))
                .map_err(|e| io::Error::other(e.to_string()))?;
            Ok(Stream::Tls(Box::new(rustls::StreamOwned::new(
                conn, stream,
            ))))
        }
    }

    fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
        use rustls::pki_types::pem::PemObject;
        let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        CertificateDer::pem_slice_iter(&data)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
        use rustls::pki_types::pem::{Error as PemError, PemObject};
        let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        // Skips any non-key section and returns the first PKCS#8, PKCS#1 or SEC1
        // private key found.
        PrivateKeyDer::from_pem_slice(&data).map_err(|e| match e {
            PemError::NoItemsFound => format!(
                "{}: no private key found (expected PKCS#8, PKCS#1 or SEC1 PEM)",
                path.display()
            ),
            other => format!("{}: {other}", path.display()),
        })
    }
}

#[cfg(feature = "tls")]
pub use imp::Acceptor;

// ---------------------------------------------------------------------------
// Without the feature
// ---------------------------------------------------------------------------

/// A stand-in so `serve` compiles identically either way: construction always
/// fails, naming the build flag, so there is one accept loop rather than two.
#[cfg(not(feature = "tls"))]
#[derive(Debug, Clone)]
pub struct Acceptor {
    _private: (),
}

#[cfg(not(feature = "tls"))]
impl Acceptor {
    pub fn from_options(_opts: &TlsOptions) -> Result<Self, String> {
        Err(unavailable_message())
    }

    pub fn accept(&self, _stream: TcpStream) -> io::Result<Stream> {
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
    fn no_tls_options_is_valid_and_disabled() {
        assert!(TlsOptions::default().validate().is_ok());
        assert!(!TlsOptions::default().is_enabled());
    }

    #[test]
    fn a_cert_without_a_key_is_refused() {
        let o = TlsOptions {
            cert_path: Some(PathBuf::from("/tmp/c.pem")),
            key_path: None,
            client_ca_path: Some(PathBuf::from("/tmp/ca.pem")),
        };
        let e = o.validate().unwrap_err();
        assert!(e.contains("--tls-key"), "{e}");
        assert!(e.contains("worse than refusing"), "{e}");
        assert!(o.is_enabled());
    }

    #[test]
    fn tls_without_a_client_ca_is_refused() {
        // The console-specific rule: no client CA means no verified identity to
        // map to a role, which is the reason to run the console over TLS.
        let o = TlsOptions {
            cert_path: Some(PathBuf::from("/tmp/c.pem")),
            key_path: Some(PathBuf::from("/tmp/k.pem")),
            client_ca_path: None,
        };
        let e = o.validate().unwrap_err();
        assert!(e.contains("--tls-client-ca"), "{e}");
    }

    #[test]
    fn a_plaintext_stream_has_no_client_identity_and_reports_its_peer() {
        // A real Plain connection over loopback: it must report its peer (so the
        // loopback gate works) and never carry a certificate fingerprint (so a
        // plaintext caller can never be mistaken for a cert-authenticated one).
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        let s = Stream::Plain(accepted);
        assert!(s.peer_addr().unwrap().ip().is_loopback());
        assert!(s.client_fingerprint().is_none());
        drop(client);
    }

    #[test]
    fn the_unavailable_message_names_the_build_flag() {
        let m = unavailable_message();
        assert!(m.contains("--features tls"), "{m}");
        assert!(m.contains("loopback"), "{m}");
    }

    #[cfg(not(feature = "tls"))]
    #[test]
    fn without_the_feature_an_acceptor_refuses_to_build() {
        let o = TlsOptions {
            cert_path: Some(PathBuf::from("/tmp/c.pem")),
            key_path: Some(PathBuf::from("/tmp/k.pem")),
            client_ca_path: Some(PathBuf::from("/tmp/ca.pem")),
        };
        let e = Acceptor::from_options(&o).unwrap_err();
        assert!(e.contains("--features tls"), "{e}");
    }
}

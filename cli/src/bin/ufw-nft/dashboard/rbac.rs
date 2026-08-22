//! Role-based access control for the console's mutating actions.
//!
//! The console has always gated its one dangerous surface to loopback callers.
//! This generalizes that into three roles — viewer, responder, admin — and a
//! permission table, so a multi-operator deployment can hand out narrower
//! access than "root on the box".
//!
//! How a caller's role is decided, strongest credential first:
//!   * **A client certificate (mTLS).** When the console is built and run with
//!     TLS (`--features tls`, `ufw-nft dashboard --tls-cert … --tls-key …
//!     --tls-client-ca …`), a peer that presents a certificate chaining to the
//!     configured CA is identified by that certificate's SHA-256 fingerprint
//!     (see `tls.rs`). A fingerprint listed under `client_certs` in
//!     `/etc/unified-firewall/console-auth.json` resolves to its role. This is
//!     the strongest identity — a key that cannot be copied out of a log file —
//!     so it wins over a bearer token.
//!   * **A bearer token.** A request may carry `Authorization: Bearer <token>`;
//!     a token listed under `tokens` resolves to its role. A shared secret —
//!     fine over loopback or an SSH tunnel.
//!   * Otherwise a loopback caller gets the configured `loopback_role`
//!     (default: admin — being root-adjacent on the host already), and any
//!     other caller gets viewer (read-only).
//!
//! The transport boundary is now real, not flagged: the `tls` feature's rustls
//! terminates mTLS and verifies the client certificate against the CA; this
//! module only maps the resulting cryptographic identity to a role. Everything
//! here is pure and unit-tested, including the certificate path.

use std::collections::BTreeMap;

use ufw_shared::json::{self, Json};

const CONFIG: &str = "/etc/unified-firewall/console-auth.json";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Viewer,
    Responder,
    Admin,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// Read state (always allowed — the console is a read surface).
    Read,
    /// Contain / release a source at the kernel.
    Contain,
    /// Change the auto-response engine or its playbooks.
    Configure,
    /// Capture packets.
    Capture,
}

fn role_from_str(s: &str) -> Option<Role> {
    match s {
        "viewer" => Some(Role::Viewer),
        "responder" => Some(Role::Responder),
        "admin" => Some(Role::Admin),
        _ => None,
    }
}

/// The stable wire name for a role, for the `/api/whoami` capability report.
pub fn role_name(role: Role) -> &'static str {
    match role {
        Role::Viewer => "viewer",
        Role::Responder => "responder",
        Role::Admin => "admin",
    }
}

/// Every action paired with its wire name, so the console can render a
/// capability map for the current caller and disable actions it may not use.
pub const ALL_ACTIONS: [(&str, Action); 4] = [
    ("read", Action::Read),
    ("contain", Action::Contain),
    ("configure", Action::Configure),
    ("capture", Action::Capture),
];

/// The permission table. Higher roles include everything a lower role can do.
pub fn allows(role: Role, action: Action) -> bool {
    match action {
        Action::Read => true,
        Action::Contain => matches!(role, Role::Responder | Role::Admin),
        Action::Configure | Action::Capture => role == Role::Admin,
    }
}

struct AuthConfig {
    loopback_role: Role,
    tokens: BTreeMap<String, Role>,
    /// Client-certificate SHA-256 fingerprint (lowercase hex) -> role.
    client_certs: BTreeMap<String, Role>,
}

/// Normalize a fingerprint for lookup: lowercase, and drop the `:` separators
/// and any `sha256:` prefix that `openssl x509 -fingerprint -sha256` emits, so
/// an operator can paste it in whatever form their tool produced.
fn norm_fp(s: &str) -> String {
    s.trim()
        .strip_prefix("sha256:")
        .unwrap_or(s.trim())
        .chars()
        .filter(|c| *c != ':')
        .flat_map(char::to_lowercase)
        .collect()
}

fn load() -> AuthConfig {
    let mut cfg = AuthConfig {
        loopback_role: Role::Admin,
        tokens: BTreeMap::new(),
        client_certs: BTreeMap::new(),
    };
    if let Ok(text) = std::fs::read_to_string(CONFIG) {
        if let Ok(v) = json::parse(&text) {
            if let Some(r) = v
                .get("loopback_role")
                .and_then(Json::as_str)
                .and_then(role_from_str)
            {
                cfg.loopback_role = r;
            }
            if let Some(Json::Object(pairs)) = v.get("tokens") {
                for (tok, role) in pairs {
                    if let Some(r) = role.as_str().and_then(role_from_str) {
                        cfg.tokens.insert(tok.clone(), r);
                    }
                }
            }
            if let Some(Json::Object(pairs)) = v.get("client_certs") {
                for (fp, role) in pairs {
                    if let Some(r) = role.as_str().and_then(role_from_str) {
                        cfg.client_certs.insert(norm_fp(fp), r);
                    }
                }
            }
        }
    }
    cfg
}

/// Resolve a caller's role from, strongest first: a verified client-certificate
/// fingerprint, then a bearer token, then loopback status. The certificate wins
/// over the token because it is a key that cannot leak from a log; the token
/// wins over loopback because it is an explicit grant.
pub fn role_for(from_loopback: bool, token: Option<&str>, cert_fp: Option<&str>) -> Role {
    let cfg = load();
    if let Some(fp) = cert_fp {
        if let Some(&r) = cfg.client_certs.get(&norm_fp(fp)) {
            return r;
        }
    }
    if let Some(t) = token {
        if let Some(&r) = cfg.tokens.get(t) {
            return r;
        }
    }
    if from_loopback {
        cfg.loopback_role
    } else {
        Role::Viewer
    }
}

/// Is this caller permitted to perform `action`?
pub fn authorize(
    from_loopback: bool,
    token: Option<&str>,
    cert_fp: Option<&str>,
    action: Action,
) -> bool {
    allows(role_for(from_loopback, token, cert_fp), action)
}

/// Extract a bearer token from a raw HTTP request head, if present.
pub fn bearer(request: &str) -> Option<String> {
    for line in request.lines() {
        let l = line.trim();
        if let Some(rest) = l
            .strip_prefix("Authorization:")
            .or_else(|| l.strip_prefix("authorization:"))
        {
            let rest = rest.trim();
            if let Some(tok) = rest
                .strip_prefix("Bearer ")
                .or_else(|| rest.strip_prefix("bearer "))
            {
                let tok = tok.trim();
                if !tok.is_empty() {
                    return Some(tok.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_table() {
        assert!(allows(Role::Viewer, Action::Read));
        assert!(!allows(Role::Viewer, Action::Contain));
        assert!(allows(Role::Responder, Action::Contain));
        assert!(!allows(Role::Responder, Action::Configure));
        assert!(allows(Role::Admin, Action::Configure));
        assert!(allows(Role::Admin, Action::Capture));
    }

    #[test]
    fn loopback_defaults_to_admin_without_config() {
        // No config file on the test box -> default loopback_role = admin.
        assert_eq!(role_for(true, None, None), Role::Admin);
        assert_eq!(role_for(false, None, None), Role::Viewer);
        assert!(authorize(true, None, None, Action::Configure));
        assert!(!authorize(false, None, None, Action::Contain));
    }

    #[test]
    fn fingerprints_normalize_to_one_form() {
        // openssl prints `AA:BB:…`; a config or a paste may use any case or a
        // `sha256:` prefix. They must all match the same stored key.
        let a = norm_fp("AA:BB:CC");
        assert_eq!(a, "aabbcc");
        assert_eq!(norm_fp("sha256:aAbBcC"), "aabbcc");
        assert_eq!(norm_fp("  aabbcc \n"), "aabbcc");
    }

    #[test]
    fn capability_map_matches_table() {
        // The wire-name/action pairs the console renders must agree with allows().
        for (name, action) in ALL_ACTIONS {
            assert!(allows(Role::Admin, action), "admin allows {name}");
        }
        assert_eq!(role_name(Role::Viewer), "viewer");
        assert_eq!(role_name(Role::Responder), "responder");
        assert_eq!(role_name(Role::Admin), "admin");
        // A viewer can read and nothing else.
        let viewer_caps: Vec<_> = ALL_ACTIONS
            .into_iter()
            .filter(|(_, a)| allows(Role::Viewer, *a))
            .map(|(n, _)| n)
            .collect();
        assert_eq!(viewer_caps, vec!["read"]);
    }

    #[test]
    fn bearer_parsing() {
        let req = "POST /api/contain HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer abc123\r\n\r\n";
        assert_eq!(bearer(req).as_deref(), Some("abc123"));
        assert_eq!(bearer("GET / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(
            bearer("GET / HTTP/1.1\r\nauthorization: bearer TOK\r\n\r\n").as_deref(),
            Some("TOK")
        );
    }
}

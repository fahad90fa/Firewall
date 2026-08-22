//! Role-based access control for the console's mutating actions.
//!
//! The console has always gated its one dangerous surface to loopback callers.
//! This generalizes that into three roles — viewer, responder, admin — and a
//! permission table, so a multi-operator deployment can hand out narrower
//! access than "root on the box".
//!
//! How a caller's role is decided, and the honest boundary:
//!   * A request may carry `Authorization: Bearer <token>`; a token listed in
//!     `/etc/unified-firewall/console-auth.json` resolves to its configured
//!     role. A bearer token is a real shared secret — fine over loopback or an
//!     SSH tunnel, which is how this console is meant to be reached.
//!   * Otherwise a loopback caller gets the configured `loopback_role`
//!     (default: admin — being root-adjacent on the host already), and any
//!     other caller gets viewer (read-only).
//!
//! What is NOT here, and needs review before it ships: authenticating a
//! *non-loopback* caller by client certificate (mTLS) so a role can be bound to
//! an identity over the network. That needs a real TLS stack (the `tls`
//! feature's rustls), not a hand-rolled one. Until then, reach the console over
//! a tunnel and rely on loopback + tokens. The role/permission logic below is
//! pure and unit-tested, so it is correct the moment a real transport feeds it
//! an authenticated identity.

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
}

fn load() -> AuthConfig {
    let mut cfg = AuthConfig {
        loopback_role: Role::Admin,
        tokens: BTreeMap::new(),
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
        }
    }
    cfg
}

/// Resolve a caller's role from its loopback status and optional bearer token.
pub fn role_for(from_loopback: bool, token: Option<&str>) -> Role {
    let cfg = load();
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
pub fn authorize(from_loopback: bool, token: Option<&str>, action: Action) -> bool {
    allows(role_for(from_loopback, token), action)
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
        assert_eq!(role_for(true, None), Role::Admin);
        assert_eq!(role_for(false, None), Role::Viewer);
        assert!(authorize(true, None, Action::Configure));
        assert!(!authorize(false, None, Action::Contain));
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

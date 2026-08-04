//! Abstract syntax tree for the Unified Policy Language.
//!
//! Every node keeps the span it came from, and every leaf is still a *string*.
//! Nothing here has been interpreted: `action: allowe` parses fine and becomes
//! `Spanned<String>("allowe")`. Deciding that "allowe" is not an action, and
//! saying so with a caret under the right column, is the semantic analyzer's
//! job.
//!
//! Keeping parsing and interpretation apart is what lets the parser report
//! *structural* problems completely (a whole file's worth of them) before the
//! analyzer starts, and lets the analyzer report *meaning* problems without
//! having to guess at recovery.

use crate::error::{Span, Spanned};

/// A whole policy file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyDocument {
    pub span: Span,
    /// Language version. Required; the analyzer rejects unknown versions.
    pub version: Option<Spanned<String>>,
    pub metadata: Option<Metadata>,
    pub defaults: Option<Defaults>,
    /// Other policy files to merge in, resolved relative to this file.
    pub includes: Vec<Spanned<String>>,
    pub address_groups: Vec<AddressGroup>,
    pub port_groups: Vec<PortGroup>,
    pub applications: Vec<Application>,
    pub signature_groups: Vec<SignatureGroup>,
    pub network_profile: Option<NetworkProfile>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Metadata {
    pub span: Span,
    pub name: Option<Spanned<String>>,
    pub description: Option<Spanned<String>>,
    pub revision: Option<Spanned<String>>,
    pub author: Option<Spanned<String>>,
}

/// Policy-wide defaults applied to every rule that does not override them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Defaults {
    pub span: Span,
    /// The verdict when no rule reaches a terminal action.
    pub action: Option<Spanned<String>>,
    pub log: Option<Spanned<String>>,
    pub layer: Option<Spanned<String>>,
    pub priority: Option<Spanned<String>>,
    pub stateful: Option<Spanned<String>>,
}

/// A named set of CIDRs, referenceable from any rule's `addresses:` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressGroup {
    pub span: Span,
    pub name: Spanned<String>,
    /// CIDR literals and references to other address groups, mixed freely.
    pub entries: Vec<Spanned<String>>,
}

/// A named set of ports and port ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortGroup {
    pub span: Span,
    pub name: Spanned<String>,
    pub entries: Vec<Spanned<String>>,
}

/// A named set of DPI signature ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureGroup {
    pub span: Span,
    pub name: Spanned<String>,
    pub entries: Vec<Spanned<String>>,
}

/// An application identity template.
///
/// One logical application has a different fingerprint on each platform — a PE
/// path and an Authenticode subject on Windows, an ELF path and hash on Linux,
/// a bundle id and Team ID on macOS. Declaring them together under one name is
/// what makes a rule like `application: {names: [browser]}` compile to all
/// three backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Application {
    pub span: Span,
    pub name: Spanned<String>,
    pub description: Option<Spanned<String>>,
    pub platforms: Vec<PlatformBlock>,
    /// Trust levels this application is accepted at. Empty means any.
    pub trust: Vec<Spanned<String>>,
    /// Require the signature to validate, not merely to exist.
    pub require_valid_signature: Option<Spanned<String>>,
}

/// The per-platform half of an [`Application`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformBlock {
    pub span: Span,
    /// `windows`, `linux` or `macos`.
    pub platform: Spanned<String>,
    /// Path globs. Case sensitivity is decided from `platform`.
    pub paths: Vec<Spanned<String>>,
    pub sha256: Vec<Spanned<String>>,
    pub signers: Vec<Spanned<String>>,
    pub team_ids: Vec<Spanned<String>>,
    pub bundle_ids: Vec<Spanned<String>>,
}

/// The host's network surroundings (defense Layer 1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkProfile {
    pub span: Span,
    pub internal: Vec<Spanned<String>>,
    pub perimeter: Vec<Spanned<String>>,
    pub gateways: Vec<Spanned<String>>,
    pub dns_servers: Vec<Spanned<String>>,
    pub perimeter_crossing_requires_dpi: Option<Spanned<String>>,
}

/// One rule.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Rule {
    pub span: Span,
    pub id: Option<Spanned<String>>,
    pub description: Option<Spanned<String>>,
    pub priority: Option<Spanned<String>>,
    pub layer: Option<Spanned<String>>,
    pub direction: Option<Spanned<String>>,
    pub action: Option<Spanned<String>>,
    pub protocol: Option<Spanned<String>>,
    pub source: Option<Endpoint>,
    pub destination: Option<Endpoint>,
    pub application: Option<AppSelector>,
    pub dpi: Option<DpiClause>,
    pub interfaces: Vec<Spanned<String>>,
    pub schedule: Option<Schedule>,
    pub log: Option<Spanned<String>>,
    pub stateful: Option<Spanned<String>>,
    pub tags: Vec<Spanned<String>>,
}

/// One side of a rule's network scope.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Endpoint {
    pub span: Span,
    /// CIDR literals or address-group references.
    pub addresses: Vec<Spanned<String>>,
    /// Zone names.
    pub zones: Vec<Spanned<String>>,
    /// Port literals, ranges, or port-group references.
    pub ports: Vec<Spanned<String>>,
    pub negate: Option<Spanned<String>>,
}

/// A rule's application-identity predicate.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AppSelector {
    pub span: Span,
    /// References to `applications:` definitions.
    pub names: Vec<Spanned<String>>,
    /// Inline path globs, for one-off rules that do not deserve a definition.
    pub paths: Vec<Spanned<String>>,
    pub sha256: Vec<Spanned<String>>,
    pub signers: Vec<Spanned<String>>,
    pub team_ids: Vec<Spanned<String>>,
    pub bundle_ids: Vec<Spanned<String>>,
    /// Trust levels, or a single `">= known"`-style bound.
    pub trust: Vec<Spanned<String>>,
    pub require_valid_signature: Option<Spanned<String>>,
    pub negate: Option<Spanned<String>>,
}

impl AppSelector {
    /// Whether the author wrote an empty `application:` block, which almost
    /// certainly is not what they meant.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
            && self.paths.is_empty()
            && self.sha256.is_empty()
            && self.signers.is_empty()
            && self.team_ids.is_empty()
            && self.bundle_ids.is_empty()
            && self.trust.is_empty()
            && self.require_valid_signature.is_none()
    }
}

/// A rule's deep-inspection predicate.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DpiClause {
    pub span: Span,
    /// Signature ids or signature-group references.
    pub signatures: Vec<Spanned<String>>,
    /// Application-layer protocols the flow must have been identified as.
    pub protocols: Vec<Spanned<String>>,
    /// Action to take when the predicate is satisfied. Defaults to `deny`.
    pub on_match: Option<Spanned<String>>,
}

impl DpiClause {
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty() && self.protocols.is_empty()
    }
}

/// A recurring time window during which a rule is active.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Schedule {
    pub span: Span,
    /// Day names (`mon`..`sun`), or `weekdays` / `weekends` / `daily`.
    pub days: Vec<Spanned<String>>,
    /// `HH:MM`, local time.
    pub start: Option<Spanned<String>>,
    pub end: Option<Spanned<String>>,
}

/// Every top-level key the language accepts. Used by the parser to produce
/// "unknown key, did you mean ...?" rather than silently ignoring a typo — a
/// silently ignored key in a firewall policy is a hole.
pub const TOP_LEVEL_KEYS: &[&str] = &[
    "version",
    "metadata",
    "defaults",
    "include",
    "address_groups",
    "port_groups",
    "applications",
    "signature_groups",
    "network_profile",
    "rules",
];

pub const METADATA_KEYS: &[&str] = &["name", "description", "revision", "author"];

pub const DEFAULTS_KEYS: &[&str] = &["action", "log", "layer", "priority", "stateful"];

pub const RULE_KEYS: &[&str] = &[
    "id",
    "description",
    "priority",
    "layer",
    "direction",
    "action",
    "protocol",
    "source",
    "destination",
    "application",
    "dpi",
    "interfaces",
    "schedule",
    "log",
    "stateful",
    "tags",
];

pub const ENDPOINT_KEYS: &[&str] = &["addresses", "zones", "zone", "ports", "negate"];

pub const APP_SELECTOR_KEYS: &[&str] = &[
    "names",
    "name",
    "paths",
    "path",
    "sha256",
    "signers",
    "signer",
    "team_ids",
    "team_id",
    "bundle_ids",
    "bundle_id",
    "trust",
    "require_valid_signature",
    "negate",
];

pub const APPLICATION_KEYS: &[&str] = &[
    "description",
    "platforms",
    "trust",
    "require_valid_signature",
];

pub const PLATFORM_BLOCK_KEYS: &[&str] = &[
    "path",
    "paths",
    "sha256",
    "signer",
    "signers",
    "team_id",
    "team_ids",
    "bundle_id",
    "bundle_ids",
];

pub const DPI_KEYS: &[&str] = &["signatures", "protocols", "protocol", "on_match"];

pub const SCHEDULE_KEYS: &[&str] = &["days", "start", "end"];

pub const NETWORK_PROFILE_KEYS: &[&str] = &[
    "internal",
    "perimeter",
    "gateways",
    "dns_servers",
    "perimeter_crossing_requires_dpi",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_selectors_are_detectable() {
        assert!(AppSelector::default().is_empty());
        let s = AppSelector {
            trust: vec![Spanned::new("trusted".into(), Span::default())],
            ..Default::default()
        };
        assert!(!s.is_empty());

        assert!(DpiClause::default().is_empty());
        let d = DpiClause {
            protocols: vec![Spanned::new("http".into(), Span::default())],
            ..Default::default()
        };
        assert!(!d.is_empty());
    }

    #[test]
    fn key_tables_have_no_duplicates() {
        for table in [
            TOP_LEVEL_KEYS,
            METADATA_KEYS,
            DEFAULTS_KEYS,
            RULE_KEYS,
            ENDPOINT_KEYS,
            APP_SELECTOR_KEYS,
            APPLICATION_KEYS,
            PLATFORM_BLOCK_KEYS,
            DPI_KEYS,
            SCHEDULE_KEYS,
            NETWORK_PROFILE_KEYS,
        ] {
            let mut sorted = table.to_vec();
            sorted.sort_unstable();
            let len = sorted.len();
            sorted.dedup();
            assert_eq!(sorted.len(), len, "duplicate entry in key table {table:?}");
        }
    }
}

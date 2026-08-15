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
    /// Names of definitions that arrived through an `include:`.
    ///
    /// A shared fragment defines more than any one consumer uses — that is
    /// what makes it shareable — so "defined and never referenced" is normal
    /// for these and is not worth reporting. In the file that actually
    /// defines it, an unreferenced group is dead weight or a typo, and is.
    pub included_definitions: std::collections::BTreeSet<String>,
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
    pub rate_limit: Option<RateLimit>,
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

/// A per-rule connection-rate cap (SYN-flood / brute-force dampening).
///
/// Everything is still a string here; the analyzer interprets `rate` as a
/// count, `per` as a time unit, and `burst` as a count. It applies only to
/// permitting rules and is enforced at the nftables layer.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RateLimit {
    pub span: Span,
    pub rate: Option<Spanned<String>>,
    pub per: Option<Spanned<String>>,
    pub burst: Option<Spanned<String>>,
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

/// Point every span in a document at one location.
///
/// A span is a byte range into *one* file's text. When an included document is
/// merged into the including one, its spans keep pointing into the fragment's
/// text while the renderer has only the including file — so a diagnostic about
/// an included definition renders a caret over whatever unrelated characters
/// happen to sit at that offset. That is worse than no span at all: it is a
/// confident, wrong answer to "where is this?".
///
/// Retargeting to the `include:` line gives a location that exists in the file
/// being compiled and is where the operator can act. Which fragment the node
/// actually came from is not lost — it is in the diagnostic's message.
pub fn retarget_spans(doc: &mut PolicyDocument, to: Span) {
    fn one(span: &mut Span, to: Span) {
        *span = to;
    }
    fn scalar(value: &mut Option<Spanned<String>>, to: Span) {
        if let Some(v) = value {
            v.span = to;
        }
    }
    fn list(values: &mut [Spanned<String>], to: Span) {
        for v in values {
            v.span = to;
        }
    }
    fn endpoint(e: &mut Option<Endpoint>, to: Span) {
        if let Some(e) = e {
            one(&mut e.span, to);
            list(&mut e.addresses, to);
            list(&mut e.zones, to);
            list(&mut e.ports, to);
            scalar(&mut e.negate, to);
        }
    }

    one(&mut doc.span, to);
    scalar(&mut doc.version, to);
    list(&mut doc.includes, to);

    if let Some(m) = &mut doc.metadata {
        one(&mut m.span, to);
        scalar(&mut m.name, to);
        scalar(&mut m.description, to);
        scalar(&mut m.revision, to);
        scalar(&mut m.author, to);
    }
    if let Some(d) = &mut doc.defaults {
        one(&mut d.span, to);
        scalar(&mut d.action, to);
        scalar(&mut d.log, to);
        scalar(&mut d.layer, to);
        scalar(&mut d.priority, to);
        scalar(&mut d.stateful, to);
    }
    if let Some(n) = &mut doc.network_profile {
        one(&mut n.span, to);
        list(&mut n.internal, to);
        list(&mut n.perimeter, to);
        list(&mut n.gateways, to);
        list(&mut n.dns_servers, to);
        scalar(&mut n.perimeter_crossing_requires_dpi, to);
    }

    for g in &mut doc.address_groups {
        one(&mut g.span, to);
        g.name.span = to;
        list(&mut g.entries, to);
    }
    for g in &mut doc.port_groups {
        one(&mut g.span, to);
        g.name.span = to;
        list(&mut g.entries, to);
    }
    for g in &mut doc.signature_groups {
        one(&mut g.span, to);
        g.name.span = to;
        list(&mut g.entries, to);
    }
    for a in &mut doc.applications {
        one(&mut a.span, to);
        a.name.span = to;
        scalar(&mut a.description, to);
        list(&mut a.trust, to);
        scalar(&mut a.require_valid_signature, to);
        for p in &mut a.platforms {
            one(&mut p.span, to);
            p.platform.span = to;
            list(&mut p.paths, to);
            list(&mut p.sha256, to);
            list(&mut p.signers, to);
            list(&mut p.team_ids, to);
            list(&mut p.bundle_ids, to);
        }
    }

    for r in &mut doc.rules {
        one(&mut r.span, to);
        scalar(&mut r.id, to);
        scalar(&mut r.description, to);
        scalar(&mut r.priority, to);
        scalar(&mut r.layer, to);
        scalar(&mut r.direction, to);
        scalar(&mut r.action, to);
        scalar(&mut r.protocol, to);
        endpoint(&mut r.source, to);
        endpoint(&mut r.destination, to);
        list(&mut r.interfaces, to);
        scalar(&mut r.log, to);
        scalar(&mut r.stateful, to);
        list(&mut r.tags, to);
        if let Some(a) = &mut r.application {
            one(&mut a.span, to);
            list(&mut a.names, to);
            list(&mut a.paths, to);
            list(&mut a.sha256, to);
            list(&mut a.signers, to);
            list(&mut a.team_ids, to);
            list(&mut a.bundle_ids, to);
            list(&mut a.trust, to);
            scalar(&mut a.require_valid_signature, to);
            scalar(&mut a.negate, to);
        }
        if let Some(d) = &mut r.dpi {
            one(&mut d.span, to);
            list(&mut d.signatures, to);
            list(&mut d.protocols, to);
            scalar(&mut d.on_match, to);
        }
        if let Some(s) = &mut r.schedule {
            one(&mut s.span, to);
            list(&mut s.days, to);
            scalar(&mut s.start, to);
            scalar(&mut s.end, to);
        }
        if let Some(rl) = &mut r.rate_limit {
            one(&mut rl.span, to);
            scalar(&mut rl.rate, to);
            scalar(&mut rl.per, to);
            scalar(&mut rl.burst, to);
        }
    }
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
    "rate_limit",
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

pub const RATE_LIMIT_KEYS: &[&str] = &["rate", "per", "burst"];

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
            RATE_LIMIT_KEYS,
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

//! Semantic analysis: [`PolicyDocument`] to [`CompiledPolicy`].
//!
//! This is where a parsed file stops being text and starts being a policy. The
//! analyzer resolves every symbolic reference, checks every enum and literal,
//! applies defaults and inference, and enforces the limits that the kernel side
//! would otherwise hit at install time.
//!
//! Three decisions here are worth knowing about before reading the code.
//!
//! **Layer inference.** A rule that names an application must be evaluated
//! where identity is available; a rule with a `dpi:` clause must be evaluated
//! where payload has been inspected. Rather than making authors restate that,
//! the analyzer infers the layer from the predicates present and only requires
//! an explicit `layer:` when the author wants something other than the natural
//! one. An explicit layer that cannot support the rule's predicates is an
//! error, not a silent downgrade.
//!
//! **Multi-application rules expand.** `application: [browser, mail]` does not
//! become one predicate with both applications' paths unioned — that would
//! let `browser`'s path match under `mail`'s trust requirement. It becomes one
//! compiled rule per application, each with its own complete predicate.
//!
//! **Perimeter upgrade.** With `perimeter_crossing_requires_dpi: true`, an
//! `allow` whose destination is not provably inside the trusted network is
//! lowered to `allow-inspect`, so deeper layers still get to see the traffic.
//! That is the entire mechanism behind defense Layer 1, and it happens here
//! rather than in a backend so that all three platforms inherit it.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use ufw_shared::constants;
use ufw_shared::hash;
use ufw_shared::identity_types::{TrustLevel, TrustMask};
use ufw_shared::policy_types::*;
use ufw_shared::Platform;

use crate::ast;
use crate::error::{closest_match, codes, Diagnostic, Diagnostics, Outcome, Span, Spanned};

/// Language versions this compiler accepts.
pub const SUPPORTED_VERSIONS: &[&str] = &["1"];

/// Analyze an already-include-resolved document.
///
/// `default_name` is used as the policy name (and therefore as part of every
/// derived rule id) when the document has no `metadata.name`.
pub fn analyze(doc: &ast::PolicyDocument, default_name: &str) -> Outcome<CompiledPolicy> {
    let mut a = Analyzer {
        diags: Diagnostics::new(),
        address_groups: BTreeMap::new(),
        port_groups: BTreeMap::new(),
        signature_groups: BTreeMap::new(),
        applications: BTreeMap::new(),
        used: HashSet::new(),
        rule_ids: HashMap::new(),
    };
    let policy = a.run(doc, default_name);
    let mut diags = a.diags;
    diags.sort();
    Outcome::with(policy, diags)
}

struct Analyzer {
    diags: Diagnostics,
    address_groups: BTreeMap<String, ast::AddressGroup>,
    port_groups: BTreeMap<String, ast::PortGroup>,
    signature_groups: BTreeMap<String, ast::SignatureGroup>,
    applications: BTreeMap<String, ast::Application>,
    /// Definition names actually referenced, for the unused-definition lint.
    used: HashSet<String>,
    /// Derived numeric id -> source rule name, for collision detection.
    rule_ids: HashMap<u32, (String, Span)>,
}

impl Analyzer {
    fn err(&mut self, code: &'static str, span: Span, msg: impl Into<String>) {
        self.diags.push(Diagnostic::error(code, span, msg));
    }

    fn warn(&mut self, code: &'static str, span: Span, msg: impl Into<String>) {
        self.diags.push(Diagnostic::warning(code, span, msg));
    }

    fn note(&mut self, code: &'static str, span: Span, msg: impl Into<String>) {
        self.diags.push(Diagnostic::note(code, span, msg));
    }

    fn run(&mut self, doc: &ast::PolicyDocument, default_name: &str) -> CompiledPolicy {
        self.check_version(doc);

        if let Some(inc) = doc.includes.first() {
            self.err(
                codes::UNRESOLVED_REFERENCE,
                inc.span,
                "`include:` must be resolved before semantic analysis",
            );
        }

        self.collect_definitions(doc);

        let name = doc
            .metadata
            .as_ref()
            .and_then(|m| m.name.as_ref())
            .map(|n| n.value.clone())
            .unwrap_or_else(|| default_name.to_string());

        let defaults = self.lower_defaults(doc);
        let mut policy = CompiledPolicy::new(name.clone(), defaults.decision);
        policy.network_profile = self.lower_network_profile(doc);

        for rule in &doc.rules {
            for compiled in self.lower_rule(rule, &name, &defaults, &policy.network_profile) {
                policy.rules.push(compiled);
            }
        }

        if policy.rules.len() > constants::MAX_RULES {
            let span = doc.rules.last().map(|r| r.span).unwrap_or(doc.span);
            self.err(
                codes::LIMIT_EXCEEDED,
                span,
                format!(
                    "policy has {} rules, which exceeds the kernel limit of {}",
                    policy.rules.len(),
                    constants::MAX_RULES
                ),
            );
        }

        self.report_unused(doc);
        policy.finalize();
        policy
    }

    // -----------------------------------------------------------------
    // Version and definitions
    // -----------------------------------------------------------------

    fn check_version(&mut self, doc: &ast::PolicyDocument) {
        match &doc.version {
            Some(v) => {
                if !SUPPORTED_VERSIONS.contains(&v.value.as_str()) {
                    let val = v.value.clone();
                    let span = v.span;
                    self.diags.push(
                        Diagnostic::error(
                            codes::UNSUPPORTED_VERSION,
                            span,
                            format!("unsupported policy language version `{val}`"),
                        )
                        .with_help(format!(
                            "this compiler understands version {}",
                            SUPPORTED_VERSIONS.join(", ")
                        )),
                    );
                }
            }
            None => self.diags.push(
                Diagnostic::error(
                    codes::MISSING_FIELD,
                    doc.span,
                    "policy is missing a `version:` declaration",
                )
                .with_help("add `version: 1` as the first line"),
            ),
        }
    }

    fn collect_definitions(&mut self, doc: &ast::PolicyDocument) {
        for g in &doc.address_groups {
            if let Some(prev) = self.address_groups.get(&g.name.value) {
                let prev_span = prev.name.span;
                self.duplicate(&g.name, prev_span, "address group");
                continue;
            }
            self.address_groups.insert(g.name.value.clone(), g.clone());
        }
        for g in &doc.port_groups {
            if let Some(prev) = self.port_groups.get(&g.name.value) {
                let prev_span = prev.name.span;
                self.duplicate(&g.name, prev_span, "port group");
                continue;
            }
            self.port_groups.insert(g.name.value.clone(), g.clone());
        }
        for g in &doc.signature_groups {
            if let Some(prev) = self.signature_groups.get(&g.name.value) {
                let prev_span = prev.name.span;
                self.duplicate(&g.name, prev_span, "signature group");
                continue;
            }
            self.signature_groups
                .insert(g.name.value.clone(), g.clone());
        }
        for app in &doc.applications {
            if let Some(prev) = self.applications.get(&app.name.value) {
                let prev_span = prev.name.span;
                self.duplicate(&app.name, prev_span, "application");
                continue;
            }
            self.validate_application(app);
            self.applications
                .insert(app.name.value.clone(), app.clone());
        }
    }

    fn duplicate(&mut self, name: &Spanned<String>, first: Span, kind: &str) {
        let n = name.value.clone();
        self.diags.push(
            Diagnostic::error(
                codes::DUPLICATE_DEFINITION,
                name.span,
                format!("{kind} `{n}` is defined more than once"),
            )
            .with_secondary(first, "first definition here"),
        );
    }

    fn validate_application(&mut self, app: &ast::Application) {
        if app.platforms.is_empty() {
            self.diags.push(
                Diagnostic::error(
                    codes::EMPTY_SELECTOR,
                    app.span,
                    format!("application `{}` declares no platforms", app.name.value),
                )
                .with_help(
                    "add at least one of `windows:`, `linux:` or `macos:` under `platforms:`",
                ),
            );
        }
        for p in &app.platforms {
            if Platform::parse(&p.platform.value).is_none() {
                let val = p.platform.value.clone();
                let span = p.platform.span;
                let mut d = Diagnostic::error(
                    codes::UNKNOWN_ENUM,
                    span,
                    format!("unknown platform `{val}`"),
                );
                if let Some(s) = closest_match(&val, ["windows", "linux", "macos"]) {
                    d = d.with_help(format!("did you mean `{s}`?"));
                }
                self.diags.push(d);
            }
            if p.paths.is_empty()
                && p.sha256.is_empty()
                && p.signers.is_empty()
                && p.team_ids.is_empty()
                && p.bundle_ids.is_empty()
            {
                self.warn(
                    codes::EMPTY_SELECTOR,
                    p.span,
                    format!(
                        "platform block `{}` in application `{}` matches nothing",
                        p.platform.value, app.name.value
                    ),
                );
            }
        }
        for t in &app.trust {
            self.parse_trust_entry(t);
        }
    }

    fn report_unused(&mut self, doc: &ast::PolicyDocument) {
        let mut unused: Vec<(String, Span, &str)> = Vec::new();
        for (name, g) in &self.address_groups {
            if !self.used.contains(name.as_str()) {
                unused.push((name.clone(), g.name.span, "address group"));
            }
        }
        for (name, g) in &self.port_groups {
            if !self.used.contains(name.as_str()) {
                unused.push((name.clone(), g.name.span, "port group"));
            }
        }
        for (name, g) in &self.signature_groups {
            if !self.used.contains(name.as_str()) {
                unused.push((name.clone(), g.name.span, "signature group"));
            }
        }
        for (name, g) in &self.applications {
            if !self.used.contains(name.as_str()) {
                unused.push((name.clone(), g.name.span, "application"));
            }
        }
        // A policy that only defines things (a shared library of groups meant
        // to be `include:`d) should not be nagged about every definition.
        if doc.rules.is_empty() {
            return;
        }
        for (name, span, kind) in unused {
            // A definition that arrived through an `include:` is part of a
            // shared library, and a library that every consumer used in full
            // would not be worth sharing. Only unreferenced definitions in
            // the file that declares them are dead weight.
            if doc.included_definitions.contains(&name) {
                continue;
            }
            self.warn(
                codes::UNUSED_DEFINITION,
                span,
                format!("{kind} `{name}` is never referenced"),
            );
        }
    }

    // -----------------------------------------------------------------
    // Defaults and network profile
    // -----------------------------------------------------------------

    fn lower_defaults(&mut self, doc: &ast::PolicyDocument) -> LoweredDefaults {
        let mut out = LoweredDefaults {
            decision: Decision::Deny,
            log: true,
            layer: None,
            priority: constants::DEFAULT_PRIORITY,
            stateful: true,
        };
        let Some(d) = &doc.defaults else {
            return out;
        };

        if let Some(a) = &d.action {
            match Action::parse(&a.value) {
                Some(Action::Allow) => out.decision = Decision::Allow,
                Some(Action::Deny) => out.decision = Decision::Deny,
                Some(other) => {
                    let name = other.as_str();
                    self.diags.push(
                        Diagnostic::error(
                            codes::UNKNOWN_ENUM,
                            a.span,
                            format!("`{name}` is not a valid default action"),
                        )
                        .with_help("the policy default must be `allow` or `deny`"),
                    );
                }
                None => self.unknown_enum(a, &["allow", "deny"], "default action"),
            }
        }
        if let Some(l) = &d.log {
            out.log = self.parse_bool(l).unwrap_or(true);
        }
        if let Some(l) = &d.layer {
            out.layer = self.parse_layer(l);
        }
        if let Some(p) = &d.priority {
            out.priority = self
                .parse_u32(p, constants::MAX_PRIORITY as u32, "priority")
                .map(|v| v as u16)
                .unwrap_or(constants::DEFAULT_PRIORITY);
        }
        if let Some(s) = &d.stateful {
            out.stateful = self.parse_bool(s).unwrap_or(true);
        }
        out
    }

    fn lower_network_profile(&mut self, doc: &ast::PolicyDocument) -> NetworkProfile {
        let mut np = NetworkProfile::default();
        let Some(src) = &doc.network_profile else {
            return np;
        };
        np.internal = self.resolve_addresses(&src.internal);
        np.perimeter = self.resolve_addresses(&src.perimeter);
        for g in &src.gateways {
            if let Some(ip) = self.parse_ip(g) {
                np.gateways.push(ip);
            }
        }
        for d in &src.dns_servers {
            if let Some(ip) = self.parse_ip(d) {
                np.dns_servers.push(ip);
            }
        }
        if let Some(b) = &src.perimeter_crossing_requires_dpi {
            np.perimeter_crossing_requires_dpi = self.parse_bool(b).unwrap_or(false);
        }
        np
    }

    // -----------------------------------------------------------------
    // Rules
    // -----------------------------------------------------------------

    fn lower_rule(
        &mut self,
        rule: &ast::Rule,
        policy_name: &str,
        defaults: &LoweredDefaults,
        profile: &NetworkProfile,
    ) -> Vec<CompiledRule> {
        let Some(id) = &rule.id else {
            self.diags.push(
                Diagnostic::error(codes::MISSING_FIELD, rule.span, "rule is missing an `id:`")
                    .with_help("every rule needs a stable name; it is what logs and diffs key on"),
            );
            return Vec::new();
        };
        if id.value.len() > constants::MAX_RULE_NAME_LEN {
            let n = constants::MAX_RULE_NAME_LEN;
            self.err(
                codes::LIMIT_EXCEEDED,
                id.span,
                format!("rule id is longer than the {n}-character limit"),
            );
        }

        let Some(action_tok) = &rule.action else {
            self.diags.push(
                Diagnostic::error(
                    codes::MISSING_FIELD,
                    rule.span,
                    format!("rule `{}` is missing an `action:`", id.value),
                )
                .with_help("write one of `allow`, `deny`, `allow-inspect`, `alert` or `continue`"),
            );
            return Vec::new();
        };
        // Parse the action but do not bail on it yet: an operator who wrote
        // two bad values on one rule should learn about both from one run.
        let action_result = self.parse_action(action_tok);

        let direction = rule
            .direction
            .as_ref()
            .and_then(|d| self.parse_direction(d))
            .unwrap_or(Direction::Any);

        let protocol = rule
            .protocol
            .as_ref()
            .and_then(|p| self.parse_protocol(p))
            .unwrap_or(Protocol::Any);

        let priority = rule
            .priority
            .as_ref()
            .and_then(|p| self.parse_u32(p, constants::MAX_PRIORITY as u32, "priority"))
            .map(|v| v as u16)
            .unwrap_or(defaults.priority);

        let (source, source_ports) = match &rule.source {
            Some(ep) => self.lower_endpoint(ep, protocol),
            None => (AddressMatch::any(), PortMatch::any()),
        };
        let (dest, dest_ports) = match &rule.destination {
            Some(ep) => self.lower_endpoint(ep, protocol),
            None => (AddressMatch::any(), PortMatch::any()),
        };

        let dpi = rule.dpi.as_ref().and_then(|d| self.lower_dpi(d));
        let app_variants = self.lower_app_selector(rule.application.as_ref());

        // Every field has now been checked; if the action itself was invalid
        // there is nothing to build.
        let Some(action) = action_result else {
            return Vec::new();
        };

        let layer = self.resolve_layer(rule, defaults, app_variants[0].1.is_some(), dpi.is_some());

        let schedule = rule.schedule.as_ref().and_then(|s| self.lower_schedule(s));
        let rate_limit = self.lower_rate_limit(rule, action);

        let log = rule
            .log
            .as_ref()
            .and_then(|l| self.parse_bool(l))
            .unwrap_or(defaults.log);
        let stateful = rule
            .stateful
            .as_ref()
            .and_then(|s| self.parse_bool(s))
            .unwrap_or(defaults.stateful);

        let interfaces: Vec<String> = rule.interfaces.iter().map(|i| i.value.clone()).collect();
        let tags: Vec<String> = rule.tags.iter().map(|t| t.value.clone()).collect();

        self.lint_rule(rule, action, layer, &dest, &dest_ports, protocol);

        let multi = app_variants.len() > 1;
        if multi {
            self.note(
                codes::RULES_MERGED,
                rule.span,
                format!(
                    "rule `{}` references {} applications and expands into that many rules, \
                     so each keeps its own trust requirement",
                    id.value,
                    app_variants.len()
                ),
            );
        }

        let mut out = Vec::with_capacity(app_variants.len());
        for (suffix, app) in app_variants {
            let rule_name = match (&suffix, multi) {
                (Some(s), true) => format!("{}::{}", id.value, s),
                _ => id.value.clone(),
            };
            let numeric_id = hash::derive_rule_id(policy_name, &rule_name);
            if let Some((other, other_span)) = self.rule_ids.get(&numeric_id) {
                if other != &rule_name {
                    let other = other.clone();
                    let other_span = *other_span;
                    self.diags.push(
                        Diagnostic::error(
                            codes::RULE_ID_COLLISION,
                            id.span,
                            format!(
                                "rule `{rule_name}` hashes to the same id as `{other}` (0x{numeric_id:08x})"
                            ),
                        )
                        .with_secondary(other_span, "collides with this rule")
                        .with_help("rename one of them; ids are derived from the rule name"),
                    );
                }
            } else {
                self.rule_ids
                    .insert(numeric_id, (rule_name.clone(), id.span));
            }

            let mut compiled = CompiledRule {
                id: numeric_id,
                name: rule_name,
                priority,
                layer,
                direction,
                action,
                protocol,
                source: source.clone(),
                source_ports: source_ports.clone(),
                dest: dest.clone(),
                dest_ports: dest_ports.clone(),
                app,
                dpi: dpi.clone(),
                interfaces: interfaces.clone(),
                schedule,
                log,
                stateful,
                ebpf_eligible: false,
                tags: tags.clone(),
                rate_limit,
            };

            self.apply_perimeter_upgrade(&mut compiled, profile, rule.span);
            out.push(compiled);
        }
        out
    }

    /// Lower and validate a `rate_limit:` block. Returns `None` (with a
    /// diagnostic) when the rule cannot carry one, so a broken rate limit is a
    /// build error rather than a silently dropped control.
    fn lower_rate_limit(&mut self, rule: &ast::Rule, action: Action) -> Option<RateLimit> {
        let rl = rule.rate_limit.as_ref()?;

        // A rate limit throttles a permit; on a deny it is meaningless (the
        // packet is already dropped), and silently accepting it would hide a
        // policy the author got wrong.
        if !matches!(action, Action::Allow | Action::AllowInspect) {
            self.diags.push(
                Diagnostic::error(
                    codes::BAD_LITERAL,
                    rl.span,
                    "`rate_limit:` applies only to `allow` and `allow-inspect` rules",
                )
                .with_help(
                    "a rate limit throttles permitted traffic; a deny has nothing to throttle",
                ),
            );
            return None;
        }

        let Some(rate) = rl
            .rate
            .as_ref()
            .and_then(|r| self.parse_u32(r, 1_000_000, "rate_limit.rate"))
        else {
            if rl.rate.is_none() {
                self.diags.push(Diagnostic::error(
                    codes::MISSING_FIELD,
                    rl.span,
                    "`rate_limit:` needs a `rate:` (connections per unit)",
                ));
            }
            return None;
        };
        if rate == 0 {
            self.diags.push(Diagnostic::error(
                codes::BAD_LITERAL,
                rl.rate.as_ref().map(|r| r.span).unwrap_or(rl.span),
                "`rate_limit.rate` must be at least 1",
            ));
            return None;
        }

        let per = match &rl.per {
            Some(p) => match RatePer::parse(&p.value) {
                Some(v) => v,
                None => {
                    self.diags.push(
                        Diagnostic::error(
                            codes::UNKNOWN_ENUM,
                            p.span,
                            format!("`{}` is not a rate unit", p.value),
                        )
                        .with_help("use `second`, `minute` or `hour`"),
                    );
                    return None;
                }
            },
            None => RatePer::Second,
        };

        let burst = rl
            .burst
            .as_ref()
            .and_then(|b| self.parse_u32(b, 1_000_000, "rate_limit.burst"))
            .unwrap_or(0);

        // Honest about the capability gap: nftables enforces this on Linux; the
        // WFP and Network Extension backends do not yet, so the rule permits at
        // the same verdict on all three — it is only throttled on Linux.
        let name = rule
            .id
            .as_ref()
            .map(|i| i.value.as_str())
            .unwrap_or("this rule");
        self.note(
            codes::RATE_LIMIT_PLATFORM,
            rl.span,
            format!(
                "`{name}` caps new connections at {rate}/{} (burst {burst}); enforced on Linux \
                 via nftables, not yet on Windows or macOS",
                per.as_nft()
            ),
        );

        Some(RateLimit { rate, per, burst })
    }

    /// Defense Layer 1: when the profile says perimeter crossings must be
    /// inspected, a terminal `allow` toward anything not provably internal
    /// becomes `allow-inspect` so deeper layers still run.
    fn apply_perimeter_upgrade(
        &mut self,
        rule: &mut CompiledRule,
        profile: &NetworkProfile,
        span: Span,
    ) {
        if !profile.perimeter_crossing_requires_dpi || rule.action != Action::Allow {
            return;
        }
        if rule.direction == Direction::Inbound {
            return;
        }
        if provably_internal(&rule.dest, profile) {
            return;
        }
        rule.action = Action::AllowInspect;
        let name = rule.name.clone();
        self.note(
            codes::PERIMETER_UPGRADE,
            span,
            format!(
                "`{name}` allows traffic that may cross the perimeter, so it was lowered to \
                 `allow-inspect`; deeper layers still evaluate the flow"
            ),
        );
    }

    fn resolve_layer(
        &mut self,
        rule: &ast::Rule,
        defaults: &LoweredDefaults,
        has_app: bool,
        has_dpi: bool,
    ) -> Layer {
        // The stage a rule lands in when it does not say. Header-only rules
        // default to `packet` rather than `perimeter` because that is where
        // the overwhelming majority of them belong, and a default that put
        // every address rule ahead of every zone rule would make the zone
        // stage useless.
        let required = if has_dpi && has_app {
            Layer::Stream
        } else if has_dpi {
            Layer::AppDpi
        } else if has_app {
            Layer::Identity
        } else {
            Layer::Packet
        };

        // The earliest stage the rule's predicates *could* be evaluated at,
        // which is not the same thing. A header-only rule can legitimately be
        // pinned to `perimeter` — that is how a zone-scoped deny is written so
        // it runs before every address rule — while an identity rule cannot go
        // below `identity` no matter what the author writes, because identity
        // is not resolved yet and the rule could only ever fail to match.
        let earliest = if has_dpi && has_app {
            Layer::Stream
        } else if has_dpi {
            Layer::AppDpi
        } else if has_app {
            Layer::Identity
        } else {
            Layer::Perimeter
        };

        let explicit = rule.layer.as_ref().and_then(|l| self.parse_layer(l));
        let Some(explicit) = explicit.or(defaults.layer) else {
            return required;
        };

        // An explicit layer is honoured only if it runs no earlier than the
        // one the predicates need. Downgrading would mean evaluating an
        // identity rule where identity is not yet known, which can only ever
        // produce a non-match.
        if explicit.stage_index() < earliest.stage_index() {
            let span = rule.layer.as_ref().map(|l| l.span).unwrap_or(rule.span);
            let reason = if has_dpi {
                "a `dpi:` clause needs payload inspection"
            } else {
                "an `application:` selector needs a resolved identity"
            };
            self.diags.push(
                Diagnostic::error(
                    codes::LAYER_MISMATCH,
                    span,
                    format!(
                        "layer `{}` runs before this rule's predicates can be evaluated: {reason}",
                        explicit.as_str()
                    ),
                )
                .with_help(format!(
                    "use `layer: {}` or remove the explicit layer",
                    required.as_str()
                )),
            );
            return required;
        }
        explicit
    }

    fn lint_rule(
        &mut self,
        rule: &ast::Rule,
        action: Action,
        layer: Layer,
        dest: &AddressMatch,
        dest_ports: &PortMatch,
        protocol: Protocol,
    ) {
        if !protocol.has_ports() && protocol != Protocol::Any && !dest_ports.is_any() {
            let span = rule
                .destination
                .as_ref()
                .and_then(|d| d.ports.first())
                .map(|p| p.span)
                .unwrap_or(rule.span);
            self.diags.push(
                Diagnostic::error(
                    codes::PORTS_ON_PORTLESS_PROTOCOL,
                    span,
                    format!(
                        "protocol `{}` has no ports, so this port constraint can never match",
                        protocol.as_str()
                    ),
                )
                .with_help("remove the `ports:` list, or change the protocol to tcp/udp"),
            );
        }

        // Identity and payload predicates only apply to TCP and UDP: those are
        // the only protocols for which all three platforms surface a process
        // and a payload at enforcement time. Pairing one with ICMP produces a
        // rule that can never fire, which is worth an error rather than a
        // silently dead rule in a security policy.
        if !ufw_shared::policy_types::identity_observable(protocol) {
            let what = if rule.dpi.is_some() {
                Some(("a `dpi:` clause", "payload to inspect"))
            } else if rule.application.is_some() {
                Some(("an `application:` selector", "an owning socket"))
            } else {
                None
            };
            if let Some((clause, needs)) = what {
                self.diags.push(
                    Diagnostic::error(
                        codes::LAYER_MISMATCH,
                        rule.span,
                        format!(
                            "protocol `{}` has no {needs}, so {clause} on this rule can never match",
                            protocol.as_str()
                        ),
                    )
                    .with_help(
                        "identity and payload predicates apply to tcp and udp only; drop the \
                         `protocol:` line to cover both, or drop the predicate",
                    ),
                );
            }
        }

        if action == Action::Allow
            && layer == Layer::Packet
            && dest.is_any()
            && dest_ports.is_any()
            && protocol == Protocol::Any
            && rule.source.is_none()
            && rule.application.is_none()
        {
            self.diags.push(
                Diagnostic::warning(
                    codes::BROAD_ALLOW,
                    rule.span,
                    "this rule allows every flow at the packet layer and will shadow \
                     everything below it",
                )
                .with_help(
                    "narrow it with a `destination:`, `protocol:` or `application:`, or use \
                     `action: allow-inspect` so deeper layers still run",
                ),
            );
        }
    }

    // -----------------------------------------------------------------
    // Endpoints
    // -----------------------------------------------------------------

    fn lower_endpoint(
        &mut self,
        ep: &ast::Endpoint,
        protocol: Protocol,
    ) -> (AddressMatch, PortMatch) {
        let mut addr = AddressMatch {
            cidrs: self.resolve_addresses(&ep.addresses),
            zones: Vec::new(),
            negate: ep
                .negate
                .as_ref()
                .and_then(|n| self.parse_bool(n))
                .unwrap_or(false),
        };
        for z in &ep.zones {
            match Zone::parse(&z.value) {
                Some(zone) => {
                    if !addr.zones.contains(&zone) {
                        addr.zones.push(zone);
                    }
                }
                None => self.unknown_enum(
                    z,
                    &["loopback", "internal", "perimeter", "external"],
                    "zone",
                ),
            }
        }

        if addr.negate && addr.cidrs.is_empty() && addr.zones.is_empty() {
            self.diags.push(
                Diagnostic::warning(
                    codes::NEGATED_WILDCARD,
                    ep.span,
                    "`negate: true` with no addresses or zones matches nothing",
                )
                .with_help("negation inverts a set; give it a set to invert"),
            );
        }

        let mut ports = PortMatch {
            ranges: self.resolve_ports(&ep.ports),
            negate: false,
        };
        ports.normalize();

        if !ports.ranges.is_empty() && !protocol.has_ports() && protocol != Protocol::Any {
            // Reported by lint_rule with a better span; nothing to do here.
        }

        if ports.ranges.len() > constants::MAX_PORT_RANGES_PER_RULE {
            let n = constants::MAX_PORT_RANGES_PER_RULE;
            self.err(
                codes::LIMIT_EXCEEDED,
                ep.span,
                format!("more than {n} port ranges in one rule"),
            );
        }
        if addr.cidrs.len() > constants::MAX_CIDRS_PER_RULE {
            let n = constants::MAX_CIDRS_PER_RULE;
            self.err(
                codes::LIMIT_EXCEEDED,
                ep.span,
                format!("more than {n} addresses in one rule"),
            );
        }

        (addr, ports)
    }

    /// Resolve a list of CIDR literals and address-group references.
    fn resolve_addresses(&mut self, entries: &[Spanned<String>]) -> Vec<Cidr> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        for e in entries {
            let mut stack = Vec::new();
            self.resolve_address_entry(e, &mut out, &mut seen, &mut stack);
        }
        out
    }

    fn resolve_address_entry(
        &mut self,
        entry: &Spanned<String>,
        out: &mut Vec<Cidr>,
        seen: &mut BTreeSet<String>,
        stack: &mut Vec<String>,
    ) {
        let text = entry.value.trim();
        if text.eq_ignore_ascii_case("any") {
            for c in [Cidr::any_v4(), Cidr::any_v6()] {
                if seen.insert(c.to_string()) {
                    out.push(c);
                }
            }
            return;
        }
        if let Some(cidr) = Cidr::parse(text) {
            if seen.insert(cidr.to_string()) {
                out.push(cidr);
            }
            return;
        }
        // Looks like an address but did not parse: say so instead of treating
        // a typo'd CIDR as a group name that happens not to exist.
        if text.contains('/') || text.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            self.diags.push(
                Diagnostic::error(
                    codes::BAD_LITERAL,
                    entry.span,
                    format!("`{text}` is not a valid IP address or CIDR"),
                )
                .with_help("write `10.0.0.0/8`, `192.0.2.1`, or `2001:db8::/32`"),
            );
            return;
        }
        if stack.iter().any(|s| s == text) {
            let chain = stack.join(" -> ");
            self.err(
                codes::CYCLIC_REFERENCE,
                entry.span,
                format!("address group `{text}` refers to itself ({chain} -> {text})"),
            );
            return;
        }
        let Some(group) = self.address_groups.get(text).cloned() else {
            let names: Vec<&str> = self.address_groups.keys().map(|s| s.as_str()).collect();
            let mut d = Diagnostic::error(
                codes::UNRESOLVED_REFERENCE,
                entry.span,
                format!("unknown address group `{text}`"),
            );
            d = match closest_match(text, names.iter().copied()) {
                Some(s) => d.with_help(format!("did you mean `{s}`?")),
                None => d.with_help("define it under `address_groups:` or write a CIDR literal"),
            };
            self.diags.push(d);
            return;
        };
        self.used.insert(text.to_string());
        stack.push(text.to_string());
        for e in &group.entries {
            self.resolve_address_entry(e, out, seen, stack);
        }
        stack.pop();
    }

    fn resolve_ports(&mut self, entries: &[Spanned<String>]) -> Vec<PortRange> {
        let mut out = Vec::new();
        for e in entries {
            let mut stack = Vec::new();
            self.resolve_port_entry(e, &mut out, &mut stack);
        }
        out
    }

    fn resolve_port_entry(
        &mut self,
        entry: &Spanned<String>,
        out: &mut Vec<PortRange>,
        stack: &mut Vec<String>,
    ) {
        let text = entry.value.trim();
        if text.eq_ignore_ascii_case("any") {
            out.push(PortRange::ANY);
            return;
        }
        if let Some(r) = PortRange::parse(text) {
            out.push(r);
            return;
        }
        if text.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            self.diags.push(
                Diagnostic::error(
                    codes::BAD_LITERAL,
                    entry.span,
                    format!("`{text}` is not a valid port or port range"),
                )
                .with_help("ports are 0-65535; ranges are written `8000-8100`"),
            );
            return;
        }
        if stack.iter().any(|s| s == text) {
            self.err(
                codes::CYCLIC_REFERENCE,
                entry.span,
                format!("port group `{text}` refers to itself"),
            );
            return;
        }
        let Some(group) = self.port_groups.get(text).cloned() else {
            let names: Vec<&str> = self.port_groups.keys().map(|s| s.as_str()).collect();
            let mut d = Diagnostic::error(
                codes::UNRESOLVED_REFERENCE,
                entry.span,
                format!("unknown port group `{text}`"),
            );
            d = match closest_match(text, names.iter().copied()) {
                Some(s) => d.with_help(format!("did you mean `{s}`?")),
                None => d.with_help("define it under `port_groups:` or write a number"),
            };
            self.diags.push(d);
            return;
        };
        self.used.insert(text.to_string());
        stack.push(text.to_string());
        for e in &group.entries {
            self.resolve_port_entry(e, out, stack);
        }
        stack.pop();
    }

    // -----------------------------------------------------------------
    // Application selectors
    // -----------------------------------------------------------------

    /// Lower an `application:` selector into one or more predicates.
    ///
    /// Returns `[(None, None)]` when there is no selector, so callers can
    /// always iterate the result and produce at least one rule.
    fn lower_app_selector(
        &mut self,
        sel: Option<&ast::AppSelector>,
    ) -> Vec<(Option<String>, Option<AppMatch>)> {
        let Some(sel) = sel else {
            return vec![(None, None)];
        };
        if sel.is_empty() {
            self.diags.push(
                Diagnostic::error(
                    codes::EMPTY_SELECTOR,
                    sel.span,
                    "`application:` block constrains nothing",
                )
                .with_help(
                    "name an application, or give `paths:`, `signers:`, `sha256:` or `trust:`",
                ),
            );
            return vec![(None, None)];
        }

        let inline = self.inline_app_match(sel);

        if sel.names.is_empty() {
            if inline.is_unconstrained() {
                self.warn(
                    codes::UNCONSTRAINED_APP_SELECTOR,
                    sel.span,
                    "this selector matches any identified process; it still fails to match a \
                     process whose identity could not be resolved",
                );
            }
            return vec![(None, Some(inline))];
        }

        // Naming an application and describing one inline are two different
        // ways to answer the same question, and combining them has no reading
        // that is obviously right: are the inline patterns an extra
        // alternative, or an extra requirement? Rather than pick one silently,
        // say so.
        if !inline.fingerprints.is_empty() {
            self.diags.push(
                Diagnostic::error(
                    codes::EMPTY_SELECTOR,
                    sel.span,
                    "an `application:` block cannot combine `names:` with inline patterns",
                )
                .with_help(
                    "use one or the other; `trust:` and `require_valid_signature:` may be \
                     combined with `names:` and apply on top of the definition",
                ),
            );
        }

        let mut out = Vec::new();
        for name in &sel.names {
            let Some(app) = self.applications.get(&name.value).cloned() else {
                let names: Vec<&str> = self.applications.keys().map(|s| s.as_str()).collect();
                let text = name.value.clone();
                let mut d = Diagnostic::error(
                    codes::UNRESOLVED_REFERENCE,
                    name.span,
                    format!("unknown application `{text}`"),
                );
                d = match closest_match(&text, names.iter().copied()) {
                    Some(s) => d.with_help(format!("did you mean `{s}`?")),
                    None => d.with_help("define it under `applications:`"),
                };
                self.diags.push(d);
                continue;
            };
            self.used.insert(name.value.clone());
            let mut m = self.application_to_match(&app);
            merge_app_match(&mut m, &inline);
            out.push((Some(name.value.clone()), Some(m)));
        }
        if out.is_empty() {
            return vec![(None, None)];
        }
        out
    }

    fn inline_app_match(&mut self, sel: &ast::AppSelector) -> AppMatch {
        let mut fp = AppFingerprint::default();
        // An inline path in a rule has no platform context, so it is matched
        // case-sensitively. Authors who need Windows semantics should define
        // the application under `applications:` with a `windows:` block.
        for p in &sel.paths {
            fp.paths.push(PathPattern::new(p.value.clone(), false));
        }
        for h in &sel.sha256 {
            match hash::parse_sha256(&h.value) {
                Some(d) => fp.sha256.push(d),
                None => self.diags.push(
                    Diagnostic::error(
                        codes::BAD_LITERAL,
                        h.span,
                        "expected a 64-character SHA-256 hex digest",
                    )
                    .with_help("optionally prefixed with `sha256:`"),
                ),
            }
        }
        fp.signers = sel.signers.iter().map(|s| s.value.clone()).collect();
        fp.team_ids = sel.team_ids.iter().map(|s| s.value.clone()).collect();
        fp.bundle_ids = sel.bundle_ids.iter().map(|s| s.value.clone()).collect();

        AppMatch {
            fingerprints: if fp.is_empty() { Vec::new() } else { vec![fp] },
            trust: self.lower_trust(&sel.trust),
            require_valid_signature: sel
                .require_valid_signature
                .as_ref()
                .and_then(|b| self.parse_bool(b))
                .unwrap_or(false),
            negate: sel
                .negate
                .as_ref()
                .and_then(|b| self.parse_bool(b))
                .unwrap_or(false),
        }
    }

    /// Lower an application definition into one fingerprint per platform.
    ///
    /// Each platform block becomes its own alternative rather than being
    /// flattened together. Flattening looks tidier and is wrong: the Linux
    /// binary of a cross-platform application has no Authenticode signer, so a
    /// signer contributed by the `windows:` block would stop the rule matching
    /// on Linux — a silent, fail-closed hole.
    fn application_to_match(&mut self, app: &ast::Application) -> AppMatch {
        let mut fingerprints = Vec::with_capacity(app.platforms.len());

        for block in &app.platforms {
            let Some(platform) = Platform::parse(&block.platform.value) else {
                continue;
            };
            let ci = platform.paths_are_case_insensitive();
            let mut fp = AppFingerprint::default();
            for p in &block.paths {
                fp.paths.push(PathPattern::new(p.value.clone(), ci));
            }
            for h in &block.sha256 {
                match hash::parse_sha256(&h.value) {
                    Some(d) => fp.sha256.push(d),
                    None => self.err(
                        codes::BAD_LITERAL,
                        h.span,
                        "expected a 64-character SHA-256 hex digest",
                    ),
                }
            }
            fp.signers = block.signers.iter().map(|s| s.value.clone()).collect();
            fp.team_ids = block.team_ids.iter().map(|s| s.value.clone()).collect();
            fp.bundle_ids = block.bundle_ids.iter().map(|s| s.value.clone()).collect();
            if !fp.is_empty() {
                fingerprints.push(fp);
            }
        }

        let m = AppMatch {
            fingerprints,
            trust: self.lower_trust(&app.trust),
            require_valid_signature: app
                .require_valid_signature
                .as_ref()
                .and_then(|b| self.parse_bool(b))
                .unwrap_or(false),
            negate: false,
        };

        if m.pattern_count() > constants::MAX_APP_PATTERNS_PER_RULE {
            let n = constants::MAX_APP_PATTERNS_PER_RULE;
            self.err(
                codes::LIMIT_EXCEEDED,
                app.span,
                format!(
                    "application `{}` has more than {n} patterns",
                    app.name.value
                ),
            );
        }
        m
    }

    /// Lower a `trust:` list. Accepts level names and a single `>= level`
    /// bound, which is the form most policies actually want.
    fn lower_trust(&mut self, entries: &[Spanned<String>]) -> TrustMask {
        if entries.is_empty() {
            return TrustMask::ANY;
        }
        let mut mask = TrustMask::EMPTY;
        for e in entries {
            if let Some(m) = self.parse_trust_entry(e) {
                mask = TrustMask(mask.0 | m.0)
            }
        }
        if mask.is_empty() {
            // Every entry was invalid; fall back to the wildcard so one typo
            // does not silently turn into "matches nothing".
            return TrustMask::ANY;
        }
        mask
    }

    fn parse_trust_entry(&mut self, e: &Spanned<String>) -> Option<TrustMask> {
        let text = e.value.trim();
        if let Some(rest) = text.strip_prefix(">=") {
            return match TrustLevel::parse(rest.trim()) {
                Some(l) => Some(TrustMask::at_least(l)),
                None => {
                    self.unknown_enum_str(rest.trim(), e.span, trust_names(), "trust level");
                    None
                }
            };
        }
        match TrustLevel::parse(text) {
            Some(l) => Some(TrustMask::from_levels([l])),
            None => {
                self.unknown_enum_str(text, e.span, trust_names(), "trust level");
                None
            }
        }
    }

    // -----------------------------------------------------------------
    // DPI and schedule
    // -----------------------------------------------------------------

    fn lower_dpi(&mut self, clause: &ast::DpiClause) -> Option<DpiMatch> {
        if clause.is_empty() {
            self.diags.push(
                Diagnostic::error(
                    codes::EMPTY_SELECTOR,
                    clause.span,
                    "`dpi:` block constrains nothing",
                )
                .with_help("list `signatures:`, `protocols:`, or both"),
            );
            return None;
        }
        let mut m = DpiMatch::default();
        let mut stack = Vec::new();
        for s in &clause.signatures {
            self.resolve_signature_entry(s, &mut m.signatures, &mut stack);
        }
        for p in &clause.protocols {
            match L7Protocol::parse(&p.value) {
                Some(l7) => {
                    if !m.l7.contains(&l7) {
                        m.l7.push(l7);
                    }
                }
                None => self.unknown_enum(
                    p,
                    &["http", "tls", "dns", "ssh", "smtp", "quic"],
                    "application protocol",
                ),
            }
        }
        m.on_match = match &clause.on_match {
            Some(a) => self.parse_action(a).unwrap_or(Action::Deny),
            None => Action::Deny,
        };
        if m.signatures.len() > constants::MAX_SIGNATURES_PER_RULE {
            let n = constants::MAX_SIGNATURES_PER_RULE;
            self.err(
                codes::LIMIT_EXCEEDED,
                clause.span,
                format!("more than {n} signatures in one rule"),
            );
        }
        Some(m)
    }

    fn resolve_signature_entry(
        &mut self,
        entry: &Spanned<String>,
        out: &mut Vec<u32>,
        stack: &mut Vec<String>,
    ) {
        let text = entry.value.trim();
        // A bare number is a literal signature id.
        if let Ok(n) = text.parse::<u32>() {
            if !out.contains(&n) {
                out.push(n);
            }
            return;
        }
        if let Some(group) = self.signature_groups.get(text).cloned() {
            if stack.iter().any(|s| s == text) {
                self.err(
                    codes::CYCLIC_REFERENCE,
                    entry.span,
                    format!("signature group `{text}` refers to itself"),
                );
                return;
            }
            self.used.insert(text.to_string());
            stack.push(text.to_string());
            for e in &group.entries {
                self.resolve_signature_entry(e, out, stack);
            }
            stack.pop();
            return;
        }
        // Otherwise it is a symbolic signature name. Both this compiler and
        // the DPI engine derive the same numeric id from the name, so no
        // shared numbering table has to be maintained.
        let id = hash::derive_signature_id(text);
        if !out.contains(&id) {
            out.push(id);
        }
    }

    fn lower_schedule(&mut self, s: &ast::Schedule) -> Option<TimeWindow> {
        let mut days = 0u8;
        if s.days.is_empty() {
            days = TimeWindow::ALL_DAYS;
        }
        for d in &s.days {
            match day_mask(&d.value) {
                Some(m) => days |= m,
                None => self.unknown_enum(
                    d,
                    &[
                        "mon", "tue", "wed", "thu", "fri", "sat", "sun", "weekdays", "weekends",
                        "daily",
                    ],
                    "day",
                ),
            }
        }
        let start = match &s.start {
            Some(t) => self.parse_time(t)?,
            None => 0,
        };
        let end = match &s.end {
            Some(t) => self.parse_time(t)?,
            None => 1440,
        };
        if start == end {
            self.diags.push(
                Diagnostic::error(
                    codes::BAD_TIME_RANGE,
                    s.span,
                    "schedule start and end are the same, so the window is empty",
                )
                .with_help("use `start: 00:00` and `end: 24:00` for a whole day"),
            );
            return None;
        }
        Some(TimeWindow {
            days,
            start_minute: start,
            end_minute: end,
        })
    }

    // -----------------------------------------------------------------
    // Scalar parsing
    // -----------------------------------------------------------------

    fn parse_bool(&mut self, s: &Spanned<String>) -> Option<bool> {
        match s.value.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "on" | "1" => Some(true),
            "false" | "no" | "off" | "0" => Some(false),
            other => {
                let other = other.to_string();
                self.diags.push(
                    Diagnostic::error(
                        codes::BAD_LITERAL,
                        s.span,
                        format!("expected a boolean, found `{other}`"),
                    )
                    .with_help("write `true` or `false`"),
                );
                None
            }
        }
    }

    fn parse_u32(&mut self, s: &Spanned<String>, max: u32, what: &str) -> Option<u32> {
        match s.value.trim().parse::<u32>() {
            Ok(v) if v <= max => Some(v),
            Ok(v) => {
                self.err(
                    codes::BAD_LITERAL,
                    s.span,
                    format!("{what} {v} exceeds the maximum of {max}"),
                );
                None
            }
            Err(_) => {
                let text = s.value.clone();
                self.err(
                    codes::BAD_LITERAL,
                    s.span,
                    format!("expected a number for {what}, found `{text}`"),
                );
                None
            }
        }
    }

    fn parse_ip(&mut self, s: &Spanned<String>) -> Option<std::net::IpAddr> {
        match s.value.trim().parse() {
            Ok(ip) => Some(ip),
            Err(_) => {
                let text = s.value.clone();
                self.err(
                    codes::BAD_LITERAL,
                    s.span,
                    format!("`{text}` is not a valid IP address"),
                );
                None
            }
        }
    }

    /// `HH:MM` in 24-hour local time. `24:00` is accepted as end-of-day.
    fn parse_time(&mut self, s: &Spanned<String>) -> Option<u16> {
        let text = s.value.trim();
        let bad = |a: &mut Self| {
            a.diags.push(
                Diagnostic::error(
                    codes::BAD_TIME_RANGE,
                    s.span,
                    format!("`{text}` is not a valid time"),
                )
                .with_help("times are written `HH:MM` in 24-hour local time, e.g. `08:30`"),
            );
            None::<u16>
        };
        let Some((h, m)) = text.split_once(':') else {
            return bad(self);
        };
        let (Ok(h), Ok(m)) = (h.trim().parse::<u16>(), m.trim().parse::<u16>()) else {
            return bad(self);
        };
        if h > 24 || m > 59 || (h == 24 && m != 0) {
            return bad(self);
        }
        Some(h * 60 + m)
    }

    fn parse_action(&mut self, s: &Spanned<String>) -> Option<Action> {
        match Action::parse(s.value.trim()) {
            Some(a) => Some(a),
            None => {
                self.unknown_enum(
                    s,
                    &["allow", "deny", "allow-inspect", "alert", "continue"],
                    "action",
                );
                None
            }
        }
    }

    fn parse_layer(&mut self, s: &Spanned<String>) -> Option<Layer> {
        match Layer::parse(s.value.trim()) {
            Some(l) => Some(l),
            None => {
                self.unknown_enum(
                    s,
                    &["perimeter", "packet", "identity", "app-dpi", "stream"],
                    "layer",
                );
                None
            }
        }
    }

    fn parse_direction(&mut self, s: &Spanned<String>) -> Option<Direction> {
        match Direction::parse(s.value.trim()) {
            Some(d) => Some(d),
            None => {
                self.unknown_enum(s, &["inbound", "outbound", "any"], "direction");
                None
            }
        }
    }

    fn parse_protocol(&mut self, s: &Spanned<String>) -> Option<Protocol> {
        match Protocol::parse(s.value.trim()) {
            Some(p) => Some(p),
            None => {
                self.unknown_enum(
                    s,
                    &[
                        "tcp", "udp", "icmp", "icmpv6", "sctp", "gre", "esp", "ah", "any",
                    ],
                    "protocol",
                );
                None
            }
        }
    }

    fn unknown_enum(&mut self, s: &Spanned<String>, allowed: &[&str], what: &str) {
        self.unknown_enum_str(&s.value.clone(), s.span, allowed, what);
    }

    fn unknown_enum_str(&mut self, value: &str, span: Span, allowed: &[&str], what: &str) {
        let mut d = Diagnostic::error(
            codes::UNKNOWN_ENUM,
            span,
            format!("`{value}` is not a valid {what}"),
        );
        d = match closest_match(value, allowed.iter().copied()) {
            Some(s) => d.with_help(format!("did you mean `{s}`?")),
            None => d.with_help(format!("valid values: {}", allowed.join(", "))),
        };
        self.diags.push(d);
    }
}

struct LoweredDefaults {
    decision: Decision,
    log: bool,
    layer: Option<Layer>,
    priority: u16,
    stateful: bool,
}

fn trust_names() -> &'static [&'static str] {
    &["untrusted", "unknown", "known", "trusted", "system"]
}

fn day_mask(name: &str) -> Option<u8> {
    Some(match name.trim().to_ascii_lowercase().as_str() {
        "mon" | "monday" => 1 << 0,
        "tue" | "tuesday" => 1 << 1,
        "wed" | "wednesday" => 1 << 2,
        "thu" | "thursday" => 1 << 3,
        "fri" | "friday" => 1 << 4,
        "sat" | "saturday" => 1 << 5,
        "sun" | "sunday" => 1 << 6,
        "weekdays" => 0b0001_1111,
        "weekends" => 0b0110_0000,
        "daily" | "all" => TimeWindow::ALL_DAYS,
        _ => return None,
    })
}

/// Apply the constraints written alongside `names:` to a resolved definition,
/// so `application: {names: [browser], trust: [system]}` means "the browser,
/// and only when it is system-trusted".
///
/// Only the platform-independent constraints combine here; inline *patterns*
/// alongside `names:` are rejected by the caller as ambiguous.
fn merge_app_match(base: &mut AppMatch, inline: &AppMatch) {
    // Trust is an intersection: both the definition's bound and the rule's
    // bound must hold.
    if !inline.trust.is_any() {
        base.trust = TrustMask(base.trust.0 & inline.trust.0);
    }
    base.require_valid_signature |= inline.require_valid_signature;
    base.negate |= inline.negate;
}

/// Whether every address this predicate can match is inside the trusted
/// network. Conservative: anything it cannot prove, it answers `false` to.
fn provably_internal(dest: &AddressMatch, profile: &NetworkProfile) -> bool {
    if dest.negate {
        return false;
    }
    if !dest.zones.is_empty() {
        return dest
            .zones
            .iter()
            .all(|z| matches!(z, Zone::Loopback | Zone::Internal));
    }
    if dest.cidrs.is_empty() {
        return false;
    }
    dest.cidrs
        .iter()
        .all(|c| c.addr().is_loopback() || profile.internal.iter().any(|i| i.covers(c)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::tokenize;
    use crate::parser::parse;

    fn compile(src: &str) -> (Option<CompiledPolicy>, Diagnostics) {
        let (tokens, mut diags) = tokenize(src);
        let (doc, pdiags) = parse(&tokens);
        diags.extend(pdiags);
        let outcome = analyze(&doc, "test");
        diags.extend(outcome.diagnostics);
        (outcome.value, diags)
    }

    fn compile_ok(src: &str) -> CompiledPolicy {
        let (policy, diags) = compile(src);
        policy.unwrap_or_else(|| panic!("expected success, got {:?}", diags.codes()))
    }

    fn diags_of(src: &str) -> Diagnostics {
        compile(src).1
    }

    const BASE: &str = "version: 1\ndefaults:\n  action: deny\n";

    #[test]
    fn minimal_policy_compiles() {
        let p = compile_ok(&format!(
            "{BASE}rules:\n  - id: allow-loopback\n    action: allow\n    destination: 127.0.0.1/32\n"
        ));
        assert_eq!(p.default_action, Decision::Deny);
        assert_eq!(p.rules.len(), 1);
        assert_eq!(p.rules[0].name, "allow-loopback");
        assert!(p.verify_hash());
    }

    #[test]
    fn missing_version_is_an_error() {
        assert!(diags_of("rules:\n  - id: a\n    action: allow\n").has_code(codes::MISSING_FIELD));
    }

    #[test]
    fn a_valid_rate_limit_lowers_onto_the_rule() {
        let p = compile_ok(&format!(
            "{BASE}rules:\n  - id: a\n    action: allow\n    protocol: tcp\n    \
             destination:\n      ports: [22]\n    rate_limit:\n      rate: 50\n      \
             per: second\n      burst: 100\n"
        ));
        let rl = p.rules[0]
            .rate_limit
            .expect("the rate limit lowered onto the rule");
        assert_eq!(rl.rate, 50);
        assert_eq!(rl.per, RatePer::Second);
        assert_eq!(rl.burst, 100);
    }

    #[test]
    fn a_rate_limit_on_a_deny_is_rejected() {
        let d = diags_of(&format!(
            "{BASE}rules:\n  - id: a\n    action: deny\n    protocol: tcp\n    \
             rate_limit:\n      rate: 50\n      per: second\n"
        ));
        assert!(
            d.has_errors(),
            "a rate limit on a deny has nothing to throttle"
        );
    }

    #[test]
    fn a_rate_limit_without_a_rate_is_rejected() {
        let d = diags_of(&format!(
            "{BASE}rules:\n  - id: a\n    action: allow\n    rate_limit:\n      per: second\n"
        ));
        assert!(d.has_errors());
    }

    #[test]
    fn a_rate_limit_defaults_per_to_second_and_burst_to_zero() {
        let p = compile_ok(&format!(
            "{BASE}rules:\n  - id: a\n    action: allow\n    rate_limit:\n      rate: 5\n"
        ));
        let rl = p.rules[0].rate_limit.unwrap();
        assert_eq!(rl.per, RatePer::Second);
        assert_eq!(rl.burst, 0);
    }

    #[test]
    fn a_rate_limit_does_not_change_the_verdict() {
        // Equivalence rests on this: a rate limit is metadata on an allow, not
        // a new decision, so the compiled action is unchanged.
        let p = compile_ok(&format!(
            "{BASE}rules:\n  - id: a\n    action: allow\n    rate_limit:\n      rate: 5\n"
        ));
        assert_eq!(p.rules[0].action, Action::Allow);
    }

    #[test]
    fn unsupported_version_is_an_error() {
        assert!(diags_of("version: 99\n").has_code(codes::UNSUPPORTED_VERSION));
    }

    #[test]
    fn address_groups_resolve_transitively() {
        let p = compile_ok(&format!(
            "{BASE}address_groups:\n  a: [10.0.0.0/8]\n  b: [a, 192.168.0.0/16]\n\
             rules:\n  - id: r\n    action: allow\n    destination:\n      addresses: [b]\n"
        ));
        let dest = &p.rules[0].dest;
        assert_eq!(dest.cidrs.len(), 2);
        assert!(dest.cidrs.iter().any(|c| c.to_string() == "10.0.0.0/8"));
        assert!(dest.cidrs.iter().any(|c| c.to_string() == "192.168.0.0/16"));
    }

    #[test]
    fn cyclic_address_group_is_caught() {
        let d = diags_of(&format!(
            "{BASE}address_groups:\n  a: [b]\n  b: [a]\n\
             rules:\n  - id: r\n    action: allow\n    destination:\n      addresses: [a]\n"
        ));
        assert!(d.has_code(codes::CYCLIC_REFERENCE));
    }

    #[test]
    fn unknown_group_suggests_a_near_match() {
        let d = diags_of(&format!(
            "{BASE}address_groups:\n  internal: [10.0.0.0/8]\n\
             rules:\n  - id: r\n    action: allow\n    destination:\n      addresses: [intenal]\n"
        ));
        assert!(d.has_code(codes::UNRESOLVED_REFERENCE));
        let msg = d
            .iter()
            .find(|x| x.code == codes::UNRESOLVED_REFERENCE)
            .unwrap();
        assert_eq!(msg.help.as_deref(), Some("did you mean `internal`?"));
    }

    #[test]
    fn malformed_cidr_is_reported_as_a_literal_not_a_reference() {
        let d = diags_of(&format!(
            "{BASE}rules:\n  - id: r\n    action: allow\n    destination:\n      addresses: [10.0.0.0/99]\n"
        ));
        assert!(d.has_code(codes::BAD_LITERAL));
        assert!(!d.has_code(codes::UNRESOLVED_REFERENCE));
    }

    #[test]
    fn port_groups_resolve_and_fuse() {
        let p = compile_ok(&format!(
            "{BASE}port_groups:\n  web: [80, 443, 8000-8100]\n  more: [web, 8101-8200]\n\
             rules:\n  - id: r\n    action: allow\n    protocol: tcp\n    destination:\n      ports: [more]\n"
        ));
        let ports = &p.rules[0].dest_ports;
        // 8000-8100 and 8101-8200 are adjacent, so they fuse.
        assert_eq!(
            ports.ranges,
            vec![
                PortRange::single(80),
                PortRange::single(443),
                PortRange::new(8000, 8200)
            ]
        );
    }

    #[test]
    fn layer_is_inferred_from_predicates() {
        let src = format!(
            "{BASE}applications:\n  app:\n    platforms:\n      linux:\n        path: /usr/bin/x\n\
             rules:\n\
             \x20 - id: plain\n    action: allow\n\
             \x20 - id: ident\n    action: allow\n    application: app\n\
             \x20 - id: dpi\n    action: allow\n    dpi:\n      protocols: [http]\n\
             \x20 - id: both\n    action: allow\n    application: app\n    dpi:\n      protocols: [http]\n"
        );
        let p = compile_ok(&src);
        let layer = |name: &str| p.rules.iter().find(|r| r.name == name).unwrap().layer;
        assert_eq!(layer("plain"), Layer::Packet);
        assert_eq!(layer("ident"), Layer::Identity);
        assert_eq!(layer("dpi"), Layer::AppDpi);
        assert_eq!(layer("both"), Layer::Stream);
    }

    #[test]
    fn explicit_layer_that_runs_too_early_is_rejected() {
        let d = diags_of(&format!(
            "{BASE}rules:\n  - id: r\n    action: allow\n    layer: packet\n    dpi:\n      protocols: [http]\n"
        ));
        assert!(d.has_code(codes::LAYER_MISMATCH));
    }

    #[test]
    fn explicit_deeper_layer_is_honoured() {
        let p = compile_ok(&format!(
            "{BASE}rules:\n  - id: r\n    action: allow\n    layer: stream\n    protocol: tcp\n"
        ));
        assert_eq!(p.rules[0].layer, Layer::Stream);
    }

    #[test]
    fn ports_on_icmp_are_rejected() {
        let d = diags_of(&format!(
            "{BASE}rules:\n  - id: r\n    action: allow\n    protocol: icmp\n    destination:\n      ports: [53]\n"
        ));
        assert!(d.has_code(codes::PORTS_ON_PORTLESS_PROTOCOL));
    }

    #[test]
    fn multi_application_rules_expand_rather_than_union() {
        let src = format!(
            "{BASE}applications:\n\
             \x20 trusted_app:\n    trust: [system]\n    platforms:\n      linux:\n        path: /usr/bin/a\n\
             \x20 loose_app:\n    platforms:\n      linux:\n        path: /usr/bin/b\n\
             rules:\n  - id: r\n    action: allow\n    application: [trusted_app, loose_app]\n"
        );
        let p = compile_ok(&src);
        assert_eq!(p.rules.len(), 2);
        let strict = p.rules.iter().find(|r| r.name == "r::trusted_app").unwrap();
        let loose = p.rules.iter().find(|r| r.name == "r::loose_app").unwrap();
        // The strict app keeps its system-only trust requirement...
        assert_eq!(
            strict.app.as_ref().unwrap().trust,
            TrustMask::from_levels([TrustLevel::System])
        );
        // ...and its path does not leak into the loose rule.
        let loose_fp = &loose.app.as_ref().unwrap().fingerprints;
        assert_eq!(loose_fp.len(), 1);
        assert_eq!(loose_fp[0].paths.len(), 1);
        assert_eq!(loose_fp[0].paths[0].pattern, "/usr/bin/b");
    }

    #[test]
    fn single_application_rules_keep_their_name() {
        let src = format!(
            "{BASE}applications:\n  app:\n    platforms:\n      linux:\n        path: /usr/bin/x\n\
             rules:\n  - id: r\n    action: allow\n    application: app\n"
        );
        let p = compile_ok(&src);
        assert_eq!(p.rules.len(), 1);
        assert_eq!(p.rules[0].name, "r");
    }

    #[test]
    fn path_case_sensitivity_follows_the_platform_block() {
        let src = format!(
            "{BASE}applications:\n  app:\n    platforms:\n      windows:\n        path: \"C:\\\\a.exe\"\n      linux:\n        path: /usr/bin/a\n\
             rules:\n  - id: r\n    action: allow\n    application: app\n"
        );
        let p = compile_ok(&src);
        let fps = &p.rules[0].app.as_ref().unwrap().fingerprints;
        // One alternative per platform block, each carrying its own casing.
        assert_eq!(fps.len(), 2);
        let paths: Vec<&PathPattern> = fps.iter().flat_map(|f| f.paths.iter()).collect();
        let win = paths.iter().find(|p| p.pattern.contains('\\')).unwrap();
        let lin = paths.iter().find(|p| p.pattern.starts_with('/')).unwrap();
        assert!(win.case_insensitive);
        assert!(!lin.case_insensitive);
    }

    #[test]
    fn a_cross_platform_application_matches_on_each_platform_alone() {
        // The regression this fingerprint model exists to prevent: the Linux
        // binary has no Authenticode signer, and flattening the definition
        // would make the Windows signer requirement apply to it.
        let src = format!(
            "{BASE}applications:\n  app:\n    platforms:\n      windows:\n        path: \"C:\\\\app.exe\"\n        signer: Contoso Ltd\n      linux:\n        path: /usr/bin/app\n\
             rules:\n  - id: r\n    action: allow\n    protocol: tcp\n    application: app\n"
        );
        let p = compile_ok(&src);
        let app = p.rules[0].app.as_ref().unwrap();

        let mut linux = ufw_shared::identity_types::AppIdentity::unresolved(1, 0);
        linux.path = "/usr/bin/app".into();
        linux.trust = TrustLevel::Trusted;
        assert!(
            app.matches(Some(&linux)),
            "linux binary must match without a signer"
        );

        let mut windows = ufw_shared::identity_types::AppIdentity::unresolved(2, 0);
        windows.path = r"C:\app.exe".into();
        windows.signer = Some("Contoso Ltd".into());
        windows.trust = TrustLevel::Trusted;
        assert!(app.matches(Some(&windows)));

        let mut unsigned_windows = windows.clone();
        unsigned_windows.signer = None;
        assert!(!app.matches(Some(&unsigned_windows)));
    }

    #[test]
    fn naming_an_application_and_inlining_patterns_is_rejected() {
        let d = diags_of(&format!(
            "{BASE}applications:\n  app:\n    platforms:\n      linux:\n        path: /usr/bin/a\n\
             rules:\n  - id: r\n    action: allow\n    application:\n      names: [app]\n      paths: [/usr/bin/b]\n"
        ));
        assert!(d.has_code(codes::EMPTY_SELECTOR));
    }

    #[test]
    fn trust_bounds_lower_to_masks() {
        let src = format!(
            "{BASE}rules:\n  - id: r\n    action: deny\n    application:\n      trust: [\">= known\"]\n"
        );
        let p = compile_ok(&src);
        let t = p.rules[0].app.as_ref().unwrap().trust;
        assert!(!t.contains(TrustLevel::Unknown));
        assert!(t.contains(TrustLevel::Known));
        assert!(t.contains(TrustLevel::System));
    }

    #[test]
    fn signature_names_and_ids_both_resolve() {
        let src = format!(
            "{BASE}signature_groups:\n  g: [1001, http-exploit-post]\n\
             rules:\n  - id: r\n    action: allow\n    dpi:\n      signatures: [g, 2002]\n      on_match: deny\n"
        );
        let p = compile_ok(&src);
        let sigs = &p.rules[0].dpi.as_ref().unwrap().signatures;
        assert!(sigs.contains(&1001));
        assert!(sigs.contains(&2002));
        assert!(sigs.contains(&hash::derive_signature_id("http-exploit-post")));
    }

    #[test]
    fn dpi_on_match_defaults_to_deny() {
        let p = compile_ok(&format!(
            "{BASE}rules:\n  - id: r\n    action: allow\n    dpi:\n      protocols: [http]\n"
        ));
        assert_eq!(p.rules[0].dpi.as_ref().unwrap().on_match, Action::Deny);
        assert_eq!(p.rules[0].effective_action(), Action::Deny);
    }

    #[test]
    fn schedules_lower_to_minute_windows() {
        let p = compile_ok(&format!(
            "{BASE}rules:\n  - id: r\n    action: allow\n    schedule:\n      days: [weekdays]\n      start: \"08:30\"\n      end: \"17:00\"\n"
        ));
        let w = p.rules[0].schedule.unwrap();
        assert_eq!(w.days, 0b0001_1111);
        assert_eq!(w.start_minute, 510);
        assert_eq!(w.end_minute, 1020);
    }

    #[test]
    fn bad_time_is_reported() {
        for time in ["25:00", "8", "08:99", "abc"] {
            let d = diags_of(&format!(
                "{BASE}rules:\n  - id: r\n    action: allow\n    schedule:\n      start: \"{time}\"\n      end: \"17:00\"\n"
            ));
            assert!(d.has_code(codes::BAD_TIME_RANGE), "accepted {time}");
        }
    }

    #[test]
    fn perimeter_upgrade_lowers_allow_to_allow_inspect() {
        let src = format!(
            "{BASE}network_profile:\n  internal: [10.0.0.0/8]\n  perimeter_crossing_requires_dpi: true\n\
             rules:\n\
             \x20 - id: to-internet\n    action: allow\n    destination: 0.0.0.0/0\n\
             \x20 - id: to-lan\n    action: allow\n    destination: 10.1.0.0/16\n"
        );
        let (p, d) = compile(&src);
        let p = p.unwrap();
        let internet = p.rules.iter().find(|r| r.name == "to-internet").unwrap();
        let lan = p.rules.iter().find(|r| r.name == "to-lan").unwrap();
        assert_eq!(internet.action, Action::AllowInspect);
        // A destination provably inside the trusted network is left alone.
        assert_eq!(lan.action, Action::Allow);
        assert!(d.has_code(codes::PERIMETER_UPGRADE));
    }

    #[test]
    fn identity_and_dpi_predicates_reject_portless_protocols() {
        let d = diags_of(&format!(
            "{BASE}rules:\n  - id: r\n    action: deny\n    protocol: icmp\n    application:\n      trust: [unknown]\n"
        ));
        assert!(d.has_code(codes::LAYER_MISMATCH));

        let d = diags_of(&format!(
            "{BASE}rules:\n  - id: r\n    action: allow\n    protocol: icmp\n    dpi:\n      protocols: [http]\n"
        ));
        assert!(d.has_code(codes::LAYER_MISMATCH));

        // tcp, udp and the unconstrained wildcard are all fine.
        for proto in ["tcp", "udp"] {
            let d = diags_of(&format!(
                "{BASE}rules:\n  - id: r\n    action: deny\n    protocol: {proto}\n    application:\n      trust: [unknown]\n"
            ));
            assert!(!d.has_code(codes::LAYER_MISMATCH), "rejected {proto}");
        }
    }

    #[test]
    fn broad_allow_is_warned_about() {
        let d = diags_of(&format!("{BASE}rules:\n  - id: r\n    action: allow\n"));
        assert!(d.has_code(codes::BROAD_ALLOW));
    }

    #[test]
    fn empty_selectors_are_errors() {
        assert!(diags_of(&format!(
            "{BASE}rules:\n  - id: r\n    action: allow\n    application:\n      negate: false\n"
        ))
        .has_code(codes::EMPTY_SELECTOR));
    }

    #[test]
    fn unused_definitions_are_warned_about() {
        let d = diags_of(&format!(
            "{BASE}address_groups:\n  unused: [10.0.0.0/8]\n\
             rules:\n  - id: r\n    action: allow\n    destination: 1.2.3.4/32\n"
        ));
        assert!(d.has_code(codes::UNUSED_DEFINITION));
    }

    #[test]
    fn definition_only_policies_are_not_nagged() {
        let d = diags_of("version: 1\naddress_groups:\n  shared: [10.0.0.0/8]\n");
        assert!(!d.has_code(codes::UNUSED_DEFINITION));
    }

    #[test]
    fn duplicate_definitions_are_errors() {
        let d = diags_of(&format!(
            "{BASE}address_groups:\n  a: [10.0.0.0/8]\naddress_groups:\n  a: [11.0.0.0/8]\n"
        ));
        // The parser catches the duplicate top-level key first.
        assert!(d.has_code(codes::DUPLICATE_KEY) || d.has_code(codes::DUPLICATE_DEFINITION));
    }

    #[test]
    fn rule_ids_are_stable_across_recompiles() {
        let src = format!(
            "{BASE}rules:\n  - id: keep-me\n    action: allow\n    destination: 1.2.3.4/32\n"
        );
        let a = compile_ok(&src);
        let b = compile_ok(&src);
        assert_eq!(a.rules[0].id, b.rules[0].id);
        assert_eq!(a.ruleset_hash, b.ruleset_hash);
    }

    #[test]
    fn rule_ids_survive_insertion_of_an_earlier_rule() {
        let one = compile_ok(&format!(
            "{BASE}rules:\n  - id: b\n    action: allow\n    destination: 1.2.3.4/32\n"
        ));
        let two = compile_ok(&format!(
            "{BASE}rules:\n  - id: a\n    action: allow\n    destination: 5.6.7.8/32\n  - id: b\n    action: allow\n    destination: 1.2.3.4/32\n"
        ));
        let b1 = one.rules.iter().find(|r| r.name == "b").unwrap().id;
        let b2 = two.rules.iter().find(|r| r.name == "b").unwrap().id;
        assert_eq!(b1, b2, "inserting a rule must not renumber the others");
    }

    #[test]
    fn every_diagnostic_survives_rendering() {
        // A crash while rendering an error is worse than the error.
        let src = "version: 9\nrules:\n  - id: r\n    action: nope\n    protocol: zzz\n";
        let d = diags_of(src);
        let file = crate::error::SourceFile::new("t.yaml", src);
        let text = d.render(&file);
        assert!(text.contains("E0200"));
        assert!(text.contains("E0202"));
    }
}

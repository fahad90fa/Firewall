//! Recursive descent parser: token stream to [`PolicyDocument`].
//!
//! Block structure comes from token columns (see `lexer.rs` for why there are
//! no INDENT/DEDENT tokens). Every mapping is parsed by asking for the next key
//! at a fixed column; a token further left ends the mapping, a token further
//! right is a misindentation the parser reports and steps over.
//!
//! # Error recovery
//!
//! The parser never stops at the first problem. On an unexpected token it
//! reports it, skips to the end of the logical line — or, for a key it does not
//! recognize, over that key's entire indented block — and carries on. An
//! operator fixing a policy under pressure should get the whole list of
//! problems from one run, not one problem per run.
//!
//! # Unknown keys are errors
//!
//! A silently ignored key in a firewall policy is a hole: `destinaton:` with a
//! typo would compile to a rule matching every destination. So unknown keys are
//! hard errors, with a spelling suggestion attached.

use crate::ast::*;
use crate::error::{closest_match, codes, Diagnostic, Diagnostics, Span, Spanned};
use crate::lexer::{Token, TokenKind};

/// Parse a token stream. Always returns a document; the diagnostics say
/// whether it is complete.
pub fn parse(tokens: &[Token]) -> (PolicyDocument, Diagnostics) {
    let mut p = Parser {
        tokens,
        pos: 0,
        diags: Diagnostics::new(),
    };
    let doc = p.parse_document();
    (doc, p.diags)
}

struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
    diags: Diagnostics,
}

impl<'a> Parser<'a> {
    // -----------------------------------------------------------------
    // Token access
    // -----------------------------------------------------------------

    fn peek(&self) -> &'a Token {
        // The lexer guarantees a trailing Eof, so this never goes out of
        // bounds; clamping rather than indexing keeps that guarantee local.
        &self.tokens[self.pos.min(self.tokens.len() - 1)]
    }

    fn bump(&mut self) -> &'a Token {
        let t = self.peek();
        if self.pos < self.tokens.len() - 1 {
            self.pos += 1;
        }
        t
    }

    fn at_eof(&self) -> bool {
        matches!(self.peek().kind, TokenKind::Eof)
    }

    fn skip_newlines(&mut self) {
        while matches!(self.peek().kind, TokenKind::Newline) {
            self.bump();
        }
    }

    /// Consume through the end of the current logical line.
    fn skip_line(&mut self) {
        while !matches!(self.peek().kind, TokenKind::Newline | TokenKind::Eof) {
            self.bump();
        }
        if matches!(self.peek().kind, TokenKind::Newline) {
            self.bump();
        }
    }

    /// Consume a key's value: whatever is left on this line, plus any block
    /// indented under it. Used to step over keys the parser rejected.
    fn skip_value(&mut self, key_col: u32) {
        while !matches!(self.peek().kind, TokenKind::Newline | TokenKind::Eof) {
            self.bump();
        }
        loop {
            let save = self.pos;
            self.skip_newlines();
            let t = self.peek();
            if matches!(t.kind, TokenKind::Eof) || t.col <= key_col {
                self.pos = save;
                return;
            }
            self.skip_line();
        }
    }

    fn error(&mut self, code: &'static str, span: Span, msg: impl Into<String>) {
        self.diags.push(Diagnostic::error(code, span, msg));
    }

    // -----------------------------------------------------------------
    // Block-structure primitives
    // -----------------------------------------------------------------

    /// Next key of a block mapping whose keys sit at `col`.
    ///
    /// Returns `None` at end of input, at a token to the left of `col` (the
    /// mapping ended), or at a `-` (this is a sequence, and the caller decides
    /// what that means).
    fn next_key_at(&mut self, col: u32) -> Option<Spanned<String>> {
        loop {
            self.skip_newlines();
            let t = self.peek();
            if matches!(t.kind, TokenKind::Eof) || t.col < col {
                return None;
            }
            if matches!(t.kind, TokenKind::Dash) {
                return None;
            }
            if t.col > col {
                let span = t.span;
                self.error(
                    codes::BAD_INDENT,
                    span,
                    "unexpected indentation: this line is indented further than the block it is in",
                );
                self.skip_line();
                continue;
            }
            match &t.kind {
                TokenKind::Key(k) => {
                    let key = Spanned::new(k.clone(), t.span);
                    self.bump();
                    return Some(key);
                }
                other => {
                    let span = t.span;
                    let desc = other.describe();
                    self.error(
                        codes::EXPECTED_KEY,
                        span,
                        format!("expected a `name:` key here, found {desc}"),
                    );
                    self.skip_line();
                }
            }
        }
    }

    /// Column of the block indented under a key, if there is one. Leaves the
    /// stream untouched when there is not, so an empty value is not an error
    /// at this level.
    fn block_col(&mut self, key_col: u32) -> Option<u32> {
        if !matches!(self.peek().kind, TokenKind::Newline) {
            return None;
        }
        let save = self.pos;
        self.skip_newlines();
        let t = self.peek();
        if matches!(t.kind, TokenKind::Eof) || t.col <= key_col {
            self.pos = save;
            return None;
        }
        Some(t.col)
    }

    /// A single scalar value on the same line as its key.
    fn value_scalar(&mut self, key: &Spanned<String>) -> Option<Spanned<String>> {
        match &self.peek().kind {
            TokenKind::Scalar(s) => {
                let t = self.peek();
                let v = Spanned::new(s.clone(), t.span);
                self.bump();
                Some(v)
            }
            _ => {
                let span = key.span;
                let name = key.value.clone();
                self.error(
                    codes::EXPECTED_VALUE,
                    span,
                    format!("`{name}:` needs a value on the same line"),
                );
                self.skip_value(span.col);
                None
            }
        }
    }

    /// A list of scalars, written any of three ways:
    ///
    /// ```text
    /// ports: 443              # single value
    /// ports: [80, 443]        # flow sequence
    /// ports:                  # block sequence
    ///   - 80
    ///   - 443
    /// ```
    fn value_string_list(&mut self, key: &Spanned<String>) -> Vec<Spanned<String>> {
        match &self.peek().kind {
            TokenKind::Scalar(s) => {
                let t = self.peek();
                let v = vec![Spanned::new(s.clone(), t.span)];
                self.bump();
                v
            }
            TokenKind::LBracket => self.parse_flow_sequence(),
            TokenKind::Newline => match self.block_col(key.span.col) {
                Some(col) => {
                    if matches!(self.peek().kind, TokenKind::Dash) {
                        self.parse_block_string_sequence(col)
                    } else {
                        let span = self.peek().span;
                        let name = key.value.clone();
                        self.error(
                            codes::EXPECTED_VALUE,
                            span,
                            format!("`{name}:` expects a list; write `- item` entries or `[a, b]`"),
                        );
                        self.skip_value(key.span.col);
                        Vec::new()
                    }
                }
                None => Vec::new(),
            },
            other => {
                let span = self.peek().span;
                let desc = other.describe();
                let name = key.value.clone();
                self.error(
                    codes::EXPECTED_VALUE,
                    span,
                    format!("`{name}:` expects a value or list, found {desc}"),
                );
                self.skip_value(key.span.col);
                Vec::new()
            }
        }
    }

    fn parse_flow_sequence(&mut self) -> Vec<Spanned<String>> {
        let open = self.peek().span;
        self.bump(); // '['
        let mut out = Vec::new();
        loop {
            match &self.peek().kind {
                TokenKind::RBracket => {
                    self.bump();
                    break;
                }
                TokenKind::Scalar(s) => {
                    let t = self.peek();
                    out.push(Spanned::new(s.clone(), t.span));
                    self.bump();
                    match &self.peek().kind {
                        TokenKind::Comma => {
                            self.bump();
                        }
                        TokenKind::RBracket => {
                            self.bump();
                            break;
                        }
                        other => {
                            let span = self.peek().span;
                            let desc = other.describe();
                            self.error(
                                codes::UNEXPECTED_TOKEN,
                                span,
                                format!("expected `,` or `]` in list, found {desc}"),
                            );
                            break;
                        }
                    }
                }
                TokenKind::Comma => {
                    // `[a,,b]` or a leading comma.
                    let span = self.peek().span;
                    self.error(codes::UNEXPECTED_TOKEN, span, "empty list element");
                    self.bump();
                }
                TokenKind::Eof | TokenKind::Newline => {
                    self.error(codes::UNCLOSED_FLOW_SEQ, open, "unclosed `[`");
                    break;
                }
                other => {
                    let span = self.peek().span;
                    let desc = other.describe();
                    self.error(
                        codes::UNEXPECTED_TOKEN,
                        span,
                        format!("expected a list element, found {desc}"),
                    );
                    self.bump();
                }
            }
        }
        out
    }

    fn parse_block_string_sequence(&mut self, col: u32) -> Vec<Spanned<String>> {
        let mut out = Vec::new();
        loop {
            self.skip_newlines();
            let t = self.peek();
            if !matches!(t.kind, TokenKind::Dash) || t.col != col {
                break;
            }
            self.bump(); // '-'
            match &self.peek().kind {
                TokenKind::Scalar(s) => {
                    let t = self.peek();
                    out.push(Spanned::new(s.clone(), t.span));
                    self.bump();
                }
                other => {
                    let span = self.peek().span;
                    let desc = other.describe();
                    self.error(
                        codes::EXPECTED_VALUE,
                        span,
                        format!("expected a value after `-`, found {desc}"),
                    );
                    self.skip_line();
                }
            }
        }
        out
    }

    /// Report a repeated key within one mapping. Last-wins would be a silent
    /// way to lose a rule.
    fn check_duplicate(&mut self, seen: &mut Vec<(String, Span)>, key: &Spanned<String>) -> bool {
        if let Some((_, first)) = seen.iter().find(|(n, _)| n == &key.value) {
            let first = *first;
            let name = key.value.clone();
            self.diags.push(
                Diagnostic::error(
                    codes::DUPLICATE_KEY,
                    key.span,
                    format!("duplicate key `{name}`"),
                )
                .with_label("defined again here")
                .with_secondary(first, "first defined here"),
            );
            return true;
        }
        seen.push((key.value.clone(), key.span));
        false
    }

    fn unknown_key(&mut self, key: &Spanned<String>, allowed: &[&str], context: &str) {
        let mut d = Diagnostic::error(
            codes::UNKNOWN_KEY,
            key.span,
            format!("unknown key `{}` in {context}", key.value),
        )
        .with_label("not a recognized key");
        if let Some(sugg) = closest_match(&key.value, allowed.iter().copied()) {
            d = d.with_help(format!("did you mean `{sugg}`?"));
        } else {
            d = d.with_help(format!("valid keys here: {}", allowed.join(", ")));
        }
        self.diags.push(d);
        self.skip_value(key.span.col);
    }

    // -----------------------------------------------------------------
    // Document
    // -----------------------------------------------------------------

    fn parse_document(&mut self) -> PolicyDocument {
        let mut doc = PolicyDocument::default();
        self.skip_newlines();
        if self.at_eof() {
            return doc;
        }

        // Base column is taken from the first token rather than hard-coded to
        // 1, so a policy embedded in an indented block still parses.
        let base = self.peek().col;
        doc.span = Span::new(
            self.peek().span.start,
            self.tokens.last().map(|t| t.span.end).unwrap_or(0),
            self.peek().line,
            base,
        );

        let mut seen: Vec<(String, Span)> = Vec::new();

        while let Some(key) = self.next_key_at(base) {
            if self.check_duplicate(&mut seen, &key) {
                self.skip_value(base);
                continue;
            }
            match key.value.as_str() {
                "version" => doc.version = self.value_scalar(&key),
                "metadata" => doc.metadata = Some(self.parse_metadata(&key)),
                "defaults" => doc.defaults = Some(self.parse_defaults(&key)),
                "include" => doc.includes = self.value_string_list(&key),
                "address_groups" => {
                    doc.address_groups = self
                        .parse_named_lists(&key)
                        .into_iter()
                        .map(|(name, entries, span)| AddressGroup {
                            span,
                            name,
                            entries,
                        })
                        .collect();
                }
                "port_groups" => {
                    doc.port_groups = self
                        .parse_named_lists(&key)
                        .into_iter()
                        .map(|(name, entries, span)| PortGroup {
                            span,
                            name,
                            entries,
                        })
                        .collect();
                }
                "signature_groups" => {
                    doc.signature_groups = self
                        .parse_named_lists(&key)
                        .into_iter()
                        .map(|(name, entries, span)| SignatureGroup {
                            span,
                            name,
                            entries,
                        })
                        .collect();
                }
                "applications" => doc.applications = self.parse_applications(&key),
                "network_profile" => doc.network_profile = Some(self.parse_network_profile(&key)),
                "rules" => doc.rules = self.parse_rules(&key),
                _ => self.unknown_key(&key, TOP_LEVEL_KEYS, "the top level of a policy"),
            }
        }

        // Anything left that is not EOF is a structural problem worth naming.
        self.skip_newlines();
        if !self.at_eof() {
            let span = self.peek().span;
            let desc = self.peek().kind.describe();
            self.error(
                codes::UNEXPECTED_TOKEN,
                span,
                format!("unexpected {desc} after the end of the policy"),
            );
        }

        doc
    }

    fn parse_metadata(&mut self, key: &Spanned<String>) -> Metadata {
        let mut m = Metadata {
            span: key.span,
            ..Default::default()
        };
        let Some(col) = self.block_col(key.span.col) else {
            return m;
        };
        let mut seen = Vec::new();
        while let Some(k) = self.next_key_at(col) {
            if self.check_duplicate(&mut seen, &k) {
                self.skip_value(col);
                continue;
            }
            match k.value.as_str() {
                "name" => m.name = self.value_scalar(&k),
                "description" => m.description = self.value_scalar(&k),
                "revision" => m.revision = self.value_scalar(&k),
                "author" => m.author = self.value_scalar(&k),
                _ => self.unknown_key(&k, METADATA_KEYS, "`metadata`"),
            }
        }
        m
    }

    fn parse_defaults(&mut self, key: &Spanned<String>) -> Defaults {
        let mut d = Defaults {
            span: key.span,
            ..Default::default()
        };
        let Some(col) = self.block_col(key.span.col) else {
            return d;
        };
        let mut seen = Vec::new();
        while let Some(k) = self.next_key_at(col) {
            if self.check_duplicate(&mut seen, &k) {
                self.skip_value(col);
                continue;
            }
            match k.value.as_str() {
                "action" => d.action = self.value_scalar(&k),
                "log" => d.log = self.value_scalar(&k),
                "layer" => d.layer = self.value_scalar(&k),
                "priority" => d.priority = self.value_scalar(&k),
                "stateful" => d.stateful = self.value_scalar(&k),
                _ => self.unknown_key(&k, DEFAULTS_KEYS, "`defaults`"),
            }
        }
        d
    }

    /// `name: [entries]` mappings, shared by address, port and signature
    /// groups.
    fn parse_named_lists(
        &mut self,
        key: &Spanned<String>,
    ) -> Vec<(Spanned<String>, Vec<Spanned<String>>, Span)> {
        let mut out = Vec::new();
        let Some(col) = self.block_col(key.span.col) else {
            return out;
        };
        let mut seen = Vec::new();
        while let Some(name) = self.next_key_at(col) {
            if self.check_duplicate(&mut seen, &name) {
                self.skip_value(col);
                continue;
            }
            let entries = self.value_string_list(&name);
            let span = name.span;
            out.push((name, entries, span));
        }
        out
    }

    fn parse_applications(&mut self, key: &Spanned<String>) -> Vec<Application> {
        let mut out = Vec::new();
        let Some(col) = self.block_col(key.span.col) else {
            return out;
        };
        let mut seen = Vec::new();
        while let Some(name) = self.next_key_at(col) {
            if self.check_duplicate(&mut seen, &name) {
                self.skip_value(col);
                continue;
            }
            let span = name.span;
            let mut app = Application {
                span,
                name,
                description: None,
                platforms: Vec::new(),
                trust: Vec::new(),
                require_valid_signature: None,
            };
            if let Some(inner) = self.block_col(col) {
                let mut inner_seen = Vec::new();
                while let Some(k) = self.next_key_at(inner) {
                    if self.check_duplicate(&mut inner_seen, &k) {
                        self.skip_value(inner);
                        continue;
                    }
                    match k.value.as_str() {
                        "description" => app.description = self.value_scalar(&k),
                        "trust" => app.trust = self.value_string_list(&k),
                        "require_valid_signature" => {
                            app.require_valid_signature = self.value_scalar(&k)
                        }
                        "platforms" => app.platforms = self.parse_platform_blocks(&k),
                        _ => self.unknown_key(&k, APPLICATION_KEYS, "an application definition"),
                    }
                }
            }
            out.push(app);
        }
        out
    }

    fn parse_platform_blocks(&mut self, key: &Spanned<String>) -> Vec<PlatformBlock> {
        let mut out = Vec::new();
        let Some(col) = self.block_col(key.span.col) else {
            return out;
        };
        let mut seen = Vec::new();
        while let Some(platform) = self.next_key_at(col) {
            if self.check_duplicate(&mut seen, &platform) {
                self.skip_value(col);
                continue;
            }
            let span = platform.span;
            let mut block = PlatformBlock {
                span,
                platform,
                paths: Vec::new(),
                sha256: Vec::new(),
                signers: Vec::new(),
                team_ids: Vec::new(),
                bundle_ids: Vec::new(),
            };
            if let Some(inner) = self.block_col(col) {
                let mut inner_seen = Vec::new();
                while let Some(k) = self.next_key_at(inner) {
                    if self.check_duplicate(&mut inner_seen, &k) {
                        self.skip_value(inner);
                        continue;
                    }
                    match k.value.as_str() {
                        "path" | "paths" => block.paths.extend(self.value_string_list(&k)),
                        "sha256" => block.sha256.extend(self.value_string_list(&k)),
                        "signer" | "signers" => block.signers.extend(self.value_string_list(&k)),
                        "team_id" | "team_ids" => block.team_ids.extend(self.value_string_list(&k)),
                        "bundle_id" | "bundle_ids" => {
                            block.bundle_ids.extend(self.value_string_list(&k))
                        }
                        _ => self.unknown_key(&k, PLATFORM_BLOCK_KEYS, "a platform block"),
                    }
                }
            }
            out.push(block);
        }
        out
    }

    fn parse_network_profile(&mut self, key: &Spanned<String>) -> NetworkProfile {
        let mut np = NetworkProfile {
            span: key.span,
            ..Default::default()
        };
        let Some(col) = self.block_col(key.span.col) else {
            return np;
        };
        let mut seen = Vec::new();
        while let Some(k) = self.next_key_at(col) {
            if self.check_duplicate(&mut seen, &k) {
                self.skip_value(col);
                continue;
            }
            match k.value.as_str() {
                "internal" => np.internal = self.value_string_list(&k),
                "perimeter" => np.perimeter = self.value_string_list(&k),
                "gateways" => np.gateways = self.value_string_list(&k),
                "dns_servers" => np.dns_servers = self.value_string_list(&k),
                "perimeter_crossing_requires_dpi" => {
                    np.perimeter_crossing_requires_dpi = self.value_scalar(&k)
                }
                _ => self.unknown_key(&k, NETWORK_PROFILE_KEYS, "`network_profile`"),
            }
        }
        np
    }

    // -----------------------------------------------------------------
    // Rules
    // -----------------------------------------------------------------

    fn parse_rules(&mut self, key: &Spanned<String>) -> Vec<Rule> {
        let mut out = Vec::new();
        let Some(col) = self.block_col(key.span.col) else {
            return out;
        };
        loop {
            self.skip_newlines();
            let t = self.peek();
            if !matches!(t.kind, TokenKind::Dash) || t.col != col {
                if t.col >= col && !matches!(t.kind, TokenKind::Eof) && t.col > key.span.col {
                    let span = t.span;
                    let desc = t.kind.describe();
                    self.error(
                        codes::UNEXPECTED_TOKEN,
                        span,
                        format!("expected `- ` to start a rule, found {desc}"),
                    );
                    self.skip_line();
                    continue;
                }
                break;
            }
            let dash_span = t.span;
            self.bump(); // '-'

            // The rule's mapping starts wherever the first key after the dash
            // is, whether that is on the same line (`- id: x`) or the next.
            let item_col = if matches!(self.peek().kind, TokenKind::Newline) {
                self.skip_newlines();
                let c = self.peek().col;
                if c <= col || self.at_eof() {
                    self.error(codes::EXPECTED_VALUE, dash_span, "empty rule entry");
                    continue;
                }
                c
            } else {
                self.peek().col
            };
            out.push(self.parse_rule(item_col, dash_span));
        }
        out
    }

    fn parse_rule(&mut self, col: u32, dash_span: Span) -> Rule {
        let mut rule = Rule {
            span: dash_span,
            ..Default::default()
        };
        let mut seen = Vec::new();
        while let Some(k) = self.next_key_at(col) {
            if self.check_duplicate(&mut seen, &k) {
                self.skip_value(col);
                continue;
            }
            rule.span = rule.span.merge(k.span);
            match k.value.as_str() {
                "id" => rule.id = self.value_scalar(&k),
                "description" => rule.description = self.value_scalar(&k),
                "priority" => rule.priority = self.value_scalar(&k),
                "layer" => rule.layer = self.value_scalar(&k),
                "direction" => rule.direction = self.value_scalar(&k),
                "action" => rule.action = self.value_scalar(&k),
                "protocol" => rule.protocol = self.value_scalar(&k),
                "source" => rule.source = Some(self.parse_endpoint(&k)),
                "destination" => rule.destination = Some(self.parse_endpoint(&k)),
                "application" => rule.application = Some(self.parse_app_selector(&k)),
                "dpi" => rule.dpi = Some(self.parse_dpi(&k)),
                "interfaces" => rule.interfaces = self.value_string_list(&k),
                "schedule" => rule.schedule = Some(self.parse_schedule(&k)),
                "log" => rule.log = self.value_scalar(&k),
                "stateful" => rule.stateful = self.value_scalar(&k),
                "rate_limit" => rule.rate_limit = Some(self.parse_rate_limit(&k)),
                "tags" => rule.tags = self.value_string_list(&k),
                _ => self.unknown_key(&k, RULE_KEYS, "a rule"),
            }
        }
        rule
    }

    fn parse_endpoint(&mut self, key: &Spanned<String>) -> Endpoint {
        let mut ep = Endpoint {
            span: key.span,
            ..Default::default()
        };

        // `source: any` and `destination: [10.0.0.0/8]` are shorthands for a
        // block with only `addresses:`; they are how most rules are written.
        match &self.peek().kind {
            TokenKind::Scalar(_) | TokenKind::LBracket => {
                ep.addresses = self.value_string_list(key);
                return ep;
            }
            _ => {}
        }

        let Some(col) = self.block_col(key.span.col) else {
            return ep;
        };
        let mut seen = Vec::new();
        while let Some(k) = self.next_key_at(col) {
            if self.check_duplicate(&mut seen, &k) {
                self.skip_value(col);
                continue;
            }
            match k.value.as_str() {
                "addresses" => ep.addresses = self.value_string_list(&k),
                "zone" | "zones" => ep.zones.extend(self.value_string_list(&k)),
                "ports" => ep.ports = self.value_string_list(&k),
                "negate" => ep.negate = self.value_scalar(&k),
                _ => self.unknown_key(&k, ENDPOINT_KEYS, "a `source:`/`destination:` block"),
            }
        }
        ep
    }

    fn parse_app_selector(&mut self, key: &Spanned<String>) -> AppSelector {
        let mut sel = AppSelector {
            span: key.span,
            ..Default::default()
        };

        // `application: browser` and `application: [browser, mail]` name
        // definitions from the `applications:` section.
        match &self.peek().kind {
            TokenKind::Scalar(_) | TokenKind::LBracket => {
                sel.names = self.value_string_list(key);
                return sel;
            }
            _ => {}
        }

        let Some(col) = self.block_col(key.span.col) else {
            return sel;
        };
        let mut seen = Vec::new();
        while let Some(k) = self.next_key_at(col) {
            if self.check_duplicate(&mut seen, &k) {
                self.skip_value(col);
                continue;
            }
            match k.value.as_str() {
                "name" | "names" => sel.names.extend(self.value_string_list(&k)),
                "path" | "paths" => sel.paths.extend(self.value_string_list(&k)),
                "sha256" => sel.sha256.extend(self.value_string_list(&k)),
                "signer" | "signers" => sel.signers.extend(self.value_string_list(&k)),
                "team_id" | "team_ids" => sel.team_ids.extend(self.value_string_list(&k)),
                "bundle_id" | "bundle_ids" => sel.bundle_ids.extend(self.value_string_list(&k)),
                "trust" => sel.trust.extend(self.value_string_list(&k)),
                "require_valid_signature" => sel.require_valid_signature = self.value_scalar(&k),
                "negate" => sel.negate = self.value_scalar(&k),
                _ => self.unknown_key(&k, APP_SELECTOR_KEYS, "an `application:` block"),
            }
        }
        sel
    }

    fn parse_dpi(&mut self, key: &Spanned<String>) -> DpiClause {
        let mut dpi = DpiClause {
            span: key.span,
            ..Default::default()
        };
        let Some(col) = self.block_col(key.span.col) else {
            // `dpi: [sig-a, sig-b]` shorthand.
            if matches!(self.peek().kind, TokenKind::Scalar(_) | TokenKind::LBracket) {
                dpi.signatures = self.value_string_list(key);
            }
            return dpi;
        };
        let mut seen = Vec::new();
        while let Some(k) = self.next_key_at(col) {
            if self.check_duplicate(&mut seen, &k) {
                self.skip_value(col);
                continue;
            }
            match k.value.as_str() {
                "signatures" => dpi.signatures = self.value_string_list(&k),
                "protocol" | "protocols" => dpi.protocols.extend(self.value_string_list(&k)),
                "on_match" => dpi.on_match = self.value_scalar(&k),
                _ => self.unknown_key(&k, DPI_KEYS, "a `dpi:` block"),
            }
        }
        dpi
    }

    fn parse_schedule(&mut self, key: &Spanned<String>) -> Schedule {
        let mut s = Schedule {
            span: key.span,
            ..Default::default()
        };
        let Some(col) = self.block_col(key.span.col) else {
            return s;
        };
        let mut seen = Vec::new();
        while let Some(k) = self.next_key_at(col) {
            if self.check_duplicate(&mut seen, &k) {
                self.skip_value(col);
                continue;
            }
            match k.value.as_str() {
                "days" => s.days = self.value_string_list(&k),
                "start" => s.start = self.value_scalar(&k),
                "end" => s.end = self.value_scalar(&k),
                _ => self.unknown_key(&k, SCHEDULE_KEYS, "a `schedule:` block"),
            }
        }
        s
    }

    fn parse_rate_limit(&mut self, key: &Spanned<String>) -> RateLimit {
        let mut rl = RateLimit {
            span: key.span,
            ..Default::default()
        };
        let Some(col) = self.block_col(key.span.col) else {
            return rl;
        };
        let mut seen = Vec::new();
        while let Some(k) = self.next_key_at(col) {
            if self.check_duplicate(&mut seen, &k) {
                self.skip_value(col);
                continue;
            }
            match k.value.as_str() {
                "rate" => rl.rate = self.value_scalar(&k),
                "per" => rl.per = self.value_scalar(&k),
                "burst" => rl.burst = self.value_scalar(&k),
                _ => self.unknown_key(&k, RATE_LIMIT_KEYS, "a `rate_limit:` block"),
            }
        }
        rl
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::tokenize;

    fn parse_ok(src: &str) -> PolicyDocument {
        let (tokens, ldiags) = tokenize(src);
        assert!(!ldiags.has_errors(), "lexer errors: {:?}", ldiags.codes());
        let (doc, diags) = parse(&tokens);
        assert!(!diags.has_errors(), "parser errors: {:?}", diags.codes());
        doc
    }

    fn parse_diags(src: &str) -> Diagnostics {
        let (tokens, mut d) = tokenize(src);
        let (_, pd) = parse(&tokens);
        d.extend(pd);
        d
    }

    const FULL: &str = r#"
version: 1

metadata:
  name: baseline
  description: "Default deny with explicit allows"
  revision: 7

defaults:
  action: deny
  log: true

address_groups:
  rfc1918:
    - 10.0.0.0/8
    - 192.168.0.0/16
  dns: [1.1.1.1/32, 8.8.8.8/32]

port_groups:
  web: [80, 443, 8000-8100]

applications:
  browser:
    description: Managed web browser
    trust: [trusted, system]
    platforms:
      windows:
        path: "C:\\Program Files\\Browser\\browser.exe"
        signer: Example Corp
      linux:
        paths:
          - /usr/bin/browser
          - /opt/browser/*
      macos:
        bundle_id: com.example.browser
        team_id: ABCDE12345

signature_groups:
  exploits: [1001, 1002]

network_profile:
  internal: [rfc1918]
  perimeter: [203.0.113.0/24]
  dns_servers: [1.1.1.1]
  perimeter_crossing_requires_dpi: true

rules:
  - id: allow-dns
    priority: 100
    layer: packet
    direction: outbound
    action: allow
    protocol: udp
    destination:
      addresses: [dns]
      ports: [53]
    tags: [baseline]

  - id: browser-web
    priority: 200
    layer: identity
    action: allow
    protocol: tcp
    application: browser
    destination:
      ports: web
      zones: [external]

  - id: block-exploits
    priority: 10
    layer: stream
    action: allow
    dpi:
      signatures: [exploits]
      protocols: [http, tls]
      on_match: deny
    schedule:
      days: [mon, tue, wed, thu, fri]
      start: "08:00"
      end: "18:00"
"#;

    #[test]
    fn parses_a_complete_policy() {
        let doc = parse_ok(FULL);
        assert_eq!(doc.version.as_ref().unwrap().value, "1");
        assert_eq!(
            doc.metadata.as_ref().unwrap().name.as_ref().unwrap().value,
            "baseline"
        );
        assert_eq!(
            doc.defaults
                .as_ref()
                .unwrap()
                .action
                .as_ref()
                .unwrap()
                .value,
            "deny"
        );
        assert_eq!(doc.address_groups.len(), 2);
        assert_eq!(doc.port_groups.len(), 1);
        assert_eq!(doc.signature_groups.len(), 1);
        assert_eq!(doc.applications.len(), 1);
        assert_eq!(doc.rules.len(), 3);
    }

    #[test]
    fn block_and_flow_sequences_are_equivalent() {
        let doc = parse_ok(FULL);
        let rfc1918 = &doc.address_groups[0];
        assert_eq!(rfc1918.name.value, "rfc1918");
        assert_eq!(
            rfc1918
                .entries
                .iter()
                .map(|e| e.value.as_str())
                .collect::<Vec<_>>(),
            vec!["10.0.0.0/8", "192.168.0.0/16"]
        );
        let dns = &doc.address_groups[1];
        assert_eq!(
            dns.entries
                .iter()
                .map(|e| e.value.as_str())
                .collect::<Vec<_>>(),
            vec!["1.1.1.1/32", "8.8.8.8/32"]
        );
    }

    #[test]
    fn dash_then_key_on_same_line_forms_one_mapping() {
        let doc = parse_ok(FULL);
        let r = &doc.rules[0];
        assert_eq!(r.id.as_ref().unwrap().value, "allow-dns");
        assert_eq!(r.priority.as_ref().unwrap().value, "100");
        assert_eq!(r.action.as_ref().unwrap().value, "allow");
        assert_eq!(r.protocol.as_ref().unwrap().value, "udp");
        let dst = r.destination.as_ref().unwrap();
        assert_eq!(dst.addresses.len(), 1);
        assert_eq!(dst.ports[0].value, "53");
        assert_eq!(r.tags[0].value, "baseline");
    }

    #[test]
    fn platform_blocks_nest_correctly() {
        let doc = parse_ok(FULL);
        let app = &doc.applications[0];
        assert_eq!(app.name.value, "browser");
        assert_eq!(app.trust.len(), 2);
        assert_eq!(app.platforms.len(), 3);
        let win = &app.platforms[0];
        assert_eq!(win.platform.value, "windows");
        assert_eq!(win.paths[0].value, r"C:\Program Files\Browser\browser.exe");
        assert_eq!(win.signers[0].value, "Example Corp");
        let lin = &app.platforms[1];
        assert_eq!(lin.paths.len(), 2);
        let mac = &app.platforms[2];
        assert_eq!(mac.bundle_ids[0].value, "com.example.browser");
        assert_eq!(mac.team_ids[0].value, "ABCDE12345");
    }

    #[test]
    fn scalar_shorthand_for_endpoint_and_application() {
        let doc = parse_ok(FULL);
        let r = &doc.rules[1];
        assert_eq!(r.application.as_ref().unwrap().names[0].value, "browser");
        let dst = r.destination.as_ref().unwrap();
        assert_eq!(dst.ports[0].value, "web");
        assert_eq!(dst.zones[0].value, "external");
    }

    #[test]
    fn dpi_and_schedule_blocks() {
        let doc = parse_ok(FULL);
        let r = &doc.rules[2];
        let dpi = r.dpi.as_ref().unwrap();
        assert_eq!(dpi.signatures[0].value, "exploits");
        assert_eq!(dpi.protocols.len(), 2);
        assert_eq!(dpi.on_match.as_ref().unwrap().value, "deny");
        let s = r.schedule.as_ref().unwrap();
        assert_eq!(s.days.len(), 5);
        assert_eq!(s.start.as_ref().unwrap().value, "08:00");
    }

    #[test]
    fn rate_limit_block_parses_into_its_fields() {
        let doc = parse_ok(
            "rules:\n  - id: a\n    action: allow\n    rate_limit:\n      rate: 50\n      \
             per: second\n      burst: 100\n",
        );
        let rl = doc.rules[0]
            .rate_limit
            .as_ref()
            .expect("a rate_limit block");
        assert_eq!(rl.rate.as_ref().unwrap().value, "50");
        assert_eq!(rl.per.as_ref().unwrap().value, "second");
        assert_eq!(rl.burst.as_ref().unwrap().value, "100");
    }

    #[test]
    fn unknown_top_level_key_is_an_error_with_a_suggestion() {
        let d = parse_diags("version: 1\nruels:\n  - id: a\n");
        assert!(d.has_code(codes::UNKNOWN_KEY));
        let text = d.iter().find(|x| x.code == codes::UNKNOWN_KEY).unwrap();
        assert_eq!(text.help.as_deref(), Some("did you mean `rules`?"));
    }

    #[test]
    fn unknown_rule_key_does_not_swallow_the_next_rule() {
        let src = "rules:\n  - id: a\n    destinaton:\n      ports: [1]\n  - id: b\n";
        let (tokens, _) = tokenize(src);
        let (doc, diags) = parse(&tokens);
        assert!(diags.has_code(codes::UNKNOWN_KEY));
        // Recovery must not lose rule `b`.
        assert_eq!(doc.rules.len(), 2);
        assert_eq!(doc.rules[1].id.as_ref().unwrap().value, "b");
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        let d = parse_diags("version: 1\nversion: 2\n");
        assert!(d.has_code(codes::DUPLICATE_KEY));

        let d = parse_diags("rules:\n  - id: a\n    action: allow\n    action: deny\n");
        assert!(d.has_code(codes::DUPLICATE_KEY));
    }

    #[test]
    fn missing_value_is_reported() {
        let d = parse_diags("version:\n");
        assert!(d.has_code(codes::EXPECTED_VALUE));
    }

    #[test]
    fn misindentation_is_reported_and_recovered() {
        let src = "metadata:\n  name: a\n      description: b\nversion: 1\n";
        let (tokens, _) = tokenize(src);
        let (doc, diags) = parse(&tokens);
        assert!(diags.has_code(codes::BAD_INDENT));
        assert_eq!(doc.version.as_ref().unwrap().value, "1");
    }

    #[test]
    fn empty_document_parses_to_an_empty_policy() {
        let doc = parse_ok("# nothing but a comment\n");
        assert!(doc.version.is_none());
        assert!(doc.rules.is_empty());
    }

    #[test]
    fn rules_with_no_dash_are_reported() {
        let d = parse_diags("rules:\n  id: a\n");
        assert!(d.has_code(codes::UNEXPECTED_TOKEN));
    }

    #[test]
    fn multi_line_flow_sequence_parses() {
        let doc = parse_ok("port_groups:\n  web: [80,\n    443]\n");
        assert_eq!(doc.port_groups[0].entries.len(), 2);
    }

    #[test]
    fn rule_span_covers_its_keys() {
        let doc = parse_ok("rules:\n  - id: a\n    action: allow\n");
        let r = &doc.rules[0];
        assert!(r.span.start < r.span.end);
        assert_eq!(r.span.line, 2);
    }

    #[test]
    fn parser_terminates_on_hostile_input() {
        for src in [
            "rules:\n  -\n",
            "rules:\n  - \n  - \n",
            "a:\n  b:\n    c:\n",
            "[",
            "- - -\n",
            "rules:\n  - id:\n",
            ":\n",
        ] {
            let (tokens, _) = tokenize(src);
            let _ = parse(&tokens);
        }
    }
}

//! Compiler diagnostics with source spans.
//!
//! A policy file is edited by humans under time pressure, often during an
//! incident. The difference between "invalid policy" and a message that points
//! at the offending column and says what to write instead is the difference
//! between a five-second fix and a rollback, so diagnostics here carry a span,
//! a stable code, and — where there is an obvious repair — a suggestion.
//!
//! Diagnostics are *collected*, not thrown. A single compile reports every
//! independent problem it can find rather than stopping at the first, because
//! an operator fixing a policy wants the whole list.

use std::fmt;

/// A byte range in a source file, plus the 1-based line/column of its start.
///
/// Both are stored because the byte range is what slices the source for the
/// snippet, and line/column is what the operator's editor understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Span {
    pub start: u32,
    pub end: u32,
    pub line: u32,
    pub col: u32,
}

impl Span {
    pub fn new(start: u32, end: u32, line: u32, col: u32) -> Self {
        Span { start, end, line, col }
    }

    /// A zero-width span, used for diagnostics about something that is
    /// *missing* rather than wrong.
    pub fn point(at: u32, line: u32, col: u32) -> Self {
        Span { start: at, end: at, line, col }
    }

    /// Smallest span covering both.
    pub fn merge(self, other: Span) -> Span {
        if self.start <= other.start {
            Span { start: self.start, end: self.end.max(other.end), line: self.line, col: self.col }
        } else {
            Span { start: other.start, end: self.end.max(other.end), line: other.line, col: other.col }
        }
    }

    pub fn len(&self) -> u32 {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }
}

/// A value together with where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spanned<T> {
    pub value: T,
    pub span: Span,
}

impl<T> Spanned<T> {
    pub fn new(value: T, span: Span) -> Self {
        Spanned { value, span }
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Spanned<U> {
        Spanned { value: f(self.value), span: self.span }
    }

    pub fn as_ref(&self) -> Spanned<&T> {
        Spanned { value: &self.value, span: self.span }
    }
}

impl<T: fmt::Display> fmt::Display for Spanned<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Compilation cannot produce a policy.
    Error,
    /// Compilation succeeds but the policy probably does not do what the
    /// author intended.
    Warning,
    /// Informational: what the optimizer changed, and why.
    Note,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Note => "note",
        }
    }
}

/// Stable diagnostic codes.
///
/// These appear in CI output and in `ufwctl policy validate`, so they are
/// treated as API: a code's meaning never changes once assigned.
pub mod codes {
    // Lexical
    pub const TAB_INDENT: &str = "E0001";
    pub const UNTERMINATED_STRING: &str = "E0002";
    pub const BAD_ESCAPE: &str = "E0003";
    pub const UNCLOSED_FLOW_SEQ: &str = "E0004";
    pub const STRAY_CHARACTER: &str = "E0005";

    // Syntactic
    pub const UNEXPECTED_TOKEN: &str = "E0100";
    pub const EXPECTED_KEY: &str = "E0101";
    pub const EXPECTED_VALUE: &str = "E0102";
    pub const BAD_INDENT: &str = "E0103";
    pub const DUPLICATE_KEY: &str = "E0104";
    pub const UNKNOWN_KEY: &str = "E0105";

    // Semantic
    pub const UNSUPPORTED_VERSION: &str = "E0200";
    pub const MISSING_FIELD: &str = "E0201";
    pub const UNKNOWN_ENUM: &str = "E0202";
    pub const BAD_LITERAL: &str = "E0203";
    pub const UNRESOLVED_REFERENCE: &str = "E0204";
    pub const DUPLICATE_DEFINITION: &str = "E0205";
    pub const EMPTY_SELECTOR: &str = "E0206";
    pub const LAYER_MISMATCH: &str = "E0207";
    pub const PORTS_ON_PORTLESS_PROTOCOL: &str = "E0208";
    pub const LIMIT_EXCEEDED: &str = "E0209";
    pub const RULE_ID_COLLISION: &str = "E0210";
    pub const CYCLIC_REFERENCE: &str = "E0211";
    pub const BAD_TIME_RANGE: &str = "E0212";

    // Warnings
    pub const UNREACHABLE_RULE: &str = "W0300";
    pub const REDUNDANT_PREDICATE: &str = "W0301";
    pub const UNCONSTRAINED_APP_SELECTOR: &str = "W0302";
    pub const UNUSED_DEFINITION: &str = "W0303";
    pub const BROAD_ALLOW: &str = "W0304";
    pub const DPI_WITHOUT_CAPABILITY: &str = "W0305";
    pub const NEGATED_WILDCARD: &str = "W0306";

    // Pipeline / driver
    pub const IGNORED_INCLUDE_SETTING: &str = "W0307";
    pub const WARNINGS_DENIED: &str = "E0500";
    /// The three backends disagreed. Always a compiler defect, never a policy
    /// defect, which is why it has its own code.
    pub const INTERNAL_EQUIVALENCE_FAILURE: &str = "E0501";

    // Notes
    pub const RULES_MERGED: &str = "N0400";
    pub const RULE_ELIMINATED: &str = "N0401";
    pub const EBPF_OFFLOAD: &str = "N0402";
    pub const PERIMETER_UPGRADE: &str = "N0403";
}

/// One diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: &'static str,
    pub message: String,
    pub span: Span,
    /// Text rendered under the caret.
    pub label: Option<String>,
    /// Additional spans with their own labels, e.g. "first defined here".
    pub secondary: Vec<(Span, String)>,
    /// Suggested repair, rendered as `= help: ...`.
    pub help: Option<String>,
}

impl Diagnostic {
    pub fn error(code: &'static str, span: Span, message: impl Into<String>) -> Self {
        Diagnostic {
            severity: Severity::Error,
            code,
            message: message.into(),
            span,
            label: None,
            secondary: Vec::new(),
            help: None,
        }
    }

    pub fn warning(code: &'static str, span: Span, message: impl Into<String>) -> Self {
        Diagnostic { severity: Severity::Warning, ..Self::error(code, span, message) }
    }

    pub fn note(code: &'static str, span: Span, message: impl Into<String>) -> Self {
        Diagnostic { severity: Severity::Note, ..Self::error(code, span, message) }
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    pub fn with_secondary(mut self, span: Span, label: impl Into<String>) -> Self {
        self.secondary.push((span, label.into()));
        self
    }

    /// Render with a source snippet and caret underline.
    pub fn render(&self, source: &SourceFile) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "{}[{}]: {}\n",
            self.severity.as_str(),
            self.code,
            self.message
        ));
        out.push_str(&format!(
            "  --> {}:{}:{}\n",
            source.name, self.span.line, self.span.col
        ));
        render_snippet(&mut out, source, self.span, self.label.as_deref());
        for (span, label) in &self.secondary {
            out.push_str(&format!(
                "  --> {}:{}:{}\n",
                source.name, span.line, span.col
            ));
            render_snippet(&mut out, source, *span, Some(label));
        }
        if let Some(help) = &self.help {
            out.push_str(&format!("   = help: {help}\n"));
        }
        out
    }
}

fn render_snippet(out: &mut String, source: &SourceFile, span: Span, label: Option<&str>) {
    let Some(line_text) = source.line(span.line) else {
        return;
    };
    let gutter_width = span.line.to_string().len().max(2);
    let pad = " ".repeat(gutter_width);
    out.push_str(&format!("{pad} |\n"));
    out.push_str(&format!(
        "{:>width$} | {}\n",
        span.line,
        line_text.trim_end(),
        width = gutter_width
    ));
    // Column is 1-based and counted in characters, matching what an editor
    // shows; tabs are rejected in indentation so a space run is faithful.
    let caret_pad = " ".repeat(span.col.saturating_sub(1) as usize);
    let caret_len = span.len().max(1) as usize;
    let carets = "^".repeat(caret_len.min(line_text.chars().count().max(1)));
    match label {
        Some(l) => out.push_str(&format!("{pad} | {caret_pad}{carets} {l}\n")),
        None => out.push_str(&format!("{pad} | {caret_pad}{carets}\n")),
    }
}

/// A named source text, kept alongside diagnostics so they can be rendered.
#[derive(Debug, Clone)]
pub struct SourceFile {
    pub name: String,
    pub text: String,
    /// Byte offset of the start of each line, 0-based index = line 1.
    line_starts: Vec<u32>,
}

impl SourceFile {
    pub fn new(name: impl Into<String>, text: impl Into<String>) -> Self {
        let text = text.into();
        let mut line_starts = vec![0u32];
        for (i, b) in text.bytes().enumerate() {
            if b == b'\n' {
                line_starts.push(i as u32 + 1);
            }
        }
        SourceFile { name: name.into(), text, line_starts }
    }

    /// 1-based line lookup.
    pub fn line(&self, line: u32) -> Option<&str> {
        if line == 0 {
            return None;
        }
        let idx = (line - 1) as usize;
        let start = *self.line_starts.get(idx)? as usize;
        let end = self
            .line_starts
            .get(idx + 1)
            .map(|e| *e as usize - 1)
            .unwrap_or(self.text.len());
        self.text.get(start..end.min(self.text.len()))
    }

    pub fn line_count(&self) -> u32 {
        self.line_starts.len() as u32
    }
}

/// A collection of diagnostics produced by one compilation.
#[derive(Debug, Clone, Default)]
pub struct Diagnostics {
    items: Vec<Diagnostic>,
}

impl Diagnostics {
    pub fn new() -> Self {
        Diagnostics::default()
    }

    pub fn push(&mut self, d: Diagnostic) {
        self.items.push(d);
    }

    pub fn extend(&mut self, other: Diagnostics) {
        self.items.extend(other.items);
    }

    pub fn iter(&self) -> impl Iterator<Item = &Diagnostic> {
        self.items.iter()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn errors(&self) -> impl Iterator<Item = &Diagnostic> {
        self.items.iter().filter(|d| d.severity == Severity::Error)
    }

    pub fn warnings(&self) -> impl Iterator<Item = &Diagnostic> {
        self.items.iter().filter(|d| d.severity == Severity::Warning)
    }

    pub fn has_errors(&self) -> bool {
        self.errors().next().is_some()
    }

    pub fn error_count(&self) -> usize {
        self.errors().count()
    }

    pub fn warning_count(&self) -> usize {
        self.warnings().count()
    }

    /// Whether a diagnostic with this code was produced. Used extensively by
    /// the test-suite, which asserts on codes rather than message text so that
    /// wording can be improved without breaking tests.
    pub fn has_code(&self, code: &str) -> bool {
        self.items.iter().any(|d| d.code == code)
    }

    pub fn codes(&self) -> Vec<&'static str> {
        self.items.iter().map(|d| d.code).collect()
    }

    /// Sort by source position so output reads top-to-bottom.
    pub fn sort(&mut self) {
        self.items
            .sort_by_key(|d| (d.span.line, d.span.col, d.code));
    }

    pub fn render(&self, source: &SourceFile) -> String {
        let mut out = String::new();
        for d in &self.items {
            out.push_str(&d.render(source));
            out.push('\n');
        }
        if self.has_errors() {
            out.push_str(&format!(
                "compilation failed: {} error(s), {} warning(s)\n",
                self.error_count(),
                self.warning_count()
            ));
        }
        out
    }

    pub fn into_vec(self) -> Vec<Diagnostic> {
        self.items
    }
}

impl IntoIterator for Diagnostics {
    type Item = Diagnostic;
    type IntoIter = std::vec::IntoIter<Diagnostic>;
    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

/// Result type used throughout the compiler: a value plus every diagnostic
/// gathered on the way to it. `value` is `None` only when a phase could not
/// produce anything usable.
#[derive(Debug, Clone)]
pub struct Outcome<T> {
    pub value: Option<T>,
    pub diagnostics: Diagnostics,
}

impl<T> Outcome<T> {
    pub fn ok(value: T) -> Self {
        Outcome { value: Some(value), diagnostics: Diagnostics::new() }
    }

    pub fn with(value: T, diagnostics: Diagnostics) -> Self {
        let value = if diagnostics.has_errors() { None } else { Some(value) };
        Outcome { value, diagnostics }
    }

    pub fn failed(diagnostics: Diagnostics) -> Self {
        Outcome { value: None, diagnostics }
    }

    pub fn is_ok(&self) -> bool {
        self.value.is_some()
    }

    /// Take the value, panicking with rendered diagnostics if there is none.
    /// Test-only convenience; production paths match on `value`.
    #[track_caller]
    pub fn expect_ok(self, source: &SourceFile) -> T {
        match self.value {
            Some(v) => v,
            None => panic!("compilation failed:\n{}", self.diagnostics.render(source)),
        }
    }
}

/// Suggest the closest match from a set of known names.
///
/// Plain Levenshtein over a small candidate set: policy files misspell enum
/// values and group names constantly, and "did you mean `outbound`?" is worth
/// far more than "unknown value".
pub fn closest_match<'a, I: IntoIterator<Item = &'a str>>(
    input: &str,
    candidates: I,
) -> Option<&'a str> {
    let input_lower = input.to_ascii_lowercase();
    let mut best: Option<(usize, &str)> = None;
    for c in candidates {
        let d = levenshtein(&input_lower, &c.to_ascii_lowercase());
        // Only suggest when the edit distance is small relative to the word.
        let threshold = (c.len() / 3).max(2);
        if d <= threshold && best.map(|(bd, _)| d < bd).unwrap_or(true) {
            best = Some((d, c));
        }
    }
    best.map(|(_, c)| c)
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_file_line_lookup() {
        let s = SourceFile::new("t.yaml", "one\ntwo\nthree");
        assert_eq!(s.line(1), Some("one"));
        assert_eq!(s.line(2), Some("two"));
        assert_eq!(s.line(3), Some("three"));
        assert_eq!(s.line(4), None);
        assert_eq!(s.line(0), None);
        assert_eq!(s.line_count(), 3);
    }

    #[test]
    fn source_file_handles_trailing_newline() {
        let s = SourceFile::new("t.yaml", "a\nb\n");
        assert_eq!(s.line(1), Some("a"));
        assert_eq!(s.line(2), Some("b"));
        assert_eq!(s.line(3), Some(""));
    }

    #[test]
    fn rendered_diagnostic_points_at_the_right_column() {
        let src = SourceFile::new("p.yaml", "rules:\n  - action: allowe\n");
        let d = Diagnostic::error(codes::UNKNOWN_ENUM, Span::new(19, 25, 2, 13), "unknown action `allowe`")
            .with_label("not a valid action")
            .with_help("did you mean `allow`?");
        let text = d.render(&src);
        assert!(text.contains("error[E0202]: unknown action `allowe`"));
        assert!(text.contains("--> p.yaml:2:13"));
        assert!(text.contains("  - action: allowe"));
        // The caret must land under `allowe`. The gutter is `NN | ` (5
        // characters here) and the value starts at column 13, so the caret
        // belongs at index 5 + 12.
        let source_line = text.lines().find(|l| l.contains("- action")).unwrap();
        let caret_line = text.lines().find(|l| l.contains('^')).unwrap();
        assert_eq!(source_line.find("allowe"), Some(17));
        assert_eq!(caret_line.find('^'), Some(17));
        assert!(text.contains("= help: did you mean `allow`?"));
    }

    #[test]
    fn diagnostics_collect_rather_than_stop() {
        let mut d = Diagnostics::new();
        d.push(Diagnostic::error(codes::MISSING_FIELD, Span::default(), "a"));
        d.push(Diagnostic::warning(codes::BROAD_ALLOW, Span::default(), "b"));
        d.push(Diagnostic::note(codes::RULES_MERGED, Span::default(), "c"));
        assert_eq!(d.len(), 3);
        assert_eq!(d.error_count(), 1);
        assert_eq!(d.warning_count(), 1);
        assert!(d.has_errors());
        assert!(d.has_code(codes::BROAD_ALLOW));
        assert!(!d.has_code("E9999"));
    }

    #[test]
    fn outcome_discards_value_when_errors_present() {
        let mut d = Diagnostics::new();
        d.push(Diagnostic::error(codes::MISSING_FIELD, Span::default(), "boom"));
        let o = Outcome::with(42u32, d);
        assert!(!o.is_ok());

        let mut d = Diagnostics::new();
        d.push(Diagnostic::warning(codes::BROAD_ALLOW, Span::default(), "meh"));
        let o = Outcome::with(42u32, d);
        assert_eq!(o.value, Some(42));
    }

    #[test]
    fn span_merge_covers_both() {
        let a = Span::new(10, 20, 2, 3);
        let b = Span::new(5, 15, 1, 1);
        let m = a.merge(b);
        assert_eq!((m.start, m.end, m.line, m.col), (5, 20, 1, 1));
    }

    #[test]
    fn suggestions_are_close_but_not_wild() {
        let candidates = ["allow", "deny", "alert", "continue"];
        assert_eq!(closest_match("allowe", candidates), Some("allow"));
        assert_eq!(closest_match("dney", candidates), Some("deny"));
        assert_eq!(closest_match("ALERT", candidates), Some("alert"));
        // Nothing plausible: better silent than misleading.
        assert_eq!(closest_match("quantum", candidates), None);
    }
}

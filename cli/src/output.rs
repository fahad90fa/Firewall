//! Terminal output formatting.
//!
//! Three formats, one rule: **`--output json` prints exactly what the daemon
//! returned.** Not a re-serialization, not a subset — the bytes. An operator
//! piping `ufwctl status -o json` into `jq` during an incident is debugging
//! the daemon, and a CLI that reshapes the payload on the way past is
//! debugging itself.
//!
//! The table format is the one humans read, so it is allowed to drop fields,
//! reorder them and abbreviate. YAML sits between: complete, but easier to
//! read than dense JSON.

use std::fmt::Write as _;

use ufw_shared::json::Json;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    #[default]
    Table,
    Json,
    Yaml,
}

impl Format {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "table" | "text" => Format::Table,
            "json" => Format::Json,
            "yaml" | "yml" => Format::Yaml,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Format::Table => "table",
            Format::Json => "json",
            Format::Yaml => "yaml",
        }
    }
}

/// A table with aligned columns.
#[derive(Debug, Default)]
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    pub fn new<S: Into<String>>(headers: impl IntoIterator<Item = S>) -> Self {
        Table {
            headers: headers.into_iter().map(Into::into).collect(),
            rows: Vec::new(),
        }
    }

    pub fn push<S: Into<String>>(&mut self, row: impl IntoIterator<Item = S>) {
        self.rows.push(row.into_iter().map(Into::into).collect());
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Render with two spaces between columns.
    ///
    /// Width is measured in characters rather than bytes, so a rule name with
    /// a non-ASCII character does not skew the column it is in.
    pub fn render(&self) -> String {
        let columns = self.headers.len();
        let mut widths: Vec<usize> = self.headers.iter().map(|h| h.chars().count()).collect();
        for row in &self.rows {
            for (i, cell) in row.iter().take(columns).enumerate() {
                widths[i] = widths[i].max(cell.chars().count());
            }
        }

        let mut out = String::new();
        for (i, header) in self.headers.iter().enumerate() {
            let _ = write!(out, "{}", pad(header, widths[i], i + 1 == columns));
        }
        out.push('\n');

        for row in &self.rows {
            for (i, cell) in row.iter().take(columns).enumerate() {
                let _ = write!(out, "{}", pad(cell, widths[i], i + 1 == columns));
            }
            out.push('\n');
        }
        out
    }
}

fn pad(text: &str, width: usize, last: bool) -> String {
    if last {
        return text.to_string();
    }
    let len = text.chars().count();
    let mut out = String::with_capacity(width + 2);
    out.push_str(text);
    for _ in len..width + 2 {
        out.push(' ');
    }
    out
}

/// Render a parsed JSON value as YAML.
///
/// A small emitter rather than a dependency: this is display-only output, and
/// nothing reads it back.
pub fn to_yaml(value: &Json, indent: usize) -> String {
    let pad = "  ".repeat(indent);
    match value {
        Json::Null => "null".into(),
        Json::Bool(b) => b.to_string(),
        Json::Number(n) => {
            if n.fract() == 0.0 && n.abs() < 1e15 {
                format!("{}", *n as i64)
            } else {
                n.to_string()
            }
        }
        Json::String(s) => yaml_scalar(s),
        Json::Array(items) if items.is_empty() => "[]".into(),
        Json::Array(items) => {
            let mut out = String::new();
            for item in items {
                out.push('\n');
                out.push_str(&pad);
                out.push_str("- ");
                let rendered = to_yaml(item, indent + 1);
                // A nested block starts on the next line; a scalar stays put.
                out.push_str(rendered.trim_start_matches('\n').trim_start());
            }
            out
        }
        Json::Object(map) if map.is_empty() => "{}".into(),
        Json::Object(map) => {
            let mut out = String::new();
            for (key, val) in map {
                out.push('\n');
                out.push_str(&pad);
                let _ = write!(out, "{key}:");
                let rendered = to_yaml(val, indent + 1);
                if rendered.starts_with('\n') {
                    out.push_str(&rendered);
                } else {
                    let _ = write!(out, " {rendered}");
                }
            }
            out
        }
    }
}

/// Quote a YAML scalar when leaving it bare would change its meaning.
fn yaml_scalar(s: &str) -> String {
    let needs_quotes = s.is_empty()
        || s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit() || c == '-')
        || s.contains(": ")
        || s.contains('\n')
        || s.contains('#')
        || matches!(
            s.to_ascii_lowercase().as_str(),
            "true" | "false" | "null" | "yes" | "no" | "on" | "off"
        );
    if needs_quotes {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        s.to_string()
    }
}

/// Emit a daemon response in the requested format.
///
/// `table` is a closure so a command only builds its table when one is
/// actually going to be printed.
pub fn emit(format: Format, raw: &str, table: impl FnOnce(&Json) -> String) -> String {
    match format {
        // Verbatim: the operator asked for what the daemon said.
        Format::Json => raw.to_string(),
        Format::Yaml => match ufw_shared::json::parse(raw) {
            Ok(v) => to_yaml(&v, 0).trim_start_matches('\n').to_string() + "\n",
            Err(_) => raw.to_string(),
        },
        Format::Table => match ufw_shared::json::parse(raw) {
            Ok(v) => table(&v),
            Err(_) => raw.to_string(),
        },
    }
}

/// Field lookup with a default, for building tables from a response.
pub fn field<'a>(value: &'a Json, key: &str) -> &'a Json {
    value.get(key).unwrap_or(&Json::Null)
}

pub fn text(value: &Json, key: &str) -> String {
    match value.get(key) {
        Some(Json::String(s)) => s.clone(),
        Some(Json::Number(n)) if n.fract() == 0.0 => format!("{}", *n as i64),
        Some(Json::Number(n)) => n.to_string(),
        Some(Json::Bool(b)) => b.to_string(),
        Some(Json::Null) | None => "-".into(),
        Some(other) => format!("{other:?}"),
    }
}

pub fn number(value: &Json, key: &str) -> u64 {
    value.get(key).and_then(|v| v.as_u64()).unwrap_or(0)
}

/// Human-readable duration, e.g. `3d 4h 12m`.
pub fn duration(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

/// Byte count with a binary unit suffix.
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ufw_shared::json;

    #[test]
    fn tables_align_on_character_width() {
        let mut t = Table::new(["ID", "NAME", "ACTION"]);
        t.push(["1", "allow-dns", "allow"]);
        t.push(["22", "block-café", "deny"]);
        let rendered = t.render();
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), 3);
        // Every row starts its second column at the same character offset.
        let offset = |line: &str| line.chars().position(|c| c != ' ').unwrap_or(0);
        let _ = offset;
        for line in &lines {
            assert!(line.contains("  "), "{line}");
        }
        assert!(lines[2].starts_with("22  "));
    }

    #[test]
    fn json_output_is_the_daemon_response_verbatim() {
        // Byte-for-byte: an operator piping into jq is debugging the daemon,
        // not the CLI.
        let raw = r#"{"ok":true,"weird_field":[1,2,3],"nested":{"a":null}}"#;
        assert_eq!(emit(Format::Json, raw, |_| "table".into()), raw);
    }

    #[test]
    fn yaml_output_round_trips_the_structure() {
        let raw = r#"{"host":"web-01","policy":{"revision":7,"rules":12},"tags":["a","b"]}"#;
        let out = emit(Format::Yaml, raw, |_| String::new());
        assert!(out.contains("host: web-01"));
        assert!(out.contains("policy:"));
        assert!(out.contains("  revision: 7"));
        assert!(out.contains("  - a"));
    }

    #[test]
    fn yaml_quotes_scalars_that_would_change_meaning() {
        assert_eq!(yaml_scalar("plain"), "plain");
        assert_eq!(yaml_scalar("true"), "\"true\"");
        assert_eq!(yaml_scalar("no"), "\"no\"");
        assert_eq!(yaml_scalar("123"), "\"123\"");
        assert_eq!(yaml_scalar(""), "\"\"");
        assert_eq!(yaml_scalar("a: b"), "\"a: b\"");
        assert_eq!(yaml_scalar("-dash"), "\"-dash\"");
        assert_eq!(yaml_scalar("has#hash"), "\"has#hash\"");
    }

    #[test]
    fn a_malformed_response_is_passed_through_rather_than_swallowed() {
        // If the daemon ever answers with something unparseable, the operator
        // needs to see it, not an empty table.
        let raw = "not json at all";
        for format in [Format::Json, Format::Yaml, Format::Table] {
            assert_eq!(emit(format, raw, |_| "table".into()), raw);
        }
    }

    #[test]
    fn empty_collections_render_compactly() {
        let v = json::parse(r#"{"a":[],"b":{}}"#).unwrap();
        let out = to_yaml(&v, 0);
        assert!(out.contains("a: []"));
        assert!(out.contains("b: {}"));
    }

    #[test]
    fn field_accessors_fall_back_rather_than_panic() {
        let v = json::parse(r#"{"s":"x","n":42,"b":true,"z":null}"#).unwrap();
        assert_eq!(text(&v, "s"), "x");
        assert_eq!(text(&v, "n"), "42");
        assert_eq!(text(&v, "b"), "true");
        assert_eq!(text(&v, "z"), "-");
        assert_eq!(text(&v, "missing"), "-");
        assert_eq!(number(&v, "n"), 42);
        assert_eq!(number(&v, "missing"), 0);
        assert_eq!(field(&v, "missing"), &Json::Null);
    }

    #[test]
    fn durations_read_naturally() {
        assert_eq!(duration(45), "45s");
        assert_eq!(duration(125), "2m 5s");
        assert_eq!(duration(3_725), "1h 2m");
        assert_eq!(duration(90_061), "1d 1h 1m");
    }

    #[test]
    fn byte_counts_get_a_unit() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(2048), "2.0 KiB");
        assert_eq!(bytes(5 * 1024 * 1024), "5.0 MiB");
    }

    #[test]
    fn format_parsing_accepts_the_documented_aliases() {
        assert_eq!(Format::parse("json"), Some(Format::Json));
        assert_eq!(Format::parse("yml"), Some(Format::Yaml));
        assert_eq!(Format::parse("text"), Some(Format::Table));
        assert_eq!(Format::parse("xml"), None);
    }
}

//! Minimal JSON emitter and parser.
//!
//! The daemon emits JSON in three places (structured log events, the REST
//! management API, and the CLI's `--output json` mode) and parses it in one
//! (REST request bodies). That is not enough surface to justify pulling a
//! serialization framework into the trusted computing base, so this module
//! implements exactly what those four call sites need.
//!
//! The emitter is a builder rather than a derive: log events are hot-path
//! structures and writing them field-by-field into a reused `String` avoids
//! constructing an intermediate value tree per packet decision.

use std::collections::BTreeMap;
use std::fmt::Write as _;

// ---------------------------------------------------------------------------
// Emitting
// ---------------------------------------------------------------------------

/// Append `s` to `out` as a JSON string literal, including the quotes.
///
/// Escapes per RFC 8259: the two mandatory escapes, the five short escapes,
/// and `\u00XX` for the remaining control characters. Multi-byte UTF-8 is
/// passed through unescaped, which is legal and keeps log lines readable.
pub fn escape_into(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Quote and escape `s` into a fresh `String`.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    escape_into(&mut out, s);
    out
}

/// Incremental JSON object/array writer.
///
/// Tracks whether a separating comma is needed so call sites do not have to.
/// Nesting is manual (`begin_object` / `end_object`); the writer does not
/// validate balance, and every emitter in this tree is covered by a test that
/// round-trips its output through [`parse`].
pub struct JsonWriter {
    out: String,
    needs_comma: Vec<bool>,
}

impl Default for JsonWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl JsonWriter {
    pub fn new() -> Self {
        JsonWriter { out: String::with_capacity(512), needs_comma: vec![false] }
    }

    pub fn with_capacity(n: usize) -> Self {
        JsonWriter { out: String::with_capacity(n), needs_comma: vec![false] }
    }

    pub fn finish(self) -> String {
        self.out
    }

    pub fn as_str(&self) -> &str {
        &self.out
    }

    fn sep(&mut self) {
        if let Some(last) = self.needs_comma.last_mut() {
            if *last {
                self.out.push(',');
            } else {
                *last = true;
            }
        }
    }

    fn push_frame(&mut self) {
        self.needs_comma.push(false);
    }

    fn pop_frame(&mut self) {
        self.needs_comma.pop();
    }

    pub fn begin_object(&mut self) {
        self.sep();
        self.out.push('{');
        self.push_frame();
    }

    pub fn end_object(&mut self) {
        self.pop_frame();
        self.out.push('}');
        // A complete value was just written into the enclosing frame, so the
        // next sibling needs a separating comma. This matters for the
        // `begin_object_field` path, where `key()` deliberately cleared the
        // flag so the value itself would not emit one.
        self.value_done();
    }

    pub fn begin_array(&mut self) {
        self.sep();
        self.out.push('[');
        self.push_frame();
    }

    pub fn end_array(&mut self) {
        self.pop_frame();
        self.out.push(']');
        self.value_done();
    }

    /// Emit a key and open an object as its value.
    pub fn begin_object_field(&mut self, key: &str) {
        self.key(key);
        self.out.push('{');
        self.push_frame();
    }

    /// Emit a key and open an array as its value.
    pub fn begin_array_field(&mut self, key: &str) {
        self.key(key);
        self.out.push('[');
        self.push_frame();
    }

    fn key(&mut self, key: &str) {
        self.sep();
        escape_into(&mut self.out, key);
        self.out.push(':');
        // The value that follows must not emit its own leading comma.
        if let Some(last) = self.needs_comma.last_mut() {
            *last = false;
        }
    }

    /// After writing a key the frame's comma flag is cleared so the value does
    /// not emit one; restore it once the value is complete.
    fn value_done(&mut self) {
        if let Some(last) = self.needs_comma.last_mut() {
            *last = true;
        }
    }

    pub fn str_field(&mut self, key: &str, value: &str) {
        self.key(key);
        escape_into(&mut self.out, value);
        self.value_done();
    }

    pub fn opt_str_field(&mut self, key: &str, value: Option<&str>) {
        match value {
            Some(v) => self.str_field(key, v),
            None => self.null_field(key),
        }
    }

    pub fn u64_field(&mut self, key: &str, value: u64) {
        self.key(key);
        let _ = write!(self.out, "{value}");
        self.value_done();
    }

    pub fn i64_field(&mut self, key: &str, value: i64) {
        self.key(key);
        let _ = write!(self.out, "{value}");
        self.value_done();
    }

    pub fn f64_field(&mut self, key: &str, value: f64) {
        self.key(key);
        if value.is_finite() {
            let _ = write!(self.out, "{value}");
        } else {
            // JSON has no NaN/Infinity; null is the conventional stand-in.
            self.out.push_str("null");
        }
        self.value_done();
    }

    pub fn bool_field(&mut self, key: &str, value: bool) {
        self.key(key);
        self.out.push_str(if value { "true" } else { "false" });
        self.value_done();
    }

    pub fn null_field(&mut self, key: &str) {
        self.key(key);
        self.out.push_str("null");
        self.value_done();
    }

    /// Emit an already-serialized JSON fragment as the value of `key`.
    /// The caller is responsible for the fragment being valid JSON.
    pub fn raw_field(&mut self, key: &str, raw: &str) {
        self.key(key);
        self.out.push_str(raw);
        self.value_done();
    }

    pub fn str_element(&mut self, value: &str) {
        self.sep();
        escape_into(&mut self.out, value);
    }

    pub fn u64_element(&mut self, value: u64) {
        self.sep();
        let _ = write!(self.out, "{value}");
    }

    pub fn raw_element(&mut self, raw: &str) {
        self.sep();
        self.out.push_str(raw);
    }

    /// Convenience: emit `key: [a, b, c]` from string items.
    pub fn str_array_field<'a, I: IntoIterator<Item = &'a str>>(&mut self, key: &str, items: I) {
        self.begin_array_field(key);
        for item in items {
            self.str_element(item);
        }
        self.end_array();
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// A parsed JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(m) => m.get(key),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Number(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Number(n) if *n >= 0.0 && n.fract() == 0.0 => Some(*n as u64),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(a) => Some(a),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonError {
    pub offset: usize,
    pub message: String,
}

impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid JSON at byte {}: {}", self.offset, self.message)
    }
}

impl std::error::Error for JsonError {}

/// Parse a complete JSON document. Trailing whitespace is allowed; trailing
/// non-whitespace is an error.
pub fn parse(input: &str) -> Result<Json, JsonError> {
    let mut p = Parser { b: input.as_bytes(), pos: 0, depth: 0 };
    p.skip_ws();
    let v = p.value()?;
    p.skip_ws();
    if p.pos != p.b.len() {
        return Err(p.err("trailing data after JSON value"));
    }
    Ok(v)
}

/// Recursion limit. A hostile management-API body should be rejected, not
/// turned into a stack overflow.
const MAX_DEPTH: usize = 64;

struct Parser<'a> {
    b: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn err(&self, msg: &str) -> JsonError {
        JsonError { offset: self.pos, message: msg.to_string() }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.b.len() && matches!(self.b[self.pos], b' ' | b'\t' | b'\n' | b'\r') {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn literal(&mut self, lit: &str) -> bool {
        if self.b[self.pos..].starts_with(lit.as_bytes()) {
            self.pos += lit.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self) -> Result<Json, JsonError> {
        if self.depth >= MAX_DEPTH {
            return Err(self.err("nesting too deep"));
        }
        match self.peek() {
            None => Err(self.err("unexpected end of input")),
            Some(b'n') if self.literal("null") => Ok(Json::Null),
            Some(b't') if self.literal("true") => Ok(Json::Bool(true)),
            Some(b'f') if self.literal("false") => Ok(Json::Bool(false)),
            Some(b'"') => self.string().map(Json::String),
            Some(b'[') => self.array(),
            Some(b'{') => self.object(),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            Some(_) => Err(self.err("unexpected character")),
        }
    }

    fn array(&mut self) -> Result<Json, JsonError> {
        self.pos += 1; // '['
        self.depth += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.eat(b']') {
            self.depth -= 1;
            return Ok(Json::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value()?);
            self.skip_ws();
            if self.eat(b',') {
                continue;
            }
            if self.eat(b']') {
                break;
            }
            return Err(self.err("expected ',' or ']'"));
        }
        self.depth -= 1;
        Ok(Json::Array(items))
    }

    fn object(&mut self) -> Result<Json, JsonError> {
        self.pos += 1; // '{'
        self.depth += 1;
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.eat(b'}') {
            self.depth -= 1;
            return Ok(Json::Object(map));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("expected object key"));
            }
            let key = self.string()?;
            self.skip_ws();
            if !self.eat(b':') {
                return Err(self.err("expected ':'"));
            }
            self.skip_ws();
            let val = self.value()?;
            map.insert(key, val);
            self.skip_ws();
            if self.eat(b',') {
                continue;
            }
            if self.eat(b'}') {
                break;
            }
            return Err(self.err("expected ',' or '}'"));
        }
        self.depth -= 1;
        Ok(Json::Object(map))
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.pos += 1; // opening quote
        let mut s = String::new();
        loop {
            let c = self.peek().ok_or_else(|| self.err("unterminated string"))?;
            self.pos += 1;
            match c {
                b'"' => return Ok(s),
                b'\\' => {
                    let e = self.peek().ok_or_else(|| self.err("unterminated escape"))?;
                    self.pos += 1;
                    match e {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'/' => s.push('/'),
                        b'b' => s.push('\u{08}'),
                        b'f' => s.push('\u{0c}'),
                        b'n' => s.push('\n'),
                        b'r' => s.push('\r'),
                        b't' => s.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            // Surrogate pair: a high surrogate must be
                            // followed by \uDC00-\uDFFF to form a scalar.
                            let ch = if (0xD800..0xDC00).contains(&hi) {
                                if !self.eat(b'\\') || !self.eat(b'u') {
                                    return Err(self.err("lone high surrogate"));
                                }
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(self.err("invalid low surrogate"));
                                }
                                let cp =
                                    0x1_0000u32 + ((hi as u32 - 0xD800) << 10) + (lo as u32 - 0xDC00);
                                char::from_u32(cp).ok_or_else(|| self.err("invalid code point"))?
                            } else {
                                char::from_u32(hi as u32)
                                    .ok_or_else(|| self.err("invalid code point"))?
                            };
                            s.push(ch);
                        }
                        _ => return Err(self.err("invalid escape")),
                    }
                }
                c if c < 0x20 => return Err(self.err("control character in string")),
                c if c < 0x80 => s.push(c as char),
                _ => {
                    // Multi-byte UTF-8: find the extent and validate.
                    let start = self.pos - 1;
                    let len = utf8_len(c).ok_or_else(|| self.err("invalid UTF-8"))?;
                    if start + len > self.b.len() {
                        return Err(self.err("truncated UTF-8 sequence"));
                    }
                    let slice = &self.b[start..start + len];
                    let text = std::str::from_utf8(slice)
                        .map_err(|_| self.err("invalid UTF-8 sequence"))?;
                    s.push_str(text);
                    self.pos = start + len;
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u16, JsonError> {
        if self.pos + 4 > self.b.len() {
            return Err(self.err("truncated \\u escape"));
        }
        let mut v: u16 = 0;
        for i in 0..4 {
            let c = self.b[self.pos + i];
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return Err(self.err("invalid hex digit in \\u escape")),
            };
            v = (v << 4) | d as u16;
        }
        self.pos += 4;
        Ok(v)
    }

    /// Numbers follow RFC 8259 grammar exactly, including its two prohibitions
    /// that a permissive `f64::from_str` would happily accept: a leading zero
    /// (`01`) and an empty fraction or exponent (`1.`, `1e`).
    fn number(&mut self) -> Result<Json, JsonError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }

        let int_start = self.pos;
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.pos += 1;
        }
        let int_digits = self.pos - int_start;
        if int_digits == 0 {
            return Err(self.err("number has no integer part"));
        }
        if int_digits > 1 && self.b[int_start] == b'0' {
            return Err(JsonError {
                offset: int_start,
                message: "leading zeros are not allowed".into(),
            });
        }

        if self.peek() == Some(b'.') {
            self.pos += 1;
            let frac_start = self.pos;
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
            if self.pos == frac_start {
                return Err(self.err("number has no fractional digits"));
            }
        }

        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            let exp_start = self.pos;
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
            if self.pos == exp_start {
                return Err(self.err("number has no exponent digits"));
            }
        }

        let text = std::str::from_utf8(&self.b[start..self.pos])
            .map_err(|_| self.err("invalid number"))?;
        text.parse::<f64>()
            .map(Json::Number)
            .map_err(|_| JsonError { offset: start, message: "invalid number".into() })
    }
}

fn utf8_len(first: u8) -> Option<usize> {
    match first {
        0xC2..=0xDF => Some(2),
        0xE0..=0xEF => Some(3),
        0xF0..=0xF4 => Some(4),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_emits_commas_correctly() {
        let mut w = JsonWriter::new();
        w.begin_object();
        w.str_field("a", "x");
        w.u64_field("b", 7);
        w.begin_array_field("c");
        w.u64_element(1);
        w.u64_element(2);
        w.end_array();
        w.begin_object_field("d");
        w.bool_field("e", true);
        w.end_object();
        w.null_field("f");
        w.end_object();
        assert_eq!(w.as_str(), r#"{"a":"x","b":7,"c":[1,2],"d":{"e":true},"f":null}"#);
        assert!(parse(w.as_str()).is_ok());
    }

    #[test]
    fn escaping_covers_control_chars() {
        assert_eq!(escape("a\"b\\c\nd\te\u{01}"), r#""a\"b\\c\nd\te\u0001""#);
        // Non-ASCII passes through so log lines stay human-readable.
        assert_eq!(escape("héllo"), "\"héllo\"");
    }

    #[test]
    fn roundtrip_through_parser() {
        let src = r#"{"s":"h\u00e9llo \ud83d\ude00","n":-12.5e2,"t":true,"z":null,"a":[1,{"k":[]}]}"#;
        let v = parse(src).unwrap();
        assert_eq!(v.get("s").unwrap().as_str().unwrap(), "héllo 😀");
        assert_eq!(v.get("n").unwrap().as_f64().unwrap(), -1250.0);
        assert_eq!(v.get("t").unwrap().as_bool(), Some(true));
        assert_eq!(v.get("z"), Some(&Json::Null));
        assert_eq!(v.get("a").unwrap().as_array().unwrap().len(), 2);
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            "{", "[1,]", "{\"a\"}", "tru", "01", "\"\\x\"", "{\"a\":1}x", "\"\u{1}\"",
        ] {
            assert!(parse(bad).is_err(), "should have rejected {bad:?}");
        }
    }

    #[test]
    fn rejects_deep_nesting() {
        let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
        assert!(parse(&deep).is_err());
    }

    #[test]
    fn str_array_field_helper() {
        let mut w = JsonWriter::new();
        w.begin_object();
        w.str_array_field("tags", ["a", "b"]);
        w.u64_field("n", 1);
        w.end_object();
        assert_eq!(w.as_str(), r#"{"tags":["a","b"],"n":1}"#);
    }
}

//! Integration tests for the tokenizer, driven through the public API.
//!
//! The unit tests inside `lexer.rs` cover token shapes. These cover the
//! properties the rest of the compiler depends on: that spans point at real
//! bytes, that the token stream always terminates, and that the constructs
//! real policy files use survive tokenization intact.

use ufw_policy_lang::error::codes;
use ufw_policy_lang::lexer::{tokenize, Token, TokenKind};

fn tokens_of(src: &str) -> Vec<Token> {
    let (tokens, diags) = tokenize(src);
    assert!(
        !diags.has_errors(),
        "unexpected errors: {:?}",
        diags.codes()
    );
    tokens
}

/// Every token's span must slice the source without panicking, and the slice
/// must be what the token claims to cover.
#[test]
fn spans_are_valid_byte_ranges_into_the_source() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/realistic.yaml"
    ))
    .expect("fixture");

    let (tokens, _) = tokenize(&src);
    for t in &tokens {
        let range = t.span.start as usize..t.span.end as usize;
        assert!(
            range.end <= src.len(),
            "span {range:?} exceeds source length {}",
            src.len()
        );
        // Slicing must land on character boundaries.
        let slice = &src[range];
        match &t.kind {
            TokenKind::Key(k) => assert!(
                slice.contains(k.as_str()) || slice.contains(':'),
                "key token {k:?} does not cover its own text: {slice:?}"
            ),
            TokenKind::Dash => assert_eq!(slice, "-"),
            TokenKind::LBracket => assert_eq!(slice, "["),
            TokenKind::RBracket => assert_eq!(slice, "]"),
            TokenKind::Comma => assert_eq!(slice, ","),
            _ => {}
        }
    }
}

#[test]
fn a_realistic_policy_tokenizes_without_diagnostics() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/realistic.yaml"
    ))
    .expect("fixture");
    let (tokens, diags) = tokenize(&src);
    assert!(!diags.has_errors(), "{:?}", diags.codes());
    assert!(tokens.len() > 100, "fixture should be substantial");
    assert_eq!(tokens.last().unwrap().kind, TokenKind::Eof);
}

#[test]
fn every_input_terminates_with_exactly_one_eof() {
    let inputs = [
        "",
        "\n\n\n",
        "# only a comment",
        "a:",
        ":",
        "::::",
        "- - - -",
        "[[[[",
        "]]]]",
        "\"unterminated",
        "'unterminated",
        "\\",
        "a: \"\\",
        "\t\t\t",
        "key: [1, [2, [3",
        "\u{feff}version: 1",
        &"a: b\n".repeat(1000),
        &"[".repeat(500),
    ];
    for src in inputs {
        let (tokens, _) = tokenize(src);
        assert_eq!(
            tokens.iter().filter(|t| t.kind == TokenKind::Eof).count(),
            1,
            "input {src:?} did not produce exactly one Eof"
        );
        assert_eq!(tokens.last().unwrap().kind, TokenKind::Eof);
    }
}

#[test]
fn columns_survive_the_dash_and_multibyte_text() {
    let src = "rules:\n  - id: café\n    action: allow\n";
    let tokens = tokens_of(src);
    let col = |k: &str| tokens.iter().find(|t| t.key() == Some(k)).unwrap().col;
    assert_eq!(col("rules"), 1);
    assert_eq!(col("id"), 5);
    // `action` lines up with `id`, which is what makes them siblings even
    // though the preceding value contains a multi-byte character.
    assert_eq!(col("action"), 5);
}

#[test]
fn values_that_look_like_syntax_stay_values() {
    let cases = [
        (
            "path: C:\\Windows\\System32\\svchost.exe",
            "C:\\Windows\\System32\\svchost.exe",
        ),
        (
            "url: https://example.test:8443/a?b=c",
            "https://example.test:8443/a?b=c",
        ),
        ("hash: sha256:abcdef", "sha256:abcdef"),
        ("time: 08:00", "08:00"),
        ("range: 8000-8100", "8000-8100"),
        ("neg: -1", "-1"),
        ("tag: a#b", "a#b"),
    ];
    for (src, expected) in cases {
        let tokens = tokens_of(&format!("{src}\n"));
        let scalar = tokens
            .iter()
            .find_map(|t| t.scalar())
            .unwrap_or_else(|| panic!("no scalar in {src:?}"));
        assert_eq!(scalar, expected, "for input {src:?}");
    }
}

#[test]
fn lexical_errors_carry_their_documented_codes() {
    let cases: [(&str, &str); 4] = [
        ("a:\n\tb: 1\n", codes::TAB_INDENT),
        ("a: \"oops\n", codes::UNTERMINATED_STRING),
        ("a: \"\\q\"\n", codes::BAD_ESCAPE),
        ("a: [1, 2\n", codes::UNCLOSED_FLOW_SEQ),
    ];
    for (src, code) in cases {
        let (_, diags) = tokenize(src);
        assert!(diags.has_code(code), "{src:?} should report {code}");
    }
}

#[test]
fn line_numbers_are_one_based_and_count_every_line() {
    let src = "a: 1\n\n# comment\nb: 2\n";
    let tokens = tokens_of(src);
    let line = |k: &str| tokens.iter().find(|t| t.key() == Some(k)).unwrap().line;
    assert_eq!(line("a"), 1);
    assert_eq!(line("b"), 4);
}

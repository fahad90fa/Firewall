//! Integration tests for the parser: acceptance, rejection, and recovery.

use ufw_policy_lang::ast::PolicyDocument;
use ufw_policy_lang::error::{codes, Diagnostics};
use ufw_policy_lang::lexer::tokenize;
use ufw_policy_lang::parser::parse;

fn parse_src(src: &str) -> (PolicyDocument, Diagnostics) {
    let (tokens, mut diags) = tokenize(src);
    let (doc, pdiags) = parse(&tokens);
    diags.extend(pdiags);
    (doc, diags)
}

fn fixture() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/realistic.yaml"
    ))
    .expect("fixture")
}

#[test]
fn the_realistic_fixture_parses_completely() {
    let (doc, diags) = parse_src(&fixture());
    assert!(!diags.has_errors(), "{:?}", diags.codes());

    assert_eq!(doc.version.as_ref().unwrap().value, "1");
    let meta = doc.metadata.as_ref().unwrap();
    assert_eq!(meta.name.as_ref().unwrap().value, "workstation-baseline");
    assert_eq!(meta.revision.as_ref().unwrap().value, "12");

    assert_eq!(doc.address_groups.len(), 5);
    assert_eq!(doc.port_groups.len(), 4);
    assert_eq!(doc.signature_groups.len(), 3);
    assert_eq!(doc.applications.len(), 3);
    assert!(doc.network_profile.is_some());
    assert_eq!(doc.rules.len(), 10);
}

#[test]
fn applications_keep_their_per_platform_structure() {
    let (doc, _) = parse_src(&fixture());
    let browser = doc
        .applications
        .iter()
        .find(|a| a.name.value == "browser")
        .expect("browser");
    assert_eq!(browser.platforms.len(), 3);

    let win = browser
        .platforms
        .iter()
        .find(|p| p.platform.value == "windows")
        .unwrap();
    assert_eq!(
        win.paths[0].value,
        r"C:\Program Files\Contoso Browser\browser.exe"
    );
    assert_eq!(win.signers[0].value, "Contoso Ltd");

    let mac = browser
        .platforms
        .iter()
        .find(|p| p.platform.value == "macos")
        .unwrap();
    assert_eq!(mac.bundle_ids[0].value, "com.contoso.browser");
    assert_eq!(mac.team_ids[0].value, "ABCDE12345");

    let lin = browser
        .platforms
        .iter()
        .find(|p| p.platform.value == "linux")
        .unwrap();
    assert_eq!(lin.paths.len(), 2);
}

#[test]
fn all_three_list_syntaxes_are_accepted() {
    let (doc, diags) = parse_src(
        "version: 1\n\
         port_groups:\n\
         \x20 single: 443\n\
         \x20 flow: [80, 443]\n\
         \x20 block:\n\
         \x20   - 80\n\
         \x20   - 443\n",
    );
    assert!(!diags.has_errors());
    assert_eq!(doc.port_groups[0].entries.len(), 1);
    assert_eq!(doc.port_groups[1].entries.len(), 2);
    assert_eq!(doc.port_groups[2].entries.len(), 2);
}

#[test]
fn endpoint_and_application_shorthands_expand() {
    let (doc, diags) = parse_src(
        "version: 1\nrules:\n\
         \x20 - id: a\n    action: allow\n    destination: 10.0.0.0/8\n    application: browser\n\
         \x20 - id: b\n    action: allow\n    destination: [10.0.0.0/8, 8.8.8.8/32]\n    application: [x, y]\n",
    );
    assert!(!diags.has_errors(), "{:?}", diags.codes());
    assert_eq!(
        doc.rules[0].destination.as_ref().unwrap().addresses.len(),
        1
    );
    assert_eq!(doc.rules[0].application.as_ref().unwrap().names.len(), 1);
    assert_eq!(
        doc.rules[1].destination.as_ref().unwrap().addresses.len(),
        2
    );
    assert_eq!(doc.rules[1].application.as_ref().unwrap().names.len(), 2);
}

#[test]
fn recovery_keeps_parsing_after_every_class_of_error() {
    // Each of these has one broken rule followed by a good one. The good rule
    // must survive: an operator fixing a policy needs the whole error list,
    // and a parser that gives up loses the rest of the file.
    let cases: [(&str, &str); 5] = [
        (
            "unknown key",
            "rules:\n  - id: bad\n    destinaton: 1.2.3.4/32\n  - id: good\n    action: allow\n",
        ),
        (
            "duplicate key",
            "rules:\n  - id: bad\n    action: allow\n    action: deny\n  - id: good\n    action: allow\n",
        ),
        (
            "missing value",
            "rules:\n  - id: bad\n    action:\n  - id: good\n    action: allow\n",
        ),
        (
            "misindented line",
            "rules:\n  - id: bad\n    action: allow\n        stray: 1\n  - id: good\n    action: allow\n",
        ),
        (
            "bad list element",
            "rules:\n  - id: bad\n    tags: [a,,b]\n  - id: good\n    action: allow\n",
        ),
    ];

    for (label, src) in cases {
        let full = format!("version: 1\n{src}");
        let (doc, diags) = parse_src(&full);
        assert!(diags.has_errors(), "{label}: expected an error");
        assert!(
            doc.rules
                .iter()
                .any(|r| r.id.as_ref().map(|i| i.value == "good").unwrap_or(false)),
            "{label}: recovery lost the following rule"
        );
    }
}

#[test]
fn unknown_keys_suggest_the_intended_one() {
    let cases: [(&str, &str); 3] = [
        ("version: 1\nruels:\n  - id: a\n", "rules"),
        (
            "version: 1\nrules:\n  - id: a\n    destinaton: 1.2.3.4/32\n",
            "destination",
        ),
        (
            "version: 1\nrules:\n  - id: a\n    aplication: x\n",
            "application",
        ),
    ];
    for (src, expected) in cases {
        let (_, diags) = parse_src(src);
        let d = diags
            .iter()
            .find(|d| d.code == codes::UNKNOWN_KEY)
            .unwrap_or_else(|| panic!("no unknown-key diagnostic for {src:?}"));
        assert_eq!(
            d.help.as_deref(),
            Some(format!("did you mean `{expected}`?").as_str())
        );
    }
}

#[test]
fn parser_never_hangs_or_panics_on_adversarial_input() {
    let inputs = [
        String::from("rules:\n  -\n"),
        String::from("rules:\n  - \n  - \n  - \n"),
        String::from("a:\n b:\n  c:\n   d:\n    e:\n"),
        String::from("- - - - -\n"),
        String::from("rules:\n  - id:\n    action:\n    destination:\n"),
        String::from(":\n:\n:\n"),
        "  ".repeat(1000) + "a: 1\n",
        "rules:\n".to_string() + &"  - id: r\n    action: allow\n".repeat(500),
        "[".repeat(200) + &"]".repeat(200),
        "version: 1\n".repeat(200),
    ];
    for src in inputs {
        let (_, _) = parse_src(&src);
    }
}

#[test]
fn a_document_with_only_definitions_parses() {
    let (doc, diags) = parse_src(
        "version: 1\naddress_groups:\n  shared: [10.0.0.0/8]\nport_groups:\n  web: [443]\n",
    );
    assert!(!diags.has_errors());
    assert!(doc.rules.is_empty());
    assert_eq!(doc.address_groups.len(), 1);
}

#[test]
fn rule_spans_point_into_the_source() {
    let src = fixture();
    let (doc, _) = parse_src(&src);
    for rule in &doc.rules {
        assert!(rule.span.start < rule.span.end);
        assert!((rule.span.end as usize) <= src.len());
        assert!(rule.span.line >= 1);
    }
}

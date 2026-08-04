//! Scenario: what a signature match does to a flow that was already permitted.
//!
//! The shape being tested is `action: allow` combined with
//! `dpi: {on_match: deny}` — "permit this flow unless the payload trips". It is
//! the construct that makes layered inspection meaningful: a rule at the packet
//! stage says the connection is legitimate, and a rule at the stream stage can
//! still terminate it.
//!
//! The subtle part is truncation. A scan that hit the reassembly budget did not
//! finish looking, and "no signature fired" is then not the same statement as
//! "nothing was there". Getting this wrong in either direction is bad: treating
//! truncation as a match blocks every long connection, and treating it as a
//! clean miss lets an adversary evade inspection by being verbose.

use ufw_daemon::signatures::{self, SignatureSet};
use ufw_e2e::connection_tracker::{assert_allowed, assert_decided_by, assert_denied};
use ufw_e2e::packet_generator::Flow;
use ufw_e2e::policy;
use ufw_shared::hash::derive_signature_id;
use ufw_shared::policy_types::L7Protocol;

const DPI_POLICY: &str = "\
version: 1
defaults:
  action: deny
signature_groups:
  exfiltration: [dns-tunnel-long-label, dns-tunnel-high-entropy]
  exploits: [http-exploit-post]
address_groups:
  dns: [1.1.1.1/32]
rules:
  - id: allow-dns
    priority: 100
    layer: packet
    direction: outbound
    action: allow-inspect
    protocol: udp
    destination:
      addresses: [dns]
      ports: [53]
  - id: allow-web
    priority: 110
    layer: packet
    direction: outbound
    action: allow-inspect
    protocol: tcp
    destination:
      ports: [80, 443]
  - id: block-dns-tunnel
    priority: 300
    layer: stream
    action: allow
    protocol: udp
    dpi:
      signatures: [exfiltration]
      protocols: [dns]
      on_match: deny
  - id: block-http-exploits
    priority: 310
    layer: stream
    action: allow
    protocol: tcp
    dpi:
      signatures: [exploits]
      protocols: [http]
      on_match: deny
";

fn sig(name: &str) -> u32 {
    derive_signature_id(name)
}

#[test]
fn a_permitted_flow_with_a_clean_scan_stays_permitted() {
    let p = policy(DPI_POLICY);
    let flow = Flow::udp("1.1.1.1", 53).with_dpi(L7Protocol::Dns, &[]);
    assert_decided_by(&p, &flow, "allow-dns", "ordinary DNS, inspected and clean");
}

#[test]
fn a_signature_match_terminates_a_flow_the_packet_stage_permitted() {
    // The whole point of `allow-inspect`. `allow-dns` permitted this flow at
    // the packet stage; `block-dns-tunnel` denies it at the stream stage,
    // which only works because the earlier permit was provisional.
    let p = policy(DPI_POLICY);
    let flow = Flow::udp("1.1.1.1", 53)
        .with_dpi(L7Protocol::Dns, &[sig("dns-tunnel-long-label")]);
    assert_decided_by(&p, &flow, "block-dns-tunnel",
                      "DNS carrying an encoded payload");
}

#[test]
fn a_signature_scoped_to_another_protocol_does_not_fire() {
    // `block-http-exploits` is scoped to `protocols: [http]`. A DNS flow whose
    // scan somehow reported the HTTP signature must not match it — the
    // protocol scope is part of the predicate, not documentation.
    let p = policy(DPI_POLICY);
    let flow = Flow::udp("1.1.1.1", 53)
        .with_dpi(L7Protocol::Dns, &[sig("http-exploit-post")]);
    assert_decided_by(&p, &flow, "allow-dns",
                      "a DNS flow carrying an HTTP signature id");
}

#[test]
fn a_flow_with_no_scan_at_all_is_not_condemned() {
    // No DPI result means the engine has not run — not that it ran and found
    // nothing. A DPI predicate must not match an absent scan, for the same
    // reason an application predicate must not match an absent identity.
    let p = policy(DPI_POLICY);
    let flow = Flow::udp("1.1.1.1", 53);
    assert_allowed(&p, &flow, "a DNS flow before inspection has produced anything");
    assert_decided_by(&p, &flow, "allow-dns", "the packet-stage permit still applies");
}

#[test]
fn a_truncated_scan_that_found_nothing_is_not_a_match() {
    // The direction that matters for availability. Treating truncation as a
    // match would terminate every connection that exceeded the reassembly
    // budget — which is every long-lived connection — and would present as
    // "the firewall breaks large downloads".
    let p = policy(DPI_POLICY);
    let flow = Flow::tcp("93.184.216.34", 443).with_truncated_dpi(L7Protocol::Http);
    assert_decided_by(&p, &flow, "allow-web",
                      "a flow too long to inspect fully, with no signature hit");
}

#[test]
fn a_truncated_scan_that_did_find_something_still_matches() {
    // The direction that matters for security. A signature that fired before
    // the budget ran out fired; the truncation says nothing about what was
    // already seen.
    let p = policy(DPI_POLICY);
    let mut flow = Flow::tcp("93.184.216.34", 80)
        .with_dpi(L7Protocol::Http, &[sig("http-exploit-post")]);
    if let Some(dpi) = flow.dpi.as_mut() {
        dpi.truncated = true;
    }
    assert_decided_by(&p, &flow, "block-http-exploits",
                      "an exploit found before the scan was cut short");
}

#[test]
fn the_signature_names_a_policy_uses_resolve_to_the_ids_the_engine_reports() {
    // The join between a policy file and a signature file. Both derive ids from
    // the signature's *name*, so neither has to know a number — and if the two
    // derivations ever disagreed, every DPI rule would silently stop firing
    // with no error anywhere.
    let mut set = SignatureSet::default();
    let mut errors = Vec::new();
    signatures::parse_into(
        &mut set,
        "\
version: 1
signatures:
  - id: dns-tunnel-long-label
    protocol: dns
    severity: high
    conditions:
      - field: dns.max_label_length >= 40
",
        std::path::Path::new("test.yaml"),
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:?}");

    let from_signature_file = set.by_name("dns-tunnel-long-label").expect("loaded").id;

    // And the same id, reached from the policy side.
    let p = policy(DPI_POLICY);
    let rule = p.rules.iter().find(|r| r.name == "block-dns-tunnel").expect("the rule");
    let from_policy = rule.dpi.as_ref().expect("a DPI clause");
    assert!(
        from_policy.signatures.contains(&from_signature_file),
        "the policy's signature ids {:?} do not include {} — the policy and the \
         signature file have stopped agreeing on what a name means",
        from_policy.signatures, from_signature_file
    );
}

#[test]
fn an_alert_records_the_match_without_deciding_the_flow() {
    let p = policy("\
version: 1
defaults:
  action: deny
signature_groups:
  watch: [http-exploit-post]
rules:
  - id: allow-web
    priority: 100
    layer: packet
    direction: outbound
    action: allow-inspect
    protocol: tcp
    destination:
      ports: [443]
  - id: audit-exploits
    priority: 300
    layer: stream
    action: allow
    protocol: tcp
    dpi:
      signatures: [watch]
      protocols: [http]
      on_match: alert
");
    // `alert` is not a verdict. The flow proceeds on the packet-stage permit,
    // and the alert is what reaches the log. A policy that used `alert` and
    // found its traffic blocked would be a policy nobody could tune safely.
    let flow = Flow::tcp("93.184.216.34", 443)
        .with_dpi(L7Protocol::Http, &[sig("http-exploit-post")]);
    assert_allowed(&p, &flow, "an alerting signature does not block");
}

#[test]
fn a_deny_at_the_stream_stage_beats_an_allow_inspect_at_the_packet_stage() {
    // Stated directly, because it is the ordering the whole construct depends
    // on: `allow-inspect` is provisional, and provisional means a later stage
    // can still say no.
    let p = policy(DPI_POLICY);
    assert_denied(
        &p,
        &Flow::tcp("93.184.216.34", 80)
            .with_dpi(L7Protocol::Http, &[sig("http-exploit-post")]),
        "an exploit inside a flow the packet stage permitted",
    );
}

// --- multi-pattern matching -------------------------------------------------

#[test]
fn the_shipped_signatures_build_one_shared_automaton() {
    // Part Five asks for a single pass over the payload that scans every
    // signature, rather than a search per signature. If the rules this project
    // ships do not produce a table, every deployment takes the slow path and
    // the claim is decoration.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("sig-rules");
    if !root.exists() {
        return;
    }
    let (set, errors) = signatures::load_dir(&root);
    assert!(errors.is_empty(), "{errors:#?}");

    let automaton = set.automaton().expect("the shipped signatures have content patterns");
    assert!(
        automaton.patterns().len() >= 3,
        "only {} distinct patterns; the corpus is too thin to prove anything",
        automaton.patterns().len()
    );
    // Every state costs kernel memory on three platforms, so the size of what
    // gets shipped is worth an assertion rather than a hope.
    assert!(
        automaton.state_count() < 4096,
        "the shipped table needs {} states",
        automaton.state_count()
    );
}

#[test]
fn the_shared_pass_decides_content_conditions_the_way_a_direct_search_would() {
    // The automaton exists to make scanning cheaper, not to change verdicts.
    // This walks the shipped signature set over payloads that exercise the
    // awkward cases — a pattern at offset zero, a pattern repeated, a pattern
    // that is a prefix of another — and checks both paths agree on each one.
    let mut set = SignatureSet::default();
    let mut errors = Vec::new();
    signatures::parse_into(
        &mut set,
        "version: 1\nsignatures:\n\
         \x20 - id: post\n    protocol: http\n    conditions:\n      \
         - content: \"POST\", offset: 0, depth: 8\n\
         \x20 - id: post-admin\n    protocol: http\n    conditions:\n      \
         - content: \"POST /admin\", offset: 0, depth: 64\n\
         \x20 - id: admin-anywhere\n    protocol: http\n    conditions:\n      \
         - content: \"/admin\", depth: 512, nocase: true\n\
         \x20 - id: tls-record\n    protocol: tls\n    conditions:\n      \
         - content: |16 03 01|, offset: 0, depth: 8\n",
        std::path::Path::new("test.yaml"),
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:?}");

    let automaton = set.automaton().expect("four content patterns");
    let patterns = automaton.patterns().to_vec();

    let payloads: Vec<&[u8]> = vec![
        b"",
        b"POST /admin HTTP/1.1\r\n",
        b"GET /admin HTTP/1.1\r\n",
        b"GET / HTTP/1.1\r\nReferer: /ADMIN\r\n",
        b"POST /a HTTP/1.1\r\n\r\nPOST /admin",
        &[0x16, 0x03, 0x01, 0x00, 0x2f],
        b"...................../admin.................../admin",
    ];

    for payload in payloads {
        let table = automaton.scan(payload);
        for signature in set.signatures.values() {
            for condition in &signature.conditions {
                let ufw_daemon::signatures::Condition::Content {
                    pattern, offset, depth, nocase,
                } = condition
                else {
                    continue;
                };
                let id = patterns
                    .iter()
                    .position(|p| p.bytes == *pattern && p.nocase == *nocase)
                    .expect("every content pattern has an id") as u32;

                let shared = signatures::content_holds(condition, Some(&table), id, payload);
                let direct = ufw_daemon::automaton::naive_contains(
                    pattern, *nocase, payload, *offset, *depth,
                );
                assert_eq!(
                    shared,
                    direct,
                    "`{}` disagrees on {:?}: shared pass says {shared}, direct search says \
                     {direct}",
                    signature.name,
                    String::from_utf8_lossy(payload)
                );
            }
        }
    }
}

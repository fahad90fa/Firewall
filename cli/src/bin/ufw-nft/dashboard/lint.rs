//! Policy-correctness linter — static checks over the *loaded* ruleset.
//!
//! Every finding is sound and conservative: it flags a rule only when an
//! earlier rule in the same chain provably decides the same traffic first, or
//! when a rule has seen no traffic in a chain that otherwise has. It never
//! claims a rule is "dead" from a window with no traffic at all, and it never
//! guesses at subset relationships it cannot prove from the match text — same
//! philosophy as the attack classifier: only findings a person can act on.

use super::ruleset::{ChainView, RuleView};

pub struct Finding {
    /// "warn" (a real problem) | "info" (worth a look).
    pub severity: String,
    pub chain: String,
    pub rule: String,
    /// "shadowed" | "duplicate" | "unreachable" | "no-hits".
    pub kind: String,
    pub detail: String,
}

/// A terminal verdict decides the packet's fate; a non-terminal one (log/alert
/// via `continue`) lets it fall through to later rules.
fn is_terminal(verdict: &str) -> bool {
    matches!(verdict, "accept" | "drop" | "reject")
}

/// Normalize a match expression for equality: lower-case, whitespace-collapsed.
fn norm(matchers: &str) -> String {
    matchers
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// A rule that matches every packet (no match expression) is a catch-all.
fn is_catchall(m: &str) -> bool {
    m.is_empty() || m == "every packet"
}

pub fn analyze(chains: &[ChainView]) -> Vec<Finding> {
    let mut out = Vec::new();
    for c in chains {
        let chain_has_traffic = c.rules.iter().any(|r| r.packets > 0);
        // Matchers of earlier rules, split by whether they terminate the packet.
        let mut terminal_seen: Vec<String> = Vec::new();
        let mut nonterminal_seen: Vec<(String, String)> = Vec::new(); // (matcher, verdict)
        let mut catchall_terminated = false;

        for r in &c.rules {
            let m = norm(&r.matchers);

            if catchall_terminated {
                out.push(finding(
                    "warn", c, r, "unreachable",
                    "an earlier rule matches every packet with a terminal verdict, so this rule can never run.",
                ));
            } else if terminal_seen.contains(&m) {
                out.push(finding(
                    "warn", c, r, "shadowed",
                    "an earlier rule with the same match already decides this traffic, so this rule can never run.",
                ));
            } else if nonterminal_seen
                .iter()
                .any(|(sm, sv)| *sm == m && *sv == r.verdict)
            {
                out.push(finding(
                    "info", c, r, "duplicate",
                    "an earlier rule in this chain has the same match and verdict — this one is redundant.",
                ));
            }

            // Track this rule for the ones that follow.
            if is_terminal(&r.verdict) {
                terminal_seen.push(m.clone());
                if is_catchall(&m) {
                    catchall_terminated = true;
                }
            } else {
                nonterminal_seen.push((m.clone(), r.verdict.clone()));
            }

            // A rule that never fires, in a chain that has otherwise seen
            // traffic, is a candidate for removal — but only a candidate, since
            // the window is finite. Skip rules already flagged unreachable.
            if chain_has_traffic
                && r.packets == 0
                && is_terminal(&r.verdict)
                && !catchall_terminated
                && !terminal_seen[..terminal_seen.len().saturating_sub(1)].contains(&m)
            {
                out.push(finding(
                    "info", c, r, "no-hits",
                    "no packets have matched this rule in the observed window — review whether it is still needed.",
                ));
            }
        }
    }
    out
}

fn finding(sev: &str, c: &ChainView, r: &RuleView, kind: &str, detail: &str) -> Finding {
    Finding {
        severity: sev.into(),
        chain: c.name.clone(),
        rule: if r.name.is_empty() {
            "(unnamed)".into()
        } else {
            r.name.clone()
        },
        kind: kind.into(),
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(name: &str, matchers: &str, verdict: &str, packets: u64) -> RuleView {
        RuleView {
            name: name.into(),
            matchers: matchers.into(),
            verdict: verdict.into(),
            log_kind: None,
            packets,
            bytes: 0,
            dports: vec![],
            rate_limit: None,
        }
    }
    fn chain(rules: Vec<RuleView>) -> Vec<ChainView> {
        vec![ChainView {
            name: "input".into(),
            policy: "drop".into(),
            rules,
        }]
    }

    #[test]
    fn identical_match_after_terminal_is_shadowed() {
        let f = analyze(&chain(vec![
            rule("a", "tcp dport { 22 }", "drop", 5),
            rule("b", "tcp dport { 22 }", "accept", 0),
        ]));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "shadowed");
        assert_eq!(f[0].rule, "b");
    }

    #[test]
    fn everything_after_a_terminal_catchall_is_unreachable() {
        let f = analyze(&chain(vec![
            rule("catch", "", "drop", 3),
            rule("late", "tcp dport { 80 }", "accept", 0),
        ]));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "unreachable");
        assert_eq!(f[0].rule, "late");
    }

    #[test]
    fn a_nonterminal_log_rule_does_not_shadow() {
        // An alert/continue rule with the same match lets the packet fall
        // through — the later accept still runs, so no "shadowed".
        let f = analyze(&chain(vec![
            rule("log", "tcp dport { 22 }", "continue", 4),
            rule("acc", "tcp dport { 22 }", "accept", 4),
        ]));
        assert!(f
            .iter()
            .all(|x| x.kind != "shadowed" && x.kind != "unreachable"));
    }

    #[test]
    fn duplicate_nonterminal_is_info() {
        let f = analyze(&chain(vec![
            rule("l1", "tcp dport { 22 }", "continue", 1),
            rule("l2", "tcp dport { 22 }", "continue", 1),
        ]));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "duplicate");
    }

    #[test]
    fn zero_hits_only_when_chain_has_traffic() {
        // Quiet chain: nothing has any hits -> no "no-hits" noise.
        let quiet = analyze(&chain(vec![
            rule("a", "tcp dport { 22 }", "drop", 0),
            rule("b", "tcp dport { 80 }", "accept", 0),
        ]));
        assert!(quiet.is_empty());
        // Busy chain: the idle terminal rule is flagged.
        let busy = analyze(&chain(vec![
            rule("a", "tcp dport { 22 }", "drop", 9),
            rule("b", "tcp dport { 80 }", "accept", 0),
        ]));
        assert_eq!(busy.iter().filter(|x| x.kind == "no-hits").count(), 1);
    }

    #[test]
    fn a_clean_ruleset_has_no_findings() {
        let f = analyze(&chain(vec![
            rule("a", "tcp dport { 22 }", "drop", 3),
            rule("b", "tcp dport { 80 }", "accept", 7),
        ]));
        assert!(f.is_empty());
    }
}

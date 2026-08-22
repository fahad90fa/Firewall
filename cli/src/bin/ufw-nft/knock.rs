//! Port knocking / single-packet authorization.
//!
//! A protected port (SSH, a management panel) stays invisible to scanners: it
//! is dropped for everyone until a source sends the correct sequence of TCP
//! SYNs to a set of "knock" ports, in order, within a short window. That source
//! is then admitted for a while, tracked entirely by native nftables timeout
//! sets — no daemon, no state file.
//!
//! Correctness note, stated plainly: across nftables base chains a later `drop`
//! beats an earlier `accept`, so this standalone table gates the port by
//! *dropping unauthorized traffic before* the policy table (it hooks at a lower
//! priority). That is the effective control when the main policy does not itself
//! drop the protected port — i.e. use it with a default-allow policy, or simply
//! leave the protected port out of your policy and let the knock table own it.
//! With a default-deny policy that also drops the port, add an allow rule for it
//! so the knock table remains the gate. `check` runs the generated ruleset
//! through `nft -c` before anything is loaded.

/// How long a partial sequence (and a completed authorization) live.
const STAGE_WINDOW_SECS: u64 = 10;

/// Validate the knock configuration. At least two knock ports, all distinct,
/// none equal to the protected port, none zero.
pub fn validate(protected: u16, knocks: &[u16]) -> Result<(), String> {
    if knocks.len() < 2 {
        return Err("a knock sequence needs at least two ports".into());
    }
    if knocks.len() > 6 {
        return Err("a knock sequence of more than six ports is refused".into());
    }
    if protected == 0 || knocks.contains(&0) {
        return Err("port 0 is not valid".into());
    }
    for (i, &p) in knocks.iter().enumerate() {
        if p == protected {
            return Err(format!(
                "knock port {p} must differ from the protected port"
            ));
        }
        if knocks[..i].contains(&p) {
            return Err(format!(
                "knock port {p} is repeated — the sequence must be distinct"
            ));
        }
    }
    Ok(())
}

/// The nftables program that installs the knock table for `protected` guarded by
/// the ordered `knocks`, admitting a source for `ttl_secs`.
pub fn program(protected: u16, knocks: &[u16], ttl_secs: u64) -> String {
    let n = knocks.len();
    let stages = n - 1; // stage1..stage(n-1); the last knock admits to `allowed`
    let mut p = String::new();
    p.push_str("add table inet ufw_knock\n");
    p.push_str("add set inet ufw_knock allowed { type ipv4_addr; flags timeout; }\n");
    for s in 1..=stages {
        p.push_str(&format!(
            "add set inet ufw_knock stage{s} {{ type ipv4_addr; flags timeout; }}\n"
        ));
    }
    p.push_str(
        "add chain inet ufw_knock input { type filter hook input priority -25; policy accept; }\n",
    );
    p.push_str("flush chain inet ufw_knock input\n");

    // Authorized sources reach the port.
    p.push_str(&format!(
        "add rule inet ufw_knock input tcp dport {protected} ip saddr @allowed counter accept\n"
    ));

    // Knock rules, final knock first. Each advances the source one stage; the
    // knock packet itself is always dropped (those ports offer nothing).
    for i in (0..n).rev() {
        let port = knocks[i];
        if i == 0 {
            // First knock: unconditionally enter stage1.
            p.push_str(&format!(
                "add rule inet ufw_knock input tcp dport {port} add @stage1 {{ ip saddr timeout {STAGE_WINDOW_SECS}s }} counter drop\n"
            ));
        } else if i == n - 1 {
            // Final knock: from the last stage, admit to `allowed`.
            p.push_str(&format!(
                "add rule inet ufw_knock input tcp dport {port} ip saddr @stage{stages} add @allowed {{ ip saddr timeout {ttl_secs}s }} counter drop\n"
            ));
        } else {
            // Middle knock: from stage i, advance to stage i+1.
            p.push_str(&format!(
                "add rule inet ufw_knock input tcp dport {port} ip saddr @stage{i} add @stage{next} {{ ip saddr timeout {STAGE_WINDOW_SECS}s }} counter drop\n",
                next = i + 1
            ));
        }
    }

    // Everyone else who reaches for the protected port is blocked.
    p.push_str(&format!(
        "add rule inet ufw_knock input tcp dport {protected} counter drop\n"
    ));
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_rules() {
        assert!(validate(22, &[7000, 8000, 9000]).is_ok());
        assert!(validate(22, &[7000]).is_err()); // too few
        assert!(validate(22, &[22, 8000]).is_err()); // collides with protected
        assert!(validate(22, &[7000, 7000]).is_err()); // repeated
        assert!(validate(0, &[7000, 8000]).is_err()); // port 0
    }

    #[test]
    fn program_has_expected_shape() {
        let p = program(22, &[7000, 8000, 9000], 3600);
        // Two intermediate stages for a 3-knock sequence.
        assert!(p.contains("add set inet ufw_knock stage1"));
        assert!(p.contains("add set inet ufw_knock stage2"));
        assert!(!p.contains("stage3"));
        // Authorized-accept and default-drop for the protected port.
        assert!(p.contains("tcp dport 22 ip saddr @allowed counter accept"));
        assert!(p.contains("tcp dport 22 counter drop"));
        // First knock enters stage1 unconditionally; final knock admits.
        assert!(p.contains("tcp dport 7000 add @stage1"));
        assert!(p.contains("tcp dport 9000 ip saddr @stage2 add @allowed"));
        // Middle knock advances stage1 -> stage2.
        assert!(p.contains("tcp dport 8000 ip saddr @stage1 add @stage2"));
        // The admit timeout is the requested ttl.
        assert!(p.contains("timeout 3600s"));
    }

    #[test]
    fn two_knock_sequence_uses_one_stage() {
        let p = program(2222, &[1234, 5678], 600);
        assert!(p.contains("stage1"));
        assert!(!p.contains("stage2"));
        assert!(p.contains("tcp dport 1234 add @stage1"));
        assert!(p.contains("tcp dport 5678 ip saddr @stage1 add @allowed"));
    }
}

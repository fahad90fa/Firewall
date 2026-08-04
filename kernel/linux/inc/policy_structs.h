/*
 * Unified Firewall — the rule table as the kernel sees it.
 *
 * This header is the C half of the contract that `shared/src/policy_types.rs`
 * defines in Rust. The compiler's Linux backend emits `ufw_rules.h` against
 * these declarations, and the daemon ships the same structures over netlink,
 * so any disagreement here is a disagreement about what a policy means.
 *
 * Two rules govern edits:
 *
 *   1. Discriminants are ABI. UFW_ACTION_DENY is 1 in this file, in the Rust
 *      enum, in the generated header and in whatever is already installed in
 *      a running kernel. Values are never reused, and new ones are appended.
 *   2. Every structure is fixed-size and self-contained. There are no
 *      pointers into a rule, because a rule is memcpy'd out of a netlink
 *      message into an RCU-published table and must not reference the
 *      message's lifetime.
 *
 * The size cost of (2) is real: a rule is a little over 1 KiB, so the
 * 65536-rule ceiling is ~70 MiB. That is deliberate. The alternative is
 * variable-length rules with offsets, which turns every field access into
 * arithmetic on attacker-influenced values in a context where a mistake is a
 * kernel memory disclosure.
 */

#ifndef UFW_POLICY_STRUCTS_H
#define UFW_POLICY_STRUCTS_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#endif

/* Bumped whenever anything in this file changes meaning. The daemon refuses
 * to install into a module that reports a different revision, because a
 * mismatched rule table is worse than no rule table: it filters, but not
 * what the operator wrote. */
#define UFW_ABI_REVISION 2

/* --- limits ------------------------------------------------------------ */

#define UFW_MAX_RULES              65536
#define UFW_MAX_RULE_NAME          64
#define UFW_MAX_CIDRS_PER_RULE     16
#define UFW_MAX_PORT_RANGES        8
#define UFW_MAX_FINGERPRINTS       4
#define UFW_MAX_PATHS_PER_FP       4
#define UFW_MAX_PATH_LEN           256
#define UFW_MAX_SIGNERS_PER_FP     2
#define UFW_MAX_SIGNER_LEN         128
#define UFW_MAX_HASHES_PER_FP      2
#define UFW_MAX_SIGNATURES_PER_RULE 16
#define UFW_MAX_L7_PER_RULE        4
#define UFW_MAX_INTERFACES         4
#define UFW_MAX_IFNAME             16

/* --- verdicts and actions ---------------------------------------------- */

/*
 * The five actions, matching ufw_shared::policy_types::Action exactly.
 *
 * UFW_ACTION_ALLOW_INSPECT is the one that needs explaining: it is a
 * provisional permit. The packet proceeds, but evaluation does not stop, so a
 * later stage can still deny. It is how "allow this flow, but kill it if the
 * payload trips a signature" is expressed, and it is what the compiler
 * silently lowers a perimeter-crossing ALLOW into.
 */
enum ufw_action {
	UFW_ACTION_ALLOW         = 0,
	UFW_ACTION_DENY          = 1,
	UFW_ACTION_ALERT         = 2,
	UFW_ACTION_CONTINUE      = 3,
	UFW_ACTION_ALLOW_INSPECT = 4,
};

/* What the hook returns to the stack. Distinct from ufw_action because
 * ALERT and CONTINUE are not verdicts — they are annotations that leave the
 * decision to a later rule. */
enum ufw_verdict {
	UFW_VERDICT_PASS = 0,
	UFW_VERDICT_DROP = 1,
	/* Send a reset or an ICMP unreachable rather than dropping silently.
	 * Used only for locally originated flows: telling a remote scanner
	 * that a port is closed is information it did not have. */
	UFW_VERDICT_REJECT = 2,
};

/*
 * Evaluation stages, in the order they run.
 *
 * Note that this is not the numeric order of the defense layers. Identity is
 * stage 2 and DPI is stage 3, because the process behind a socket is known
 * before its payload has been seen: an identity rule that would deny the flow
 * should not first pay for reassembly and a signature scan.
 */
enum ufw_stage {
	UFW_STAGE_PERIMETER = 0,
	UFW_STAGE_PACKET    = 1,
	UFW_STAGE_IDENTITY  = 2,
	UFW_STAGE_APP_DPI   = 3,
	UFW_STAGE_STREAM    = 4,
	UFW_STAGE__COUNT    = 5,
};

enum ufw_direction {
	UFW_DIR_ANY      = 0,
	UFW_DIR_INBOUND  = 1,
	UFW_DIR_OUTBOUND = 2,
};

/* IANA protocol numbers are used directly; this is the wildcard. 255 is
 * "reserved" in the IANA registry and so can never collide with a real one. */
#define UFW_PROTO_ANY 255

enum ufw_zone {
	UFW_ZONE_LOCAL     = 0,
	UFW_ZONE_INTERNAL  = 1,
	UFW_ZONE_PERIMETER = 2,
	UFW_ZONE_EXTERNAL  = 3,
	UFW_ZONE_ANY       = 4,
};

/* Matching ufw_shared::identity_types::TrustLevel. Ordered, and compared
 * with >= for `trust: [">= known"]` style bounds. */
enum ufw_trust {
	UFW_TRUST_UNTRUSTED = 0,
	UFW_TRUST_UNKNOWN   = 1,
	UFW_TRUST_KNOWN     = 2,
	UFW_TRUST_TRUSTED   = 3,
	UFW_TRUST_SYSTEM    = 4,
};

enum ufw_l7 {
	UFW_L7_UNKNOWN = 0,
	UFW_L7_HTTP    = 1,
	UFW_L7_TLS     = 2,
	UFW_L7_DNS     = 3,
	UFW_L7_SSH     = 4,
	UFW_L7_SMTP    = 5,
	UFW_L7_QUIC    = 6,
};

/* --- rule flags -------------------------------------------------------- */

#define UFW_FLAG_LOG             (1u << 0)
#define UFW_FLAG_STATEFUL        (1u << 1)
/* The rule's verdict needs the owning process, so the classifier must
 * resolve identity before it can be evaluated. Resolution can block, which
 * is why this is a flag rather than something inferred from the app match:
 * the fast path checks it and bails out early. */
#define UFW_FLAG_NEEDS_IDENTITY  (1u << 2)
#define UFW_FLAG_NEEDS_DPI       (1u << 3)
/* Expressible with L3/L4 header fields alone, so the tc program may decide
 * it without entering the module. */
#define UFW_FLAG_EBPF_ELIGIBLE   (1u << 4)
#define UFW_FLAG_NEGATE_SRC      (1u << 5)
#define UFW_FLAG_NEGATE_DST      (1u << 6)
#define UFW_FLAG_NEGATE_APP      (1u << 7)
#define UFW_FLAG_HAS_SCHEDULE    (1u << 8)
#define UFW_FLAG_REQUIRE_VALID_SIG (1u << 9)

/* --- predicates -------------------------------------------------------- */

struct ufw_cidr {
	/* Big-endian, IPv4 in the first four bytes with the rest zeroed. The
	 * `is_v6` flag rather than a separate family field keeps the struct
	 * one byte smaller and the comparison branch-free. */
	__u8  addr[16];
	__u8  prefix_len;
	__u8  is_v6;
	__u8  _pad[2];
};

struct ufw_port_range {
	__u16 lo;
	__u16 hi;
};

struct ufw_addr_match {
	struct ufw_cidr cidrs[UFW_MAX_CIDRS_PER_RULE];
	__u8  cidr_count;
	/* Bitmask over enum ufw_zone. Empty means "any zone". */
	__u8  zone_mask;
	__u8  negate;
	__u8  _pad;
};

struct ufw_port_match {
	struct ufw_port_range ranges[UFW_MAX_PORT_RANGES];
	__u8  range_count;
	__u8  negate;
	__u8  _pad[2];
};

/*
 * One platform's way of naming a binary.
 *
 * A fingerprint is a conjunction: if it carries both a path set and a signer,
 * the binary must satisfy both. Fingerprints within a rule are a
 * *disjunction*, which is what lets one logical application be a Windows
 * signer, a Linux path and a macOS Team ID at the same time without the Linux
 * binary being required to carry an Authenticode signature.
 */
struct ufw_fingerprint {
	char  paths[UFW_MAX_PATHS_PER_FP][UFW_MAX_PATH_LEN];
	__u8  path_count;
	/* Paths are compared case-insensitively when this is set, which is
	 * decided by the platform the fingerprint was written for, not by the
	 * platform evaluating it. A Windows path stays case-insensitive even
	 * when a Linux module is the one reading the rule. */
	__u8  case_insensitive;
	__u8  hash_count;
	__u8  signer_count;
	__u8  hashes[UFW_MAX_HASHES_PER_FP][32];
	char  signers[UFW_MAX_SIGNERS_PER_FP][UFW_MAX_SIGNER_LEN];
};

struct ufw_app_match {
	struct ufw_fingerprint fingerprints[UFW_MAX_FINGERPRINTS];
	__u8  fingerprint_count;
	/* Bitmask over enum ufw_trust. Empty means any trust level. */
	__u8  trust_mask;
	__u8  negate;
	__u8  require_valid_signature;
};

struct ufw_dpi_match {
	__u32 signature_ids[UFW_MAX_SIGNATURES_PER_RULE];
	__u8  signature_count;
	__u8  l7[UFW_MAX_L7_PER_RULE];
	__u8  l7_count;
	/* The verdict when the predicate holds. Separate from the rule's own
	 * action so `action: allow` + `on_match: deny` expresses "permit
	 * unless the payload trips". */
	__u8  on_match;
	__u8  _pad;
};

/*
 * A recurring window, in minutes from Monday 00:00 local time.
 *
 * Local time, not UTC, and that is a deliberate and slightly uncomfortable
 * choice: "business hours" is a statement about the operator's clock, and
 * expressing it in UTC would silently shift it twice a year. The cost is that
 * a daylight-saving transition moves the window, so the daemon pushes the
 * current offset on every reload rather than the module computing it.
 */
struct ufw_schedule {
	__u16 start_minute;
	__u16 end_minute;
	/* Bit 0 = Monday. */
	__u8  day_mask;
	__u8  _pad[3];
};

/* --- the rule ---------------------------------------------------------- */

struct ufw_rule {
	__u32 id;
	char  name[UFW_MAX_RULE_NAME];
	__u8  stage;
	__u8  action;
	__u8  direction;
	__u8  protocol;
	__u32 priority;
	__u32 flags;

	struct ufw_addr_match  src;
	struct ufw_addr_match  dst;
	struct ufw_port_match  src_ports;
	struct ufw_port_match  dst_ports;
	struct ufw_app_match   app;
	struct ufw_dpi_match   dpi;
	struct ufw_schedule    schedule;

	char  interfaces[UFW_MAX_INTERFACES][UFW_MAX_IFNAME];
	__u8  interface_count;
	__u8  _pad[7];
};

/*
 * The installed table.
 *
 * Published under RCU. Readers take rcu_read_lock() and dereference `rules`;
 * a reload builds a whole new table and swaps the pointer, so a packet in
 * flight always sees one complete consistent policy rather than a half-
 * applied one. That is why this is a whole-table swap and not an in-place
 * edit, even for a one-rule change: an in-place edit has a window in which
 * the table is neither the old policy nor the new one.
 *
 * `stage_start` indexes the first rule of each stage. The table is sorted by
 * (stage, priority, id), so evaluating a stage is a bounded scan rather than
 * a filtered walk of the whole table.
 */
struct ufw_policy_table {
	__u64 revision;
	__u8  ruleset_hash[32];
	__u32 rule_count;
	__u8  default_verdict;
	__u8  abi_revision;
	__u8  _pad[2];
	__u32 stage_start[UFW_STAGE__COUNT + 1];
	struct ufw_rule rules[];
};

/* --- flow facts -------------------------------------------------------- */

/*
 * Everything the classifier knows about one packet or flow.
 *
 * Assembled once per decision and passed down by pointer. `identity_valid`
 * and `dpi_valid` are separate from the payloads because absent facts must
 * never read as wildcards: an unresolved identity does not match an app
 * predicate, not even a negated one. Fail-closed asymmetry is the property
 * that keeps "deny everything not signed by us" from being satisfied by a
 * process the resolver could not inspect.
 */
struct ufw_flow_facts {
	__u8  is_v6;
	__u8  protocol;
	__u8  direction;
	__u8  src_zone;
	__u8  dst_zone;
	__u8  identity_valid;
	__u8  dpi_valid;
	__u8  l7;

	__u8  src_addr[16];
	__u8  dst_addr[16];
	__u16 src_port;
	__u16 dst_port;

	/* Identity, valid only when identity_valid is set. */
	__u32 pid;
	__u64 start_time_us;
	__u8  trust;
	__u8  signature_valid;
	__u8  path_len;
	__u8  signer_len;
	char  path[UFW_MAX_PATH_LEN];
	char  signer[UFW_MAX_SIGNER_LEN];
	__u8  sha256[32];

	/* DPI results, valid only when dpi_valid is set. */
	__u32 matched_signatures[UFW_MAX_SIGNATURES_PER_RULE];
	__u8  matched_count;
	/* The scan hit the reassembly budget, so a miss is not evidence of
	 * absence. Rules that deny on a signature treat a truncated scan as a
	 * non-match and say so in the log; rules that alert on one report the
	 * truncation, because "we did not finish looking" is the finding. */
	__u8  dpi_truncated;

	char  ifname[UFW_MAX_IFNAME];
	__u16 minute_of_week;
	__u8  minute_valid;
	__u8  _pad;
};

/* The outcome of evaluating a table against one flow. */
struct ufw_decision {
	__u8  verdict;
	__u8  stage;
	__u8  logged;
	__u8  _pad;
	__u32 rule_id;
	/* Points into the published table, which the caller holds an RCU read
	 * lock over for the lifetime of this structure. */
	const char *rule_name;
};

/* Synthetic rule ids for decisions no rule produced. Chosen at the top of
 * the space so they cannot collide with a hash-derived id. */
#define UFW_RULE_ID_DEFAULT     0xFFFFFFFFu
#define UFW_RULE_ID_NO_POLICY   0xFFFFFFFEu
#define UFW_RULE_ID_FAIL_CLOSED 0xFFFFFFFDu

#endif /* UFW_POLICY_STRUCTS_H */

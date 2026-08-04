/*
 * Unified Firewall — eBPF fast path, shared declarations.
 *
 * # What the fast path may and may not do
 *
 * It may decide a packet early. It may never decide a packet *differently*
 * from the full table.
 *
 * That is guaranteed structurally rather than by testing: the compiler gives
 * this program the longest **prefix** of the rule table that is inbound-
 * relevant and expressible in L3/L4 fields. Because it is a prefix, a match
 * here is provably the match the full table would have found — every rule
 * that could have matched earlier is also in this program. Give it an
 * arbitrary subset instead and that stops being true, because a rule the
 * program does not carry might have matched first.
 *
 * Anything not decided here falls through to the netfilter hook, which
 * evaluates everything. The fast path is an accelerator and cannot change an
 * outcome.
 *
 * # Why inbound only
 *
 * tc ingress runs before netfilter; tc egress runs after it. So on the
 * outbound path the netfilter hook has already decided by the time a tc
 * program would see the packet, and a second decision there could only
 * contradict the first. Attaching to ingress alone removes the possibility.
 *
 * # Verifier constraints that shaped this code
 *
 * No unbounded loops, no function pointers, no dynamic indices without an
 * explicit bound check the verifier can see. The rule scan is therefore an
 * unrolled bounded loop with a compile-time maximum, and every array index is
 * masked. Code that looks needlessly defensive here usually is not: it is the
 * shape the verifier accepts.
 */

#ifndef UFW_EBPF_COMMON_H
#define UFW_EBPF_COMMON_H

#include <linux/types.h>

/* Verdicts, matching enum ufw_verdict in policy_structs.h. The eBPF program
 * only ever produces PASS or DROP; REJECT needs to generate a packet, which
 * is not something a tc classifier should be doing. */
#define UFW_VERDICT_PASS 0
#define UFW_VERDICT_DROP 1

#define UFW_DIR_ANY      0
#define UFW_DIR_INBOUND  1
#define UFW_DIR_OUTBOUND 2

#define UFW_PROTO_ANY 255

#define UFW_EBPF_FLAG_LOG (1u << 0)

/*
 * Bounds, chosen against the verifier's instruction budget rather than
 * against what a policy might want.
 *
 * A rule scan is rules × (cidrs + ports) comparisons, all unrolled. At 64
 * rules with 8 CIDRs and 4 port ranges each that is a few thousand
 * instructions, comfortably inside the limit with room for the parsing
 * preamble. Raising these is not free: the program either stops verifying or
 * starts costing more than the netfilter path it is meant to avoid.
 *
 * A policy with more eBPF-eligible rules than this is not broken — the
 * compiler simply stops the prefix at UFW_EBPF_MAX_RULES, and the rest is
 * decided by the module.
 */
#define UFW_EBPF_MAX_RULES 64

/*
 * LPM trie keys, for the XDP deny sets in xdp_filter.c.
 *
 * `prefixlen` first and in host byte order is the kernel's requirement, not a
 * choice: BPF_MAP_TYPE_LPM_TRIE reads it from the front of the key. The
 * address that follows stays in network order, because that is how it arrives
 * and byte-swapping on the fast path to compare against a table the daemon
 * could have stored either way is work for nothing.
 */
/*
 * What the LSM hook recorded about the process that opened a socket.
 *
 * Deliberately does not carry a path. A path is variable-length and would make
 * this structure large enough to matter at 65536 entries, and it is also the
 * thing that can be changed underneath — the inode cannot. The daemon resolves
 * (device, inode, generation) to a path and a signature when it needs to, and
 * a replaced binary gets a new inode, which is exactly the change an identity
 * rule must notice.
 */
struct ufw_lsm_identity {
	__u64 inode;
	__u64 cgroup_id;
	__u64 captured_ns;
	__u32 device;
	__u32 inode_generation;
	__u32 pid;
	__u32 uid;
	char  comm[16];
};

struct ufw_lpm_key_v4 {
	__u32 prefixlen;
	__u32 addr;
};

struct ufw_lpm_key_v6 {
	__u32 prefixlen;
	__u8  addr[16];
};
#define UFW_EBPF_MAX_CIDRS 8
#define UFW_EBPF_MAX_PORTS 4

struct ufw_ebpf_cidr {
	__u32 addr;		/* IPv4 only; see the note in packet_filter.c */
	__u8  prefix_len;
	__u8  _pad[3];
};

struct ufw_ebpf_port_range {
	__u16 lo;
	__u16 hi;
};

struct ufw_ebpf_rule {
	__u32 rule_id;
	char  name[32];
	__u8  action;
	__u8  direction;
	__u8  protocol;
	__u8  flags;
	struct ufw_ebpf_cidr src_cidrs[UFW_EBPF_MAX_CIDRS];
	__u8  src_n;
	struct ufw_ebpf_cidr dst_cidrs[UFW_EBPF_MAX_CIDRS];
	__u8  dst_n;
	struct ufw_ebpf_port_range src_ports[UFW_EBPF_MAX_PORTS];
	__u8  src_port_n;
	struct ufw_ebpf_port_range dst_ports[UFW_EBPF_MAX_PORTS];
	__u8  dst_port_n;
};

/* Map keys. */

struct ufw_flow_key {
	__u32 src_addr;
	__u32 dst_addr;
	__u16 src_port;
	__u16 dst_port;
	__u8  protocol;
	__u8  _pad[3];
};

struct ufw_flow_state {
	__u64 first_seen_ns;
	__u64 last_seen_ns;
	__u64 packets;
	__u64 bytes;
	__u32 rule_id;
	__u8  verdict;
	__u8  _pad[3];
};

struct ufw_ebpf_counters {
	__u64 packets_seen;
	__u64 packets_passed;
	__u64 packets_dropped;
	__u64 fell_through;
	__u64 parse_failed;
};

/* Map names, referenced by the loader in build/linux/. */
#define UFW_MAP_FLOWS    "ufw_flows"
#define UFW_MAP_COUNTERS "ufw_counters"
#define UFW_MAP_CONFIG   "ufw_config"

/* Config map indices. */
#define UFW_CONFIG_ENABLED  0
#define UFW_CONFIG_REVISION 1

#endif /* UFW_EBPF_COMMON_H */

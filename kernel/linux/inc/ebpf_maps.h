/*
 * Unified Firewall — the eBPF maps, as the userspace loader sees them.
 *
 * The kernel module and the eBPF programs do not share memory and do not talk
 * to each other. They are two independent enforcement points that happen to
 * be compiled from the same policy, and the loader in build/linux/ is what
 * connects them to the daemon.
 *
 * That separation is deliberate. A shared map between a tc program and a
 * netfilter module would be a synchronisation problem in softirq context on
 * two different code paths, for the benefit of an optimisation. Instead each
 * side gets its own copy of the rules it needs, both derived from the same
 * compile, and the fast path is constrained to a prefix so the two cannot
 * disagree. See ebpf/common.h for the prefix argument.
 *
 * This header exists so the loader and any diagnostic tooling agree on map
 * names, key types and value types without including the BPF-side headers,
 * which need a bpf target to compile.
 */

#ifndef UFW_EBPF_MAPS_H
#define UFW_EBPF_MAPS_H

#include <linux/types.h>

/* Pin paths. Under /sys/fs/bpf so the maps outlive the loader process: an
 * operator restarting the daemon should not flush the flow table and
 * re-decide every established connection. */
#define UFW_BPF_PIN_DIR      "/sys/fs/bpf/ufw"
#define UFW_BPF_PIN_FLOWS    UFW_BPF_PIN_DIR "/flows"
#define UFW_BPF_PIN_COUNTERS UFW_BPF_PIN_DIR "/counters"
#define UFW_BPF_PIN_CONFIG   UFW_BPF_PIN_DIR "/config"
#define UFW_BPF_PIN_RULES    UFW_BPF_PIN_DIR "/rule_counters"

/* Mirrors of the BPF-side types. Kept in this header rather than shared with
 * ebpf/common.h because that file includes BPF headers; a mismatch between
 * the two is caught by the static assertions at the bottom of the loader. */

struct ufw_bpf_flow_key {
	__u32 src_addr;
	__u32 dst_addr;
	__u16 src_port;
	__u16 dst_port;
	__u8  protocol;
	__u8  _pad[3];
};

struct ufw_bpf_flow_state {
	__u64 first_seen_ns;
	__u64 last_seen_ns;
	__u64 packets;
	__u64 bytes;
	__u32 rule_id;
	__u8  verdict;
	__u8  _pad[3];
};

struct ufw_bpf_rule_counter {
	__u64 packets;
	__u64 bytes;
	__u64 last_seen_ns;
};

struct ufw_bpf_counters {
	__u64 packets_seen;
	__u64 packets_passed;
	__u64 packets_dropped;
	__u64 fell_through;
	__u64 parse_failed;
};

/* Indices into the config array map. */
enum ufw_bpf_config {
	/* Zero disables the fast path without detaching the program, which is
	 * what an operator wants when working out whether a behaviour
	 * difference comes from the fast path or from the module. */
	UFW_BPF_CONFIG_ENABLED  = 0,
	/* The policy revision the loaded rule table was compiled from. The
	 * daemon compares this against the module's revision; a mismatch
	 * means one of the two enforcement points is stale, which is
	 * reported rather than silently tolerated. */
	UFW_BPF_CONFIG_REVISION = 1,
};

#endif /* UFW_EBPF_MAPS_H */

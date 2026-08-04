// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Unified Firewall — flow table maintenance.
 *
 * The fast path in packet_filter.c writes flow state; this program ages it.
 *
 * # Why a separate program
 *
 * The flow map is an LRU hash, so it never fills — the kernel evicts for us.
 * But LRU eviction is by *access*, and a TCP connection that was denied and
 * then abandoned keeps its entry alive as long as the peer retransmits. That
 * is the wrong retention policy for a security decision: a flow's verdict
 * should expire on the flow's terms, not on the attacker's.
 *
 * So this program is attached to a periodic trigger from userspace and sweeps
 * entries whose last packet is older than their protocol's timeout. TCP gets
 * a long one because a legitimately idle connection is common; UDP gets a
 * short one because there is no such thing as an idle UDP flow, only a
 * finished one.
 *
 * # Why not do it in the classifier
 *
 * The classifier runs per packet, and sweeping there would mean either
 * amortising a scan across packets (state, and complexity, in the hot path)
 * or scanning on every packet (unacceptable). A sweep that runs on a timer
 * costs nothing per packet and everything it costs is off the data path.
 */

#include <linux/bpf.h>
#include <linux/in.h>

#include <bpf/bpf_helpers.h>

#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Timeouts, in nanoseconds.
 *
 * TCP: five minutes. Long enough that an idle SSH session or a held HTTP
 * keep-alive is not re-decided, short enough that a verdict does not outlive
 * the policy that produced it by much.
 *
 * UDP: thirty seconds. There is no idle UDP flow — a DNS exchange is over in
 * milliseconds and a media stream sends continuously — so a gap this long
 * means the flow ended.
 *
 * Other: one minute, applied to anything the fast path cached without ports.
 */
#define UFW_CT_TCP_IDLE_NS   (300ULL * 1000000000ULL)
#define UFW_CT_UDP_IDLE_NS   (30ULL * 1000000000ULL)
#define UFW_CT_OTHER_IDLE_NS (60ULL * 1000000000ULL)

/* Bounded per invocation: bpf_for_each_map_elem needs a callback with a
 * bounded budget, and holding the map's bucket locks for a long sweep would
 * stall the classifier. Several invocations cover a large map. */
#define UFW_CT_SWEEP_BUDGET 1024

extern struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct ufw_flow_key);
	__type(value, struct ufw_flow_state);
} ufw_flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} ufw_ct_stats SEC(".maps");

#define UFW_CT_STAT_SWEPT   0
#define UFW_CT_STAT_EXPIRED 1

struct sweep_ctx {
	__u64 now;
	__u32 examined;
	__u32 expired;
};

static __always_inline __u64 idle_limit(__u8 protocol)
{
	if (protocol == IPPROTO_TCP)
		return UFW_CT_TCP_IDLE_NS;
	if (protocol == IPPROTO_UDP)
		return UFW_CT_UDP_IDLE_NS;
	return UFW_CT_OTHER_IDLE_NS;
}

static __u64 sweep_one(struct bpf_map *map, struct ufw_flow_key *key,
		       struct ufw_flow_state *state, struct sweep_ctx *ctx)
{
	if (ctx->examined >= UFW_CT_SWEEP_BUDGET)
		return 1;	/* non-zero stops the iteration */

	ctx->examined++;

	if (ctx->now - state->last_seen_ns > idle_limit(key->protocol)) {
		bpf_map_delete_elem(map, key);
		ctx->expired++;
	}
	return 0;
}

SEC("syscall")
int ufw_conntrack_sweep(void *unused)
{
	struct sweep_ctx ctx = {
		.now = bpf_ktime_get_ns(),
		.examined = 0,
		.expired = 0,
	};
	__u32 swept_key = UFW_CT_STAT_SWEPT;
	__u32 expired_key = UFW_CT_STAT_EXPIRED;
	__u64 *swept, *expired;

	bpf_for_each_map_elem(&ufw_flows, sweep_one, &ctx, 0);

	swept = bpf_map_lookup_elem(&ufw_ct_stats, &swept_key);
	if (swept)
		*swept += ctx.examined;

	expired = bpf_map_lookup_elem(&ufw_ct_stats, &expired_key);
	if (expired)
		*expired += ctx.expired;

	return 0;
}

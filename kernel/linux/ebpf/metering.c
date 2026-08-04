// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Unified Firewall — per-rule traffic accounting.
 *
 * Separate from the classifier because accounting and filtering have
 * different failure modes and should not share one. If the counter map is
 * full or a lookup fails, a metering program returns without an opinion; a
 * classifier cannot, because it has to say pass or drop. Keeping them apart
 * means an accounting problem can never become a filtering problem.
 *
 * This attaches to tc *egress*, which the classifier deliberately does not.
 * There is no verdict here, so the ordering hazard that keeps the classifier
 * off egress — netfilter has already decided by then — does not apply: this
 * program only counts what the decision let through.
 *
 * # Percentile-free by design
 *
 * The counters are totals, not histograms. A histogram in a BPF map means
 * either fixed buckets (which are wrong until someone tunes them, and are
 * then wrong again when traffic changes) or a sketch (which is a lot of
 * arithmetic on the data path for a number nobody reads during an incident).
 * Totals answer "is this rule being used" and "how much", which is what a
 * rule's counters are actually consulted for.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct ufw_rule_counter {
	__u64 packets;
	__u64 bytes;
	__u64 last_seen_ns;
};

/*
 * Per-CPU so the update is a plain read-modify-write with no atomics and no
 * contention. Summed by the reader, which means a snapshot can be slightly
 * inconsistent across CPUs — acceptable for a counter, and the alternative
 * is a shared cache line touched by every packet on every core.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, UFW_EBPF_MAX_RULES * 4);
	__type(key, __u32);		/* rule id */
	__type(value, struct ufw_rule_counter);
} ufw_rule_counters SEC(".maps");

extern struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct ufw_flow_key);
	__type(value, struct ufw_flow_state);
} ufw_flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ufw_ebpf_counters);
} ufw_meter_totals SEC(".maps");

static __always_inline void account(__u32 rule_id, __u32 bytes)
{
	struct ufw_rule_counter *counter;
	struct ufw_rule_counter fresh = {
		.packets = 1,
		.bytes = bytes,
		.last_seen_ns = bpf_ktime_get_ns(),
	};

	counter = bpf_map_lookup_elem(&ufw_rule_counters, &rule_id);
	if (counter) {
		counter->packets++;
		counter->bytes += bytes;
		counter->last_seen_ns = fresh.last_seen_ns;
		return;
	}

	/* BPF_NOEXIST rather than BPF_ANY: two CPUs can reach here for the
	 * same rule at once, and the loser should not clobber the winner's
	 * count back to 1. */
	bpf_map_update_elem(&ufw_rule_counters, &rule_id, &fresh, BPF_NOEXIST);
}

SEC("tc")
int ufw_meter(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct ufw_flow_key key = {};
	struct ufw_flow_state *state;
	struct ufw_ebpf_counters *totals;
	__u32 zero = 0;

	totals = bpf_map_lookup_elem(&ufw_meter_totals, &zero);
	if (totals)
		totals->packets_seen++;

	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;

	/*
	 * The flow map is keyed on the ingress orientation, so an egress
	 * packet's addresses are swapped relative to it. Looking up the
	 * reversed key finds the flow this packet belongs to; a flow the
	 * fast path never decided simply is not counted here, which is
	 * correct — its rule is one the module applied, and the module has
	 * its own counters.
	 */
	key.src_addr = ip->daddr;
	key.dst_addr = ip->saddr;
	key.protocol = ip->protocol;

	state = bpf_map_lookup_elem(&ufw_flows, &key);
	if (!state)
		return TC_ACT_OK;

	account(state->rule_id, skb->len);
	if (totals)
		totals->packets_passed++;

	return TC_ACT_OK;
}

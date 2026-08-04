// SPDX-License-Identifier: GPL-2.0
/*
 * Unified Firewall — XDP fast path.
 *
 * The same rule table as packet_filter.c, at a different attachment point,
 * and the difference is where in the kernel a drop happens.
 *
 *   tc ingress  → after the sk_buff exists. The allocation, the metadata
 *                 initialisation and the protocol demux have all been paid for
 *                 by the time the verdict is reached.
 *   XDP         → in the driver's receive path, before any of that. A dropped
 *                 packet costs a table lookup and a return code.
 *
 * Under a flood that is not a percentage difference. It is the difference
 * between a machine that stays responsive and one whose CPUs are consumed
 * allocating buffers for packets it is about to discard.
 *
 * # Why tc still exists
 *
 * XDP is not a superset. It sees only ingress, only before the stack, and
 * only what the driver hands it — so on a driver without native XDP the
 * kernel falls back to generic mode, which runs *after* the sk_buff exists
 * and is slower than tc. And XDP cannot see egress at all.
 *
 * So the two are complementary rather than alternatives: XDP drops the
 * obviously-unwanted inbound flood, tc handles egress and everything XDP
 * passed. `daemon/src/ipc/linux.rs` reports which are attached, because "the
 * fast path is active" is a different statement from "XDP is active" and an
 * operator debugging throughput needs to know which.
 *
 * # The verifier's constraints shape this file
 *
 * No loops over the rule table with a variable bound, no function calls that
 * are not inlined, every pointer dereference preceded by a bounds check
 * against `data_end` that the verifier can follow. That is why the code below
 * looks repetitive: written the natural way it does not load.
 */

#include "common.h"

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
 * Addresses this host will drop before the stack sees them.
 *
 * Deliberately *not* the whole policy. XDP has no connection tracking, no
 * process identity and no payload; a rule needing any of those cannot be
 * decided here, and half-deciding it would be worse than not trying. What
 * lives here is the subset the compiler marks as XDP-eligible: source-address
 * denies with no other predicate.
 *
 * The map is populated by the daemon, so a policy reload changes it without
 * reloading the program — and an empty map means every packet passes to tc,
 * which is the correct behaviour when no rule qualifies.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, UFW_EBPF_MAX_RULES);
	__type(key, struct ufw_lpm_key_v4);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ufw_xdp_deny_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, UFW_EBPF_MAX_RULES);
	__type(key, struct ufw_lpm_key_v6);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ufw_xdp_deny_v6 SEC(".maps");

/* Two counters, because "XDP dropped nothing" and "XDP is not attached" look
 * identical from userland otherwise, and an operator chasing a throughput
 * problem needs to tell them apart. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ufw_xdp_stats SEC(".maps");

#define UFW_XDP_SEEN    0
#define UFW_XDP_DROPPED 1

static __always_inline void ufw_xdp_count(__u32 slot)
{
	__u64 *v = bpf_map_lookup_elem(&ufw_xdp_stats, &slot);

	if (v)
		__sync_fetch_and_add(v, 1);
}

SEC("xdp")
int ufw_xdp_ingress(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	__u16 proto;

	ufw_xdp_count(UFW_XDP_SEEN);

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	proto = eth->h_proto;

	/* A VLAN tag shifts everything by four bytes. One level is unwrapped;
	 * QinQ is passed to tc rather than unwrapped further, because each
	 * level is another bounds check the verifier has to follow and the
	 * second level is rare enough not to be worth the instruction budget
	 * on the fast path. */
	if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr {
			__be16 tci;
			__be16 encapsulated;
		} *vlan = (void *)(eth + 1);

		if ((void *)(vlan + 1) > data_end)
			return XDP_PASS;
		proto = vlan->encapsulated;
		data = (void *)(vlan + 1);
	} else {
		data = (void *)(eth + 1);
	}

	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = data;
		struct ufw_lpm_key_v4 key;
		__u8 *deny;

		if ((void *)(ip + 1) > data_end)
			return XDP_PASS;

		/* A fragment other than the first has no transport header, so
		 * a port-scoped rule cannot apply to it. Passing it to tc is
		 * the fail-open direction *for this layer only* — the module
		 * still sees it, and evasion.h is what looks at the overlap. */
		if (ip->frag_off & bpf_htons(0x1FFF))
			return XDP_PASS;

		key.prefixlen = 32;
		key.addr = ip->saddr;
		deny = bpf_map_lookup_elem(&ufw_xdp_deny_v4, &key);
		if (deny && *deny) {
			ufw_xdp_count(UFW_XDP_DROPPED);
			return XDP_DROP;
		}
		return XDP_PASS;
	}

	if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = data;
		struct ufw_lpm_key_v6 key;
		__u8 *deny;

		if ((void *)(ip6 + 1) > data_end)
			return XDP_PASS;

		key.prefixlen = 128;
		__builtin_memcpy(key.addr, &ip6->saddr, 16);
		deny = bpf_map_lookup_elem(&ufw_xdp_deny_v6, &key);
		if (deny && *deny) {
			ufw_xdp_count(UFW_XDP_DROPPED);
			return XDP_DROP;
		}
		return XDP_PASS;
	}

	/* ARP, and anything else this program does not decode. Dropping what
	 * it does not understand would take the machine off the network the
	 * first time somebody used a protocol nobody thought about. */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

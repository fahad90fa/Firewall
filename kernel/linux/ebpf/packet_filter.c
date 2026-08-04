// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Unified Firewall — tc ingress fast path.
 *
 * Attached to clsact ingress. Decides the packets it can decide provably
 * correctly, and passes everything else to the stack, where the netfilter
 * hook evaluates the complete policy.
 *
 * See common.h for why this is a prefix of the rule table rather than a
 * subset, and why it is ingress-only. Those two properties are what make it
 * safe for this program to return a verdict at all.
 *
 * # IPv4 only, and why that is not a gap
 *
 * The fast path handles IPv4 and hands every IPv6 packet to the stack. A v6
 * address is 16 bytes, so a v6 CIDR comparison is four 32-bit compares
 * instead of one, and the rule scan is unrolled — the instruction count
 * roughly quadruples and the program stops verifying well before 64 rules.
 *
 * Handing v6 to the slow path is correct, just slower: the netfilter hook
 * evaluates the same policy and reaches the same verdict. A v6-capable fast
 * path would need a different rule layout (an LPM trie map rather than an
 * unrolled scan), which is a worthwhile change and not a small one. Until
 * then this is an accelerator that accelerates half the traffic, not a
 * filter with a v6 hole.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "common.h"
#include "ufw_ebpf_rules.h"	/* generated: ufw_ebpf_rules[], UFW_EBPF_RULE_COUNT */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
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
} ufw_counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} ufw_config SEC(".maps");

static __always_inline struct ufw_ebpf_counters *counters(void)
{
	__u32 zero = 0;

	return bpf_map_lookup_elem(&ufw_counters, &zero);
}

static __always_inline __u64 config(__u32 index)
{
	__u64 *value = bpf_map_lookup_elem(&ufw_config, &index);

	return value ? *value : 0;
}

static __always_inline int cidr_contains(const struct ufw_ebpf_cidr *cidr,
					 __u32 addr)
{
	__u32 mask;

	/* A /0 matches everything, and the shift below is undefined for a
	 * 32-bit shift on a 32-bit type, so it is special-cased rather than
	 * relying on the compiler doing something reasonable. */
	if (cidr->prefix_len == 0)
		return 1;
	if (cidr->prefix_len >= 32)
		return cidr->addr == addr;

	mask = bpf_htonl(~0u << (32 - cidr->prefix_len));
	return (cidr->addr & mask) == (addr & mask);
}

static __always_inline int addr_match(const struct ufw_ebpf_cidr *cidrs,
				      __u8 count, __u32 addr)
{
	int i;

	if (count == 0)
		return 1;

	/* Bounded and unrolled: the verifier needs the trip count to be a
	 * compile-time constant. `count` is checked inside rather than used
	 * as the bound. */
#pragma unroll
	for (i = 0; i < UFW_EBPF_MAX_CIDRS; i++) {
		if (i >= count)
			break;
		if (cidr_contains(&cidrs[i], addr))
			return 1;
	}
	return 0;
}

static __always_inline int port_match(const struct ufw_ebpf_port_range *ranges,
				      __u8 count, __u16 port, __u8 protocol)
{
	int i;

	if (count == 0)
		return 1;

	/* A port constraint on a protocol with no ports never matches. Same
	 * rule as the module and the reference implementation; getting this
	 * wrong here would make the fast path disagree with the slow one for
	 * ICMP, which is exactly what the prefix argument is supposed to
	 * make impossible. */
	if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
		return 0;

#pragma unroll
	for (i = 0; i < UFW_EBPF_MAX_PORTS; i++) {
		if (i >= count)
			break;
		if (port >= ranges[i].lo && port <= ranges[i].hi)
			return 1;
	}
	return 0;
}

struct parsed {
	__u32 src_addr;
	__u32 dst_addr;
	__u16 src_port;
	__u16 dst_port;
	__u8  protocol;
};

/*
 * Parse enough of the packet to classify it.
 *
 * Returns 0 on success, -1 when the packet is not IPv4 or is malformed. Every
 * read is bounds-checked against `data_end` before it happens, which is both
 * a verifier requirement and the thing that makes this safe: `data_end` is
 * the only truth about how many bytes are actually there.
 */
static __always_inline int parse(void *data, void *data_end,
				 struct parsed *out)
{
	struct ethhdr *eth = data;
	struct iphdr *ip;
	__u32 ip_len;

	if ((void *)(eth + 1) > data_end)
		return -1;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return -1;

	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return -1;

	ip_len = ip->ihl * 4;
	if (ip_len < sizeof(*ip))
		return -1;
	if ((void *)ip + ip_len > data_end)
		return -1;

	/*
	 * A non-first fragment carries no transport header, so its ports are
	 * unknowable. Rather than classify it with port 0 — which would let
	 * an attacker choose which rule applies by fragmenting — it is handed
	 * to the stack, where conntrack reassembles before the netfilter hook
	 * sees it.
	 */
	if (ip->frag_off & bpf_htons(0x1FFF))
		return -1;

	out->src_addr = ip->saddr;
	out->dst_addr = ip->daddr;
	out->protocol = ip->protocol;
	out->src_port = 0;
	out->dst_port = 0;

	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = (void *)ip + ip_len;

		if ((void *)(tcp + 1) > data_end)
			return -1;
		out->src_port = bpf_ntohs(tcp->source);
		out->dst_port = bpf_ntohs(tcp->dest);
	} else if (ip->protocol == IPPROTO_UDP) {
		struct udphdr *udp = (void *)ip + ip_len;

		if ((void *)(udp + 1) > data_end)
			return -1;
		out->src_port = bpf_ntohs(udp->source);
		out->dst_port = bpf_ntohs(udp->dest);
	}
	return 0;
}

SEC("tc")
int ufw_ingress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ufw_ebpf_counters *c = counters();
	struct ufw_flow_key key = {};
	struct ufw_flow_state *state, fresh = {};
	struct parsed p;
	int i;

	/* The daemon clears this to disable the fast path without detaching
	 * the program — which is what an operator wants when diagnosing
	 * whether a difference in behaviour comes from here or from the
	 * module. */
	if (!config(UFW_CONFIG_ENABLED))
		return TC_ACT_OK;

	if (c)
		c->packets_seen++;

	if (parse(data, data_end, &p) < 0) {
		/* Not something this program can decide. The stack and the
		 * netfilter hook get it, and the hook drops it if it is
		 * genuinely unparseable there too. */
		if (c)
			c->parse_failed++;
		return TC_ACT_OK;
	}

	key.src_addr = p.src_addr;
	key.dst_addr = p.dst_addr;
	key.src_port = p.src_port;
	key.dst_port = p.dst_port;
	key.protocol = p.protocol;

	/*
	 * An established flow keeps its verdict.
	 *
	 * This is a cache of a decision this program already made, not of one
	 * the module made — the module's decisions can depend on identity and
	 * payload, which change over a flow's life. Caching only what this
	 * program decided keeps the invariant intact: everything in this map
	 * came from the prefix, and the prefix agrees with the full table.
	 */
	state = bpf_map_lookup_elem(&ufw_flows, &key);
	if (state) {
		state->last_seen_ns = bpf_ktime_get_ns();
		state->packets++;
		state->bytes += skb->len;
		if (state->verdict == UFW_VERDICT_DROP) {
			if (c)
				c->packets_dropped++;
			return TC_ACT_SHOT;
		}
		if (c)
			c->packets_passed++;
		return TC_ACT_OK;
	}

#pragma unroll
	for (i = 0; i < UFW_EBPF_MAX_RULES; i++) {
		const struct ufw_ebpf_rule *rule;

		if (i >= UFW_EBPF_RULE_COUNT)
			break;

		rule = &ufw_ebpf_rules[i];

		/* Ingress only, so a rule scoped to outbound cannot apply. */
		if (rule->direction == UFW_DIR_OUTBOUND)
			continue;
		if (rule->protocol != UFW_PROTO_ANY &&
		    rule->protocol != p.protocol)
			continue;
		if (!addr_match(rule->src_cidrs, rule->src_n, p.src_addr))
			continue;
		if (!addr_match(rule->dst_cidrs, rule->dst_n, p.dst_addr))
			continue;
		if (!port_match(rule->src_ports, rule->src_port_n,
				p.src_port, p.protocol))
			continue;
		if (!port_match(rule->dst_ports, rule->dst_port_n,
				p.dst_port, p.protocol))
			continue;

		fresh.first_seen_ns = bpf_ktime_get_ns();
		fresh.last_seen_ns = fresh.first_seen_ns;
		fresh.packets = 1;
		fresh.bytes = skb->len;
		fresh.rule_id = rule->rule_id;
		fresh.verdict = rule->action;
		bpf_map_update_elem(&ufw_flows, &key, &fresh, BPF_ANY);

		if (rule->action == UFW_VERDICT_DROP) {
			if (c)
				c->packets_dropped++;
			return TC_ACT_SHOT;
		}
		if (c)
			c->packets_passed++;
		return TC_ACT_OK;
	}

	/*
	 * No rule in the prefix matched. That is not "allow": it means the
	 * decision belongs to the full table, which the module holds. Nothing
	 * is cached, because a fall-through is not a decision.
	 */
	if (c)
		c->fell_through++;
	return TC_ACT_OK;
}

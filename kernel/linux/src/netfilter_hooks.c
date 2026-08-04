// SPDX-License-Identifier: Apache-2.0
/*
 * Unified Firewall — where packets arrive.
 *
 * Four hook registrations (in and out, v4 and v6), one shared handler. The
 * handler's job is narrow: assemble the facts, ask the classifier, act on the
 * answer, and get out of the way. Everything expensive lives behind a flag
 * check so that the common case — a header-only rule matching a packet with
 * no identity or DPI requirement — costs a table scan and nothing else.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/percpu.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <net/sock.h>

#include "../inc/module.h"
#include "../inc/netfilter_hooks.h"

DEFINE_PER_CPU(struct ufw_stats, ufw_stats);

static struct ufw_network_profile ufw_profile;
static DEFINE_SPINLOCK(ufw_profile_lock);

void ufw_profile_install(const struct ufw_network_profile *profile)
{
	unsigned long flags;

	spin_lock_irqsave(&ufw_profile_lock, flags);
	memcpy(&ufw_profile, profile, sizeof(ufw_profile));
	spin_unlock_irqrestore(&ufw_profile_lock, flags);
}

__u8 ufw_zone_of(const __u8 *addr, int is_v6)
{
	__u8 i;

	/* Loopback first: it is the most common address to classify and the
	 * one where getting it wrong is most disruptive. */
	if (!is_v6) {
		if (addr[0] == 127)
			return UFW_ZONE_LOCAL;
	} else {
		static const __u8 v6_loopback[16] = {
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
		};

		if (memcmp(addr, v6_loopback, 16) == 0)
			return UFW_ZONE_LOCAL;
	}

	/* Perimeter is checked before internal because the two can overlap:
	 * a DMZ range is usually a subset of RFC1918, and the more specific
	 * classification is the one the operator meant. */
	for (i = 0; i < ufw_profile.perimeter_count && i < UFW_MAX_CIDRS_PER_RULE; i++) {
		if (ufw_cidr_contains(&ufw_profile.perimeter[i], addr, is_v6))
			return UFW_ZONE_PERIMETER;
	}
	for (i = 0; i < ufw_profile.internal_count && i < UFW_MAX_CIDRS_PER_RULE; i++) {
		if (ufw_cidr_contains(&ufw_profile.internal[i], addr, is_v6))
			return UFW_ZONE_INTERNAL;
	}
	return UFW_ZONE_EXTERNAL;
}

/* --- statistics --------------------------------------------------------- */

void ufw_stats_sum(struct ufw_stats *out)
{
	int cpu;

	memset(out, 0, sizeof(*out));
	for_each_possible_cpu(cpu) {
		const struct ufw_stats *s = per_cpu_ptr(&ufw_stats, cpu);

		out->packets_seen += s->packets_seen;
		out->packets_allowed += s->packets_allowed;
		out->packets_denied += s->packets_denied;
		out->flows_seen += s->flows_seen;
		out->flows_allowed += s->flows_allowed;
		out->flows_denied += s->flows_denied;
		out->identity_cache_hits += s->identity_cache_hits;
		out->identity_cache_misses += s->identity_cache_misses;
		out->identity_queries_timed_out += s->identity_queries_timed_out;
		out->dpi_scans += s->dpi_scans;
		out->dpi_hits += s->dpi_hits;
		out->reassembly_contexts += s->reassembly_contexts;
		out->reassembly_truncated += s->reassembly_truncated;
		out->conntrack_entries += s->conntrack_entries;
		out->log_events_dropped += s->log_events_dropped;
		out->ebpf_fastpath_decisions += s->ebpf_fastpath_decisions;
	}
}

void ufw_stats_reset(void)
{
	int cpu;

	for_each_possible_cpu(cpu)
		memset(per_cpu_ptr(&ufw_stats, cpu), 0, sizeof(struct ufw_stats));
}

/* --- mode ---------------------------------------------------------------- */

static atomic_t ufw_mode = ATOMIC_INIT(UFW_MODE_ENFORCE);

enum ufw_mode ufw_get_mode(void)
{
	return (enum ufw_mode)atomic_read(&ufw_mode);
}

void ufw_set_mode(enum ufw_mode mode)
{
	atomic_set(&ufw_mode, (int)mode);
	ufw_log_note("enforcement mode is now %d", (int)mode);
}

/* --- the handler --------------------------------------------------------- */

/*
 * `facts` is a per-CPU scratch buffer rather than a stack local.
 *
 * sizeof(struct ufw_flow_facts) is around 600 bytes, and kernel stacks are
 * 16 KiB with softirq processing already some way into them. Putting it on
 * the stack works until it does not, and the failure mode is a stack overflow
 * inside the network stack, which is not a failure mode worth having to
 * diagnose. Preemption is disabled around the use, so the buffer cannot be
 * shared with another packet on the same CPU.
 */
static DEFINE_PER_CPU(struct ufw_flow_facts, ufw_facts_scratch);

static unsigned int ufw_handle(void *priv, struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	struct ufw_flow_facts *facts;
	struct ufw_decision decision;
	const struct net_device *dev;
	unsigned int result;
	enum ufw_mode mode;

	if (!skb)
		return NF_ACCEPT;

	mode = ufw_get_mode();
	if (mode == UFW_MODE_EMERGENCY_ALLOW)
		return NF_ACCEPT;

	dev = (state->hook == NF_INET_LOCAL_IN) ? state->in : state->out;

	/* get_cpu_ptr disables preemption, which is what makes the shared
	 * scratch buffer safe. */
	facts = get_cpu_ptr(&ufw_facts_scratch);

	if (ufw_facts_from_skb(skb, state->hook, dev, facts) < 0) {
		/*
		 * Unparseable. Dropping rather than accepting: a packet that
		 * cannot be classified cannot be shown to be permitted, and
		 * "malformed enough that the firewall gave up" is exactly the
		 * shape of an evasion attempt.
		 */
		put_cpu_ptr(&ufw_facts_scratch);
		UFW_COUNT(packets_seen);
		UFW_COUNT(packets_denied);
		return NF_DROP;
	}

	UFW_COUNT(packets_seen);

	/*
	 * Identity, only when some rule needs it. `sk` is available on the
	 * output path for locally generated traffic and on input once the
	 * socket has been looked up; where it is absent the identity stays
	 * unresolved and the fail-closed rules in classify.c apply.
	 */
	if (skb->sk)
		ufw_identity_fill(skb->sk, facts);

	/* Payload inspection, likewise. This is the expensive one, and it is
	 * gated on the flow already being interesting rather than run
	 * speculatively. */
	if (facts->protocol == IPPROTO_TCP || facts->protocol == IPPROTO_UDP)
		ufw_stream_observe(skb, facts);

	ufw_classify(facts, &decision);

	if (decision.logged)
		ufw_log_decision(facts, &decision);

	switch (decision.verdict) {
	case UFW_VERDICT_DROP:
	case UFW_VERDICT_REJECT:
		UFW_COUNT(packets_denied);
		/*
		 * Monitor mode computes and logs the decision, then accepts
		 * anyway. This is how a deployment builds the inventory a
		 * default-deny policy needs without an outage first.
		 */
		result = (mode == UFW_MODE_MONITOR) ? NF_ACCEPT : NF_DROP;
		break;
	default:
		UFW_COUNT(packets_allowed);
		result = NF_ACCEPT;
		break;
	}

	put_cpu_ptr(&ufw_facts_scratch);
	return result;
}

static struct nf_hook_ops ufw_hook_ops[] = {
	{
		.hook = ufw_handle,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = UFW_HOOK_PRIORITY,
	},
	{
		.hook = ufw_handle,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = UFW_HOOK_PRIORITY,
	},
	{
		.hook = ufw_handle,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = UFW_HOOK_PRIORITY,
	},
	{
		.hook = ufw_handle,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = UFW_HOOK_PRIORITY,
	},
};

int ufw_hooks_init(void)
{
	return nf_register_net_hooks(&init_net, ufw_hook_ops,
				     ARRAY_SIZE(ufw_hook_ops));
}

void ufw_hooks_exit(void)
{
	nf_unregister_net_hooks(&init_net, ufw_hook_ops,
				ARRAY_SIZE(ufw_hook_ops));
}

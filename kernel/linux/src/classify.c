// SPDX-License-Identifier: Apache-2.0
/*
 * Unified Firewall — the decision.
 *
 * This file is the Linux half of the equivalence claim. Everything it does
 * must agree with `CompiledPolicy::evaluate` in shared/src/policy_types.rs
 * and with the Windows and macOS classifiers, for every input. The compiler's
 * equivalence verifier checks that claim against a scenario corpus at build
 * time; this comment exists to say which lines are load-bearing when it
 * fails.
 *
 * The structure is deliberately boring: stages in a fixed order, rules within
 * a stage in a fixed order, first terminal action wins. There is no
 * optimisation here beyond the stage index, because a classifier that is
 * clever is a classifier whose cleverness has to be replicated identically in
 * C, C and Swift.
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <net/ip.h>

#include "../inc/module.h"
#include "../inc/netfilter_hooks.h"

struct ufw_policy_table __rcu *ufw_policy;

/* --- address and port matching ----------------------------------------- */

bool ufw_cidr_contains(const struct ufw_cidr *cidr, const __u8 *addr, int is_v6)
{
	int full_bytes, rest_bits;

	/* A v4 rule never matches a v6 address and vice versa. This is not an
	 * arbitrary strictness: an IPv4-mapped IPv6 address would otherwise
	 * satisfy a v4 CIDR through one path and not another depending on how
	 * the stack presented it, and that is exactly the kind of ambiguity
	 * that becomes a bypass. */
	if (!!cidr->is_v6 != !!is_v6)
		return false;

	full_bytes = cidr->prefix_len / 8;
	rest_bits = cidr->prefix_len % 8;

	if (full_bytes && memcmp(cidr->addr, addr, full_bytes) != 0)
		return false;

	if (rest_bits) {
		__u8 mask = (__u8)(0xFFu << (8 - rest_bits));

		if ((cidr->addr[full_bytes] & mask) != (addr[full_bytes] & mask))
			return false;
	}
	return true;
}

static bool ufw_match_addr(const struct ufw_addr_match *m, const __u8 *addr,
		           int is_v6, __u8 zone)
{
	bool hit = false;
	__u8 i;

	/* No constraint at all matches everything, and negating "everything"
	 * would match nothing — which is never what an author means. The
	 * compiler rejects a negated empty match, so this branch is the
	 * belt to that braces. */
	if (m->cidr_count == 0 && m->zone_mask == 0)
		return true;

	for (i = 0; i < m->cidr_count && i < UFW_MAX_CIDRS_PER_RULE; i++) {
		if (ufw_cidr_contains(&m->cidrs[i], addr, is_v6)) {
			hit = true;
			break;
		}
	}

	if (!hit && m->zone_mask)
		hit = (m->zone_mask & (1u << zone)) != 0;

	return m->negate ? !hit : hit;
}

static bool ufw_match_port(const struct ufw_port_match *m, __u16 port,
		           __u8 protocol)
{
	bool hit = false;
	__u8 i;

	if (m->range_count == 0)
		return true;

	/*
	 * A port constraint on a protocol with no ports never matches, not
	 * even negated. ICMP has no port field, so "port is not 53" is not
	 * vacuously true — it is unanswerable, and an unanswerable predicate
	 * must not permit. The reference implementation does the same; this
	 * is one of the places the three implementations most easily drift.
	 */
	if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP &&
	    protocol != UFW_PROTO_ANY)
		return false;

	for (i = 0; i < m->range_count && i < UFW_MAX_PORT_RANGES; i++) {
		if (port >= m->ranges[i].lo && port <= m->ranges[i].hi) {
			hit = true;
			break;
		}
	}
	return m->negate ? !hit : hit;
}

/* --- identity matching -------------------------------------------------- */

bool ufw_path_match(const char *pattern, const char *path, int case_insensitive)
{
	const char *p = pattern, *s = path;
	const char *star = NULL, *star_s = NULL;

	/*
	 * Iterative glob with one backtrack point. The classic recursive
	 * implementation is exponential on patterns like `*a*a*a*b` against
	 * `aaaaaaaa`, and every component of a path here is attacker-
	 * influenced: a process can be named anything. This form is O(n*m)
	 * worst case with no stack growth, which is what softirq context
	 * requires.
	 */
	while (*s) {
		char pc = *p, sc = *s;

		if (case_insensitive) {
			if (pc >= 'A' && pc <= 'Z')
				pc = (char)(pc + 32);
			if (sc >= 'A' && sc <= 'Z')
				sc = (char)(sc + 32);
		}

		if (*p == '?' || (*p && pc == sc)) {
			p++;
			s++;
		} else if (*p == '*') {
			star = p++;
			star_s = s;
		} else if (star) {
			p = star + 1;
			s = ++star_s;
		} else {
			return false;
		}
	}
	while (*p == '*')
		p++;
	return *p == '\0';
}

static bool ufw_match_fingerprint(const struct ufw_fingerprint *fp,
			          const struct ufw_flow_facts *facts)
{
	bool ok;
	__u8 i;

	/* Within a fingerprint every stated criterion must hold. A
	 * fingerprint that names both a path and a signer means "this binary,
	 * signed by them" — not "either". */
	if (fp->path_count) {
		ok = false;
		for (i = 0; i < fp->path_count && i < UFW_MAX_PATHS_PER_FP; i++) {
			if (ufw_path_match(fp->paths[i], facts->path,
					   fp->case_insensitive)) {
				ok = true;
				break;
			}
		}
		if (!ok)
			return false;
	}

	if (fp->hash_count) {
		ok = false;
		for (i = 0; i < fp->hash_count && i < UFW_MAX_HASHES_PER_FP; i++) {
			if (memcmp(fp->hashes[i], facts->sha256, 32) == 0) {
				ok = true;
				break;
			}
		}
		if (!ok)
			return false;
	}

	if (fp->signer_count) {
		ok = false;
		for (i = 0; i < fp->signer_count && i < UFW_MAX_SIGNERS_PER_FP; i++) {
			if (strncmp(fp->signers[i], facts->signer,
				    UFW_MAX_SIGNER_LEN) == 0) {
				ok = true;
				break;
			}
		}
		if (!ok)
			return false;
	}

	return true;
}

static bool ufw_match_app(const struct ufw_app_match *m,
		          const struct ufw_flow_facts *facts)
{
	bool hit;
	__u8 i;

	/*
	 * The fail-closed asymmetry, and the single most important five lines
	 * in this file.
	 *
	 * An unresolved identity does not match an application predicate —
	 * and, critically, does not match a *negated* one either. If it did,
	 * "deny anything that is not our signed binary" would be satisfied by
	 * any process the resolver could not inspect, which is precisely the
	 * set an attacker can arrange to be in.
	 */
	if (!facts->identity_valid)
		return false;

	if (m->trust_mask && !(m->trust_mask & (1u << facts->trust)))
		return false;

	if (m->require_valid_signature && !facts->signature_valid)
		return false;

	/* Fingerprints are a disjunction: one logical application is a
	 * Windows signer, a Linux path and a macOS Team ID, and a Linux
	 * binary must not be required to carry an Authenticode signature. */
	if (m->fingerprint_count == 0) {
		hit = true;
	} else {
		hit = false;
		for (i = 0; i < m->fingerprint_count && i < UFW_MAX_FINGERPRINTS; i++) {
			if (ufw_match_fingerprint(&m->fingerprints[i], facts)) {
				hit = true;
				break;
			}
		}
	}

	return m->negate ? !hit : hit;
}

/* --- DPI matching ------------------------------------------------------- */

static bool ufw_match_dpi(const struct ufw_dpi_match *m,
		          const struct ufw_flow_facts *facts)
{
	bool hit;
	__u8 i, j;

	if (!facts->dpi_valid)
		return false;

	if (m->l7_count) {
		hit = false;
		for (i = 0; i < m->l7_count && i < UFW_MAX_L7_PER_RULE; i++) {
			if (m->l7[i] == facts->l7) {
				hit = true;
				break;
			}
		}
		if (!hit)
			return false;
	}

	if (m->signature_count == 0)
		return true;

	for (i = 0; i < m->signature_count && i < UFW_MAX_SIGNATURES_PER_RULE; i++) {
		for (j = 0; j < facts->matched_count &&
			    j < UFW_MAX_SIGNATURES_PER_RULE; j++) {
			if (m->signature_ids[i] == facts->matched_signatures[j])
				return true;
		}
	}
	return false;
}

/* --- schedule ----------------------------------------------------------- */

static bool ufw_match_schedule(const struct ufw_schedule *s,
			       const struct ufw_flow_facts *facts)
{
	__u16 minute, day, minute_of_day;

	/* No clock, no match. A scheduled rule whose window cannot be
	 * evaluated is not "always active": the daemon pushes the local
	 * offset on every reload precisely so this stays answerable, and if
	 * it has not, the rule stands down rather than applying at the wrong
	 * time. */
	if (!facts->minute_valid)
		return false;

	minute = facts->minute_of_week;
	day = minute / 1440u;
	minute_of_day = minute % 1440u;

	if (!(s->day_mask & (1u << day)))
		return false;

	/* A window that wraps midnight, written `start: "22:00", end: "06:00"`,
	 * is two intervals rather than one. */
	if (s->start_minute <= s->end_minute)
		return minute_of_day >= s->start_minute &&
		       minute_of_day < s->end_minute;
	return minute_of_day >= s->start_minute ||
	       minute_of_day < s->end_minute;
}

/* --- stage gating -------------------------------------------------------- */

/*
 * Whether a stage runs at all for this protocol.
 *
 * The identity, app-dpi and stream stages need a socket with an owning
 * process and a payload to inspect. ICMP has neither, and Windows and macOS
 * cannot surface either for it at any hook. Gating here rather than on the
 * individual predicates matters for a rule that sits at one of those stages
 * without carrying an app or DPI clause — a terminal `layer: stream` deny,
 * say. Without this check Linux would attribute an ICMP denial to that rule
 * while the other two attributed it to the default, and the verdicts would
 * agree while the logs did not.
 */
static bool ufw_stage_applies(__u8 stage, __u8 protocol)
{
	switch (stage) {
	case UFW_STAGE_PERIMETER:
	case UFW_STAGE_PACKET:
		return true;
	default:
		return protocol == IPPROTO_TCP || protocol == IPPROTO_UDP ||
		       protocol == UFW_PROTO_ANY;
	}
}

/* --- the rule ------------------------------------------------------------ */

static bool ufw_rule_matches(const struct ufw_rule *rule,
			     const struct ufw_flow_facts *facts)
{
	__u8 i;

	if (!ufw_stage_applies(rule->stage, facts->protocol))
		return false;

	if (rule->direction != UFW_DIR_ANY && rule->direction != facts->direction)
		return false;

	if (rule->protocol != UFW_PROTO_ANY && rule->protocol != facts->protocol)
		return false;

	if (!ufw_match_addr(&rule->src, facts->src_addr, facts->is_v6, facts->src_zone))
		return false;
	if (!ufw_match_addr(&rule->dst, facts->dst_addr, facts->is_v6, facts->dst_zone))
		return false;

	if (!ufw_match_port(&rule->src_ports, facts->src_port, facts->protocol))
		return false;
	if (!ufw_match_port(&rule->dst_ports, facts->dst_port, facts->protocol))
		return false;

	if (rule->interface_count) {
		bool hit = false;

		for (i = 0; i < rule->interface_count && i < UFW_MAX_INTERFACES; i++) {
			if (strncmp(rule->interfaces[i], facts->ifname,
				    UFW_MAX_IFNAME) == 0) {
				hit = true;
				break;
			}
		}
		if (!hit)
			return false;
	}

	if ((rule->flags & UFW_FLAG_HAS_SCHEDULE) &&
	    !ufw_match_schedule(&rule->schedule, facts))
		return false;

	if ((rule->flags & UFW_FLAG_NEEDS_IDENTITY) && !ufw_match_app(&rule->app, facts))
		return false;

	if ((rule->flags & UFW_FLAG_NEEDS_DPI) && !ufw_match_dpi(&rule->dpi, facts))
		return false;

	return true;
}

/* A rule with a DPI clause contributes the clause's on_match action, which
 * is what makes `action: allow` + `on_match: deny` mean "permit unless the
 * payload trips". */
static __u8 effective_action(const struct ufw_rule *rule)
{
	if (rule->flags & UFW_FLAG_NEEDS_DPI)
		return rule->dpi.on_match;
	return rule->action;
}

/* --- the loop ------------------------------------------------------------ */

void ufw_classify(const struct ufw_flow_facts *facts, struct ufw_decision *out)
{
	const struct ufw_policy_table *table;
	__u8 stage;
	bool provisional_allow = false;
	__u32 provisional_rule = UFW_RULE_ID_DEFAULT;
	const char *provisional_name = NULL;

	out->verdict = UFW_VERDICT_DROP;
	out->stage = UFW_STAGE_PACKET;
	out->rule_id = UFW_RULE_ID_NO_POLICY;
	out->rule_name = "no-policy";
	out->logged = 1;

	rcu_read_lock();
	table = rcu_dereference(ufw_policy);
	if (!table) {
		/* Loaded, hooked, and holding no policy. Dropping is the only
		 * honest verdict: the module is either starting up or its
		 * daemon died, and neither is a reason to stop filtering. */
		rcu_read_unlock();
		return;
	}

	for (stage = 0; stage < UFW_STAGE__COUNT; stage++) {
		__u32 i;
		__u32 begin = table->stage_start[stage];
		__u32 end = table->stage_start[stage + 1];

		for (i = begin; i < end && i < table->rule_count; i++) {
			const struct ufw_rule *rule = &table->rules[i];
			__u8 action;

			if (!ufw_rule_matches(rule, facts))
				continue;

			action = effective_action(rule);

			switch (action) {
			case UFW_ACTION_ALLOW:
				out->verdict = UFW_VERDICT_PASS;
				out->stage = stage;
				out->rule_id = rule->id;
				out->rule_name = rule->name;
				out->logged = !!(rule->flags & UFW_FLAG_LOG);
				rcu_read_unlock();
				return;

			case UFW_ACTION_DENY:
				out->verdict = UFW_VERDICT_DROP;
				out->stage = stage;
				out->rule_id = rule->id;
				out->rule_name = rule->name;
				out->logged = !!(rule->flags & UFW_FLAG_LOG);
				rcu_read_unlock();
				return;

			case UFW_ACTION_ALLOW_INSPECT:
				/*
				 * A provisional permit. Remember it and keep
				 * going: a later stage may still deny, which
				 * is the entire point. Only the first one is
				 * recorded, so the log names the rule that
				 * actually granted the permit rather than the
				 * last one that would have.
				 */
				if (!provisional_allow) {
					provisional_allow = true;
					provisional_rule = rule->id;
					provisional_name = rule->name;
				}
				break;

			case UFW_ACTION_ALERT:
				/* Not a verdict. Record it and continue; the
				 * log carries the alert even if a later rule
				 * decides the packet. */
				ufw_log_decision(facts, &(struct ufw_decision){
					.verdict = UFW_VERDICT_PASS,
					.stage = stage,
					.rule_id = rule->id,
					.rule_name = rule->name,
					.logged = 1,
				});
				break;

			case UFW_ACTION_CONTINUE:
			default:
				break;
			}
		}
	}

	if (provisional_allow) {
		out->verdict = UFW_VERDICT_PASS;
		out->rule_id = provisional_rule;
		out->rule_name = provisional_name;
		out->stage = UFW_STAGE_PACKET;
		out->logged = 1;
	} else {
		out->verdict = table->default_verdict;
		out->rule_id = UFW_RULE_ID_DEFAULT;
		out->rule_name = "policy-default";
		out->stage = UFW_STAGE_PACKET;
		out->logged = 1;
	}

	rcu_read_unlock();
}

/* --- fact extraction ----------------------------------------------------- */

int ufw_facts_from_skb(const struct sk_buff *skb, int hooknum,
		       const struct net_device *dev,
		       struct ufw_flow_facts *facts)
{
	memset(facts, 0, sizeof(*facts));

	facts->direction = ufw_hook_direction(hooknum);
	if (dev)
		strscpy(facts->ifname, dev->name, UFW_MAX_IFNAME);

	switch (ntohs(skb->protocol)) {
	case ETH_P_IP: {
		const struct iphdr *ip = ip_hdr(skb);

		if (!ip || skb->len < sizeof(*ip))
			return -EINVAL;

		facts->is_v6 = 0;
		facts->protocol = ip->protocol;
		memcpy(facts->src_addr, &ip->saddr, 4);
		memcpy(facts->dst_addr, &ip->daddr, 4);

		/*
		 * A fragment other than the first carries no transport header,
		 * so its ports are unknowable. Rather than classify it with
		 * port 0 — which would let a rule matching "port 0" decide it,
		 * and would let an attacker choose which rule applies by
		 * fragmenting — the packet is rejected here and the caller
		 * drops it. Reassembly happens in conntrack, before this hook,
		 * for anything the module is configured to see.
		 */
		if (ip_is_fragment(ip) && (ntohs(ip->frag_off) & IP_OFFSET))
			return -EINVAL;

		if (ip->protocol == IPPROTO_TCP) {
			const struct tcphdr *th = tcp_hdr(skb);

			if (!th)
				return -EINVAL;
			facts->src_port = ntohs(th->source);
			facts->dst_port = ntohs(th->dest);
		} else if (ip->protocol == IPPROTO_UDP) {
			const struct udphdr *uh = udp_hdr(skb);

			if (!uh)
				return -EINVAL;
			facts->src_port = ntohs(uh->source);
			facts->dst_port = ntohs(uh->dest);
		}
		break;
	}
	case ETH_P_IPV6: {
		const struct ipv6hdr *ip6 = ipv6_hdr(skb);

		if (!ip6 || skb->len < sizeof(*ip6))
			return -EINVAL;

		facts->is_v6 = 1;
		facts->protocol = ip6->nexthdr;
		memcpy(facts->src_addr, &ip6->saddr, 16);
		memcpy(facts->dst_addr, &ip6->daddr, 16);

		if (ip6->nexthdr == IPPROTO_TCP) {
			const struct tcphdr *th = tcp_hdr(skb);

			if (!th)
				return -EINVAL;
			facts->src_port = ntohs(th->source);
			facts->dst_port = ntohs(th->dest);
		} else if (ip6->nexthdr == IPPROTO_UDP) {
			const struct udphdr *uh = udp_hdr(skb);

			if (!uh)
				return -EINVAL;
			facts->src_port = ntohs(uh->source);
			facts->dst_port = ntohs(uh->dest);
		}
		break;
	}
	default:
		/* Not IP. The module hooks only the IP families, so reaching
		 * here means the stack handed us something unexpected. */
		return -EINVAL;
	}

	facts->src_zone = ufw_zone_of(facts->src_addr, facts->is_v6);
	facts->dst_zone = ufw_zone_of(facts->dst_addr, facts->is_v6);
	return 0;
}

/*
 * Unified Firewall — netfilter hook placement.
 *
 * # Where the hooks sit, and why
 *
 * The module registers at NF_INET_LOCAL_IN and NF_INET_LOCAL_OUT for both
 * address families, at priority NF_IP_PRI_FILTER - 10.
 *
 * LOCAL_IN and LOCAL_OUT rather than PRE_ROUTING and POST_ROUTING because
 * this is a *host* firewall. A packet that is merely being forwarded is not
 * this host's business, and hooking the routing path would silently turn the
 * module into a network firewall whose per-application rules can never match
 * — there is no local process behind a forwarded packet, so every identity
 * rule would fail closed and drop transit traffic. Choosing the local hooks
 * makes that impossibility structural rather than a documented caveat.
 *
 * Priority FILTER - 10 places the module just ahead of iptables' filter
 * table. Running before it means a policy decision is not silently pre-empted
 * by a rule some other tool installed, and an operator debugging "why was
 * this dropped" sees this module's verdict first. It does mean an existing
 * iptables ACCEPT cannot rescue traffic this module drops, which is correct:
 * the point of a policy compiled from one source is that it is the authority.
 *
 * # The ordering hazard this file exists to document
 *
 * tc ingress runs *before* netfilter on the inbound path, and *after* it on
 * the outbound path. The eBPF fast path therefore sees inbound packets the
 * netfilter hook has not seen yet, and outbound packets it already decided.
 *
 * That asymmetry is why the compiler's Linux backend gives the eBPF program
 * only the longest *prefix* of the rule table that is (a) inbound-relevant
 * and (b) expressible in L3/L4 fields — never an arbitrary subset. A prefix
 * is safe because a match inside it is provably the same match the complete
 * table would have produced: every rule that could have matched earlier is
 * also in the program. An arbitrary subset is not safe, because a rule the
 * program does not carry might have matched first, and the fast path would
 * return a verdict the full table disagrees with.
 *
 * Anything the fast path does not decide falls through to these hooks, which
 * evaluate the complete table. The fast path can therefore only ever be an
 * accelerator; it cannot change an outcome.
 */

#ifndef UFW_NETFILTER_HOOKS_H
#define UFW_NETFILTER_HOOKS_H

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

#include "policy_structs.h"

/* Just ahead of the filter table. See the note above. */
#define UFW_HOOK_PRIORITY (NF_IP_PRI_FILTER - 10)

/* Map a netfilter hook number onto a policy direction. */
static inline __u8 ufw_hook_direction(int hooknum)
{
	switch (hooknum) {
	case NF_INET_LOCAL_IN:
		return UFW_DIR_INBOUND;
	case NF_INET_LOCAL_OUT:
		return UFW_DIR_OUTBOUND;
	default:
		/* The module registers nowhere else. Returning ANY rather
		 * than guessing means a rule with an explicit direction
		 * cannot match a packet whose direction is unknown, which
		 * fails closed. */
		return UFW_DIR_ANY;
	}
}

/*
 * The network profile, as pushed by the daemon.
 *
 * Zone classification happens in the module rather than being precomputed
 * per rule because a zone is a property of an *address*, and the same rule
 * evaluates against different addresses on every packet.
 */
struct ufw_network_profile {
	struct ufw_cidr internal[UFW_MAX_CIDRS_PER_RULE];
	struct ufw_cidr perimeter[UFW_MAX_CIDRS_PER_RULE];
	__u8 internal_count;
	__u8 perimeter_count;
	__u8 _pad[2];
};

void ufw_profile_install(const struct ufw_network_profile *profile);

#endif /* UFW_NETFILTER_HOOKS_H */

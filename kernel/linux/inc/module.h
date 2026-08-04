/*
 * Unified Firewall — Linux kernel module, internal interfaces.
 *
 * The module is four cooperating pieces:
 *
 *   netfilter_hooks.c  where packets arrive
 *   classify.c         the decision, evaluated against the RCU-published table
 *   identity.c         which process owns this socket
 *   policy_sync.c      the netlink channel to the daemon
 *
 * plus stream_reassembly.c and dpi_engine.c behind the classifier, and
 * logging.c in front of the daemon.
 *
 * The invariant everything else is arranged around: a packet is never
 * blocked waiting for userspace. Identity resolution can miss, the daemon can
 * be slow, the log queue can be full — none of those may stall softirq
 * context. Where a fact is unavailable the classifier proceeds without it and
 * the policy's fail-closed semantics decide the rest.
 */

#ifndef UFW_MODULE_H
#define UFW_MODULE_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <net/sock.h>

#include "policy_structs.h"

#define UFW_MODULE_NAME "ufw"
#define UFW_MODULE_VERSION "0.1.0"

/* Netlink family name; must match ufw_shared::constants::LINUX_GENL_FAMILY. */
#define UFW_GENL_FAMILY "ufw_ctrl"
#define UFW_GENL_VERSION 1

/* --- counters ---------------------------------------------------------- */

/*
 * Per-CPU so the hot path never touches a shared cache line. Summed on
 * demand, which means a reader can observe a slightly inconsistent snapshot
 * across counters. That is the right trade: these are operational
 * indicators, and making them consistent would mean serialising every packet
 * against every other packet's accounting.
 */
struct ufw_stats {
	__u64 packets_seen;
	__u64 packets_allowed;
	__u64 packets_denied;
	__u64 flows_seen;
	__u64 flows_allowed;
	__u64 flows_denied;
	__u64 identity_cache_hits;
	__u64 identity_cache_misses;
	__u64 identity_queries_timed_out;
	__u64 dpi_scans;
	__u64 dpi_hits;
	__u64 reassembly_contexts;
	__u64 reassembly_truncated;
	__u64 conntrack_entries;
	__u64 log_events_dropped;
	__u64 ebpf_fastpath_decisions;
};

DECLARE_PER_CPU(struct ufw_stats, ufw_stats);

#define UFW_COUNT(field) \
	do { this_cpu_inc(ufw_stats.field); } while (0)

#define UFW_ADD(field, n) \
	do { this_cpu_add(ufw_stats.field, (n)); } while (0)

void ufw_stats_sum(struct ufw_stats *out);
void ufw_stats_reset(void);

/* --- enforcement mode -------------------------------------------------- */

enum ufw_mode {
	/* Decisions are enforced. */
	UFW_MODE_ENFORCE = 0,
	/* Decisions are computed and logged; every packet passes. For
	 * building the inventory a default-deny policy needs. */
	UFW_MODE_MONITOR = 1,
	/* Everything passes and nothing is evaluated. The escape hatch: a
	 * firewall that cannot be turned off during an outage gets turned off
	 * by uninstalling it, which loses the logs as well as the filtering. */
	UFW_MODE_EMERGENCY_ALLOW = 2,
};

enum ufw_mode ufw_get_mode(void);
void ufw_set_mode(enum ufw_mode mode);

/* --- policy table ------------------------------------------------------ */

/*
 * The published table. NULL until the daemon installs one.
 *
 * A NULL table is not "allow everything". ufw_classify() returns the
 * fail-closed verdict, which is DROP, because a module that is loaded and
 * hooked but has no policy is a module in the middle of starting up or one
 * whose daemon died, and neither is a reason to stop filtering.
 */
extern struct ufw_policy_table __rcu *ufw_policy;

/* Install a new table, returning the old one for the caller to free after a
 * grace period. Takes ownership of `table`. */
struct ufw_policy_table *ufw_policy_install(struct ufw_policy_table *table);

/* Allocate a table sized for `rule_count` rules. */
struct ufw_policy_table *ufw_policy_alloc(__u32 rule_count);
void ufw_policy_free(struct ufw_policy_table *table);

/* Recompute stage_start[] after the rules array is populated. The caller
 * must have sorted by (stage, priority, id) first; this validates that and
 * returns -EINVAL if not, because an unsorted table would silently evaluate
 * stages out of order. */
int ufw_policy_index(struct ufw_policy_table *table);

/* --- classification ---------------------------------------------------- */

/*
 * Evaluate the installed policy.
 *
 * Callable from softirq context. Never sleeps: an identity or DPI fact that
 * is not already available is simply absent, and absent facts do not match.
 *
 * `facts` is filled by the caller from the packet and, where available, the
 * socket. `out` is written on every call, including when no policy is
 * installed.
 */
void ufw_classify(const struct ufw_flow_facts *facts, struct ufw_decision *out);

/* Fill the L3/L4 half of `facts` from an skb. Returns 0 on success, -EINVAL
 * if the packet is too short or malformed to classify — which is itself a
 * drop, since an unparseable packet cannot be shown to be permitted. */
int ufw_facts_from_skb(const struct sk_buff *skb, int hooknum,
		       const struct net_device *dev,
		       struct ufw_flow_facts *facts);

/* Classify an address against the installed network profile. */
__u8 ufw_zone_of(const __u8 *addr, int is_v6);

/* --- identity ---------------------------------------------------------- */

/*
 * Fill the identity half of `facts` for a locally-owned socket.
 *
 * Returns 1 if identity was resolved from cache, 0 if it was not available.
 * Never blocks: a miss enqueues an asynchronous request to the daemon and
 * returns 0, so this packet is classified without identity while the *next*
 * packet of the same flow benefits.
 *
 * That asymmetry is visible in policy: the first packet of a connection can
 * be decided without knowing the process. For TCP this is nearly always
 * harmless, because the decision that matters is taken at connect() time
 * where the socket is available synchronously and the answer is usually
 * already cached from a previous connection by the same binary.
 *
 * For the first UDP datagram of a new flow it is genuinely visible: that
 * datagram is decided without identity, so an identity rule does not match it
 * and the policy's fail-closed default applies. The module does not hold it —
 * queueing packets in softirq context waiting on userspace is exactly what
 * this design exists to avoid. The mitigation is in policy: pair a UDP
 * identity rule with a packet-stage rule constraining the destination, so the
 * unidentified first datagram is still bounded by something. See identity.c.
 */
int ufw_identity_fill(const struct sock *sk, struct ufw_flow_facts *facts);

int ufw_identity_init(void);
void ufw_identity_exit(void);
void ufw_identity_flush(void);

/* Called by policy_sync when the daemon answers a pending query. The key is
 * the same (uid, socket cookie) pair the query carried; see identity.c for
 * why it is not a bare pid. */
void ufw_identity_deliver(__u32 pid, __u64 cookie, __u8 trust,
			  __u8 signature_valid, const char *path,
			  const char *signer, const __u8 *sha256);

/* Send an asynchronous resolution request. Returns immediately; the answer
 * arrives later through ufw_identity_deliver(). */
void ufw_identity_query_send(__u32 pid, __u64 cookie);

/* --- stream reassembly and DPI ----------------------------------------- */

int ufw_stream_init(void);
void ufw_stream_exit(void);
void ufw_stream_flush(void);

/*
 * Feed a packet's payload into the flow's reassembly context and run the
 * signature engine over whatever is now contiguous.
 *
 * Returns 1 if `facts->matched_signatures` was updated, 0 if there was
 * nothing new to scan. Sets `facts->dpi_truncated` when the context hit its
 * byte budget.
 */
int ufw_stream_observe(const struct sk_buff *skb, struct ufw_flow_facts *facts);

int ufw_dpi_init(void);
void ufw_dpi_exit(void);

/* Install the signature set received from the daemon. Takes ownership. */
int ufw_dpi_install(const __u8 *encoded, size_t len);

/* Identify the application protocol of a payload. Cheap prefix checks only;
 * a full parse happens in the per-protocol decoders. */
__u8 ufw_dpi_identify(const __u8 *data, size_t len, __u16 dst_port);

/* Run the signature set against a decoded payload. */
int ufw_dpi_scan(__u8 l7, const __u8 *data, size_t len,
		 __u32 *matched, __u8 max_matches, __u8 *truncated);

/* --- logging ----------------------------------------------------------- */

int ufw_log_init(void);
void ufw_log_exit(void);

/*
 * Queue a decision for delivery to the daemon.
 *
 * Bounded and lossy by design. When the queue is full the oldest event is
 * dropped and log_events_dropped is incremented; the alternative is
 * back-pressure reaching the packet path, which would let a stalled SIEM
 * collector stall the network stack. Losing the oldest rather than the
 * newest matters because the events that arrive during an incident are the
 * ones worth keeping.
 */
void ufw_log_decision(const struct ufw_flow_facts *facts,
		      const struct ufw_decision *decision);

void ufw_log_note(const char *fmt, ...);

/* --- netlink ----------------------------------------------------------- */

int ufw_policy_sync_init(void);
void ufw_policy_sync_exit(void);

/* Whether the daemon is currently connected. Drives the fail-closed
 * behaviour on identity misses: with no daemon there is nobody to ask, so
 * the module stops enqueueing queries rather than filling the queue. */
bool ufw_daemon_connected(void);

/* --- hooks ------------------------------------------------------------- */

int ufw_hooks_init(void);
void ufw_hooks_exit(void);

/* --- helpers ----------------------------------------------------------- */

/* Compare an address against a CIDR. Both in network byte order. */
bool ufw_cidr_contains(const struct ufw_cidr *cidr, const __u8 *addr, int is_v6);

/* Case-sensitive or case-insensitive glob with `*` and `?`. Bounded: the
 * implementation is iterative with a single backtrack point, so a pattern
 * like `*a*a*a*` cannot make it quadratic on attacker-chosen input. */
bool ufw_path_match(const char *pattern, const char *path, int case_insensitive);

#endif /* UFW_MODULE_H */

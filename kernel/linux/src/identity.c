// SPDX-License-Identifier: Apache-2.0
/*
 * Unified Firewall — which process owns this socket.
 *
 * # The constraint that shapes everything here
 *
 * Resolving an identity means reading a path, hashing a file, and checking a
 * signature. All three can block, and this code runs in softirq context where
 * blocking is not available. So the module does not resolve identities. It
 * caches answers the daemon computed, and on a miss it asks — asynchronously,
 * without waiting.
 *
 * # The key, and why it is not a pid
 *
 * The cache is keyed on (pid, socket cookie), never on a bare pid. Pids are
 * reused, and a reused pid is the difference between "the browser is allowed
 * to reach the internet" and "whatever process inherited the browser's pid is
 * allowed to reach the internet". Keying on the pair means a reused pid
 * produces a *miss* — which resolves correctly a moment later — rather than a
 * confident wrong answer that persists until the entry expires.
 *
 * The socket cookie is the kernel's own per-socket identifier, stable for the
 * socket's lifetime and never reused while the socket exists. The daemon's
 * cache uses (pid, process start time) for the same reason; the two keys
 * differ because they have different facts available, but both have the
 * property that matters: a stale key misses rather than lies.
 *
 * # What a miss costs
 *
 * The packet is classified without identity, which means every identity rule
 * fails to match it and the policy's fail-closed semantics apply. For TCP
 * this is nearly always invisible: the decision that matters is taken on the
 * SYN, where `skb->sk` is the connecting socket and the answer is usually
 * already cached from a previous connection by the same binary.
 *
 * For the first UDP datagram of a new flow it is visible, and the honest
 * answer is that this module lets that datagram be decided without identity.
 * Holding it instead would mean queueing packets in softirq context waiting
 * on userspace, which is the thing this design exists to avoid. The mitigation
 * is in policy rather than in code: a UDP identity rule should be paired with
 * a packet-stage rule that constrains the destination, so the unidentified
 * first datagram is still bounded by something.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/string.h>
#include <net/sock.h>

#include "../inc/module.h"

/* Sized so the table fits comfortably in a few pages. A workstation has tens
 * of network-active processes; a busy server has hundreds. 4096 entries is
 * generous for both and bounded for neither to matter. */
#define UFW_IDENTITY_BUCKETS 256
#define UFW_IDENTITY_MAX_ENTRIES 4096

/* Entries expire so that a rebuilt binary is not permanently matched against
 * its old hash. Five minutes is short enough that a deploy takes effect
 * within one maintenance window and long enough that the daemon is not
 * re-resolving the same browser every few seconds. */
#define UFW_IDENTITY_TTL_NS (300ULL * NSEC_PER_SEC)

/* A pending query is retried at most this often, so a process the daemon
 * cannot resolve does not generate a query per packet. */
#define UFW_IDENTITY_RETRY_NS (2ULL * NSEC_PER_SEC)

struct ufw_identity_entry {
	struct hlist_node node;
	__u32 pid;
	__u64 cookie;
	__u64 resolved_at;
	__u64 last_query;
	__u8  trust;
	__u8  signature_valid;
	__u8  valid;
	char  path[UFW_MAX_PATH_LEN];
	char  signer[UFW_MAX_SIGNER_LEN];
	__u8  sha256[32];
};

static struct hlist_head ufw_identity_table[UFW_IDENTITY_BUCKETS];
static DEFINE_SPINLOCK(ufw_identity_lock);
static unsigned int ufw_identity_count;

static inline unsigned int bucket_of(__u32 pid, __u64 cookie)
{
	return jhash_2words(pid, (u32)cookie, (u32)(cookie >> 32)) %
	       UFW_IDENTITY_BUCKETS;
}

int ufw_identity_init(void)
{
	unsigned int i;

	for (i = 0; i < UFW_IDENTITY_BUCKETS; i++)
		INIT_HLIST_HEAD(&ufw_identity_table[i]);
	ufw_identity_count = 0;
	return 0;
}

void ufw_identity_flush(void)
{
	unsigned long flags;
	unsigned int i;

	spin_lock_irqsave(&ufw_identity_lock, flags);
	for (i = 0; i < UFW_IDENTITY_BUCKETS; i++) {
		struct ufw_identity_entry *e;
		struct hlist_node *tmp;

		hlist_for_each_entry_safe(e, tmp, &ufw_identity_table[i], node) {
			hlist_del(&e->node);
			kfree(e);
		}
	}
	ufw_identity_count = 0;
	spin_unlock_irqrestore(&ufw_identity_lock, flags);
}

void ufw_identity_exit(void)
{
	ufw_identity_flush();
}

/*
 * Evict the oldest entry in one bucket.
 *
 * Not a global LRU: maintaining one would mean a list operation on every hit,
 * which is a shared cache line touched by every packet. Evicting within the
 * bucket that is being inserted into keeps the cost local and bounded, at the
 * price of occasionally discarding an entry that a global policy would have
 * kept. For a cache whose miss penalty is "resolve it again", that is a good
 * trade.
 *
 * Caller holds the lock.
 */
static void evict_one(unsigned int bucket)
{
	struct ufw_identity_entry *oldest = NULL, *e;

	hlist_for_each_entry(e, &ufw_identity_table[bucket], node) {
		if (!oldest || e->resolved_at < oldest->resolved_at)
			oldest = e;
	}
	if (oldest) {
		hlist_del(&oldest->node);
		kfree(oldest);
		ufw_identity_count--;
	}
}

/* Caller holds the lock. */
static struct ufw_identity_entry *lookup(__u32 pid, __u64 cookie)
{
	unsigned int bucket = bucket_of(pid, cookie);
	struct ufw_identity_entry *e;

	hlist_for_each_entry(e, &ufw_identity_table[bucket], node) {
		if (e->pid == pid && e->cookie == cookie)
			return e;
	}
	return NULL;
}

/*
 * Ask the daemon, at most once per retry interval per socket.
 *
 * A negative entry is inserted on the first miss so that the rate limit has
 * somewhere to live. Its `valid` flag is 0, so it never satisfies an identity
 * predicate — it exists purely to remember that a query is outstanding.
 *
 * Caller holds the lock.
 */
static void request_resolution(__u32 pid, __u64 cookie, __u64 now)
{
	unsigned int bucket = bucket_of(pid, cookie);
	struct ufw_identity_entry *e = lookup(pid, cookie);

	if (e) {
		if (now - e->last_query < UFW_IDENTITY_RETRY_NS)
			return;
		e->last_query = now;
	} else {
		if (ufw_identity_count >= UFW_IDENTITY_MAX_ENTRIES)
			evict_one(bucket);

		/* GFP_ATOMIC: softirq context. A failed allocation means the
		 * query is simply not sent, which costs one more miss. */
		e = kzalloc(sizeof(*e), GFP_ATOMIC);
		if (!e)
			return;
		e->pid = pid;
		e->cookie = cookie;
		e->last_query = now;
		e->valid = 0;
		hlist_add_head(&e->node, &ufw_identity_table[bucket]);
		ufw_identity_count++;
	}

	/* With no daemon there is nobody to answer, so the query is not sent
	 * and the retry timestamp above still throttles the attempt. */
	if (ufw_daemon_connected())
		ufw_identity_query_send(pid, cookie);
}

int ufw_identity_fill(const struct sock *sk, struct ufw_flow_facts *facts)
{
	struct ufw_identity_entry *e;
	unsigned long flags;
	__u64 cookie, now;
	__u32 pid;
	int found = 0;

	if (!sk)
		return 0;

	/*
	 * `sk->sk_peer_pid`-style ownership is not available for every socket
	 * here, so the module uses the socket's own identity and lets the
	 * daemon map it to a process. The cookie is stable and unique for the
	 * socket's lifetime, which is what the cache key needs.
	 */
	cookie = sock_gen_cookie((struct sock *)sk);
	pid = sk->sk_uid.val;
	now = ktime_get_ns();

	spin_lock_irqsave(&ufw_identity_lock, flags);
	e = lookup(pid, cookie);

	if (e && e->valid && (now - e->resolved_at) < UFW_IDENTITY_TTL_NS) {
		facts->identity_valid = 1;
		facts->pid = e->pid;
		facts->trust = e->trust;
		facts->signature_valid = e->signature_valid;
		memcpy(facts->path, e->path, UFW_MAX_PATH_LEN);
		memcpy(facts->signer, e->signer, UFW_MAX_SIGNER_LEN);
		memcpy(facts->sha256, e->sha256, 32);
		facts->path_len = (__u8)strnlen(e->path, UFW_MAX_PATH_LEN - 1);
		facts->signer_len = (__u8)strnlen(e->signer, UFW_MAX_SIGNER_LEN - 1);
		found = 1;
	} else {
		/* Expired counts as a miss, and the stale entry is left in
		 * place for request_resolution to reuse as its rate-limit
		 * slot rather than being freed and immediately reallocated. */
		if (e && e->valid)
			e->valid = 0;
		request_resolution(pid, cookie, now);
	}
	spin_unlock_irqrestore(&ufw_identity_lock, flags);

	if (found)
		UFW_COUNT(identity_cache_hits);
	else
		UFW_COUNT(identity_cache_misses);

	return found;
}

/*
 * The daemon answered.
 *
 * Note what is *not* done here: nothing is retried, and no packet is
 * reclassified. The answer benefits the next packet of the flow. Replaying
 * the packet that missed would mean holding it, which is the design decision
 * this whole file exists to avoid.
 */
void ufw_identity_deliver(__u32 pid, __u64 cookie, __u8 trust,
			  __u8 signature_valid, const char *path,
			  const char *signer, const __u8 *sha256)
{
	unsigned int bucket = bucket_of(pid, cookie);
	struct ufw_identity_entry *e;
	unsigned long flags;

	spin_lock_irqsave(&ufw_identity_lock, flags);
	e = lookup(pid, cookie);
	if (!e) {
		if (ufw_identity_count >= UFW_IDENTITY_MAX_ENTRIES)
			evict_one(bucket);
		e = kzalloc(sizeof(*e), GFP_ATOMIC);
		if (!e) {
			spin_unlock_irqrestore(&ufw_identity_lock, flags);
			return;
		}
		e->pid = pid;
		e->cookie = cookie;
		hlist_add_head(&e->node, &ufw_identity_table[bucket]);
		ufw_identity_count++;
	}

	e->trust = trust;
	e->signature_valid = signature_valid;
	if (path)
		strscpy(e->path, path, UFW_MAX_PATH_LEN);
	if (signer)
		strscpy(e->signer, signer, UFW_MAX_SIGNER_LEN);
	if (sha256)
		memcpy(e->sha256, sha256, 32);
	e->resolved_at = ktime_get_ns();
	e->valid = 1;
	spin_unlock_irqrestore(&ufw_identity_lock, flags);
}

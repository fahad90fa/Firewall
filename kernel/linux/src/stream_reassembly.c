// SPDX-License-Identifier: Apache-2.0
/*
 * Unified Firewall — stream reassembly.
 *
 * See inc/stream.h for why this exists, why it is bounded at 32 KiB, and why
 * truncation is reported rather than hidden. This file is the mechanics.
 *
 * The one design decision worth restating here: overlapping segments are
 * *discarded*, not applied. A TCP overlap attack works by sending two
 * segments covering the same sequence range with different bytes, relying on
 * the firewall and the endpoint resolving the overlap differently — the
 * firewall scans benign content, the endpoint receives the payload. There is
 * no resolution policy that is correct for every endpoint, because the
 * endpoints themselves disagree (Linux prefers the first copy, some others
 * the last). So this engine keeps the first copy of any byte it has already
 * seen and marks the context truncated if a later segment tries to rewrite
 * it, which turns "the firewall was fooled" into "the firewall said it could
 * not be sure".
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include "../inc/module.h"
#include "../inc/stream.h"
/* The placement arithmetic — the only part that indexes a buffer with an
 * attacker-influenced offset — lives here so a hosted fuzzer can reach it. */
#include "../inc/stream_place.h"
/* ufw_dpi_identify() is a header-only inline; include its definition. */
#include "../inc/dpi_decoders.h"

static struct hlist_head ufw_stream_table[UFW_STREAM_BUCKETS];
static DEFINE_SPINLOCK(ufw_stream_lock);
static unsigned int ufw_stream_count;

int ufw_stream_init(void)
{
	unsigned int i;

	for (i = 0; i < UFW_STREAM_BUCKETS; i++)
		INIT_HLIST_HEAD(&ufw_stream_table[i]);
	ufw_stream_count = 0;
	return 0;
}

void ufw_stream_flush(void)
{
	unsigned long flags;
	unsigned int i;

	spin_lock_irqsave(&ufw_stream_lock, flags);
	for (i = 0; i < UFW_STREAM_BUCKETS; i++) {
		struct ufw_stream_ctx *c;
		struct hlist_node *tmp;

		hlist_for_each_entry_safe(c, tmp, &ufw_stream_table[i], node) {
			hlist_del(&c->node);
			kvfree(c);
		}
	}
	ufw_stream_count = 0;
	spin_unlock_irqrestore(&ufw_stream_lock, flags);
}

void ufw_stream_exit(void)
{
	ufw_stream_flush();
}

/*
 * Build the flow key.
 *
 * Addresses are ordered so that both directions of a connection hash to the
 * same bucket — which keeps a conversation's two contexts adjacent and makes
 * expiry cheaper — while `direction` keeps them distinct entries.
 */
static void build_key(const struct ufw_flow_facts *facts,
		      struct ufw_stream_key *key)
{
	int flip;

	memset(key, 0, sizeof(*key));
	key->protocol = facts->protocol;
	key->is_v6 = facts->is_v6;
	key->direction = facts->direction;

	flip = memcmp(facts->src_addr, facts->dst_addr, 16) > 0;
	if (flip) {
		memcpy(key->addr_a, facts->dst_addr, 16);
		memcpy(key->addr_b, facts->src_addr, 16);
		key->port_a = facts->dst_port;
		key->port_b = facts->src_port;
	} else {
		memcpy(key->addr_a, facts->src_addr, 16);
		memcpy(key->addr_b, facts->dst_addr, 16);
		key->port_a = facts->src_port;
		key->port_b = facts->dst_port;
	}
}

static inline unsigned int bucket_of(const struct ufw_stream_key *key)
{
	return jhash(key, sizeof(*key), 0) % UFW_STREAM_BUCKETS;
}

/* Caller holds the lock. */
static struct ufw_stream_ctx *lookup(const struct ufw_stream_key *key)
{
	struct ufw_stream_ctx *c;

	hlist_for_each_entry(c, &ufw_stream_table[bucket_of(key)], node) {
		if (memcmp(&c->key, key, sizeof(*key)) == 0)
			return c;
	}
	return NULL;
}

/*
 * Reclaim contexts that have gone idle, and if none have, the oldest in the
 * bucket.
 *
 * Idle-first rather than pure LRU because a context that has not seen a
 * packet in 30 seconds has already shown the engine everything it is going
 * to: signatures are anchored near the start of a stream. Evicting an active
 * flow to make room for a new one loses inspection on a flow that is still
 * carrying data.
 *
 * Caller holds the lock.
 */
static void reclaim(unsigned int bucket, __u64 now)
{
	struct ufw_stream_ctx *c, *oldest = NULL;
	struct hlist_node *tmp;
	unsigned int i;

	for (i = 0; i < UFW_STREAM_BUCKETS; i++) {
		hlist_for_each_entry_safe(c, tmp, &ufw_stream_table[i], node) {
			if (now - c->last_seen > UFW_STREAM_IDLE_NS) {
				hlist_del(&c->node);
				kvfree(c);
				ufw_stream_count--;
			}
		}
		/* One bucket's worth of sweeping per allocation keeps this
		 * O(1) amortised instead of walking the whole table while
		 * holding a spinlock in softirq context. */
		if (i == 0 && ufw_stream_count < UFW_STREAM_MAX_CONTEXTS)
			return;
	}

	if (ufw_stream_count < UFW_STREAM_MAX_CONTEXTS)
		return;

	hlist_for_each_entry(c, &ufw_stream_table[bucket], node) {
		if (!oldest || c->last_seen < oldest->last_seen)
			oldest = c;
	}
	if (oldest) {
		hlist_del(&oldest->node);
		kvfree(oldest);
		ufw_stream_count--;
	}
}

/*
 * Place `len` bytes at `offset` within the context.
 *
 * Returns the number of *new* bytes accepted. Overlaps with already-present
 * data are discarded and mark the context truncated; see the file header.
 *
 * The arithmetic itself is `ufw_stream_place()` in stream_place.h, shared
 * verbatim with the fuzzer so what CI fuzzes is what ships. This wrapper adds
 * the two things placement has no business knowing about: the context struct it
 * writes through, and the per-CPU statistics counter. `trunc_events` carries
 * back how many times placement would have bumped `reassembly_truncated`, so
 * the counter reads exactly as it did before the extraction.
 *
 * Caller holds the lock.
 */
static __u32 place(struct ufw_stream_ctx *ctx, __u32 offset,
		   const __u8 *data, __u32 len)
{
	__u32 trunc_events = 0;
	__u32 accepted;

	accepted = ufw_stream_place(ctx->data, &ctx->len, &ctx->truncated,
				    UFW_STREAM_MAX_BYTES, offset, data, len,
				    &trunc_events);
	if (trunc_events)
		UFW_ADD(reassembly_truncated, trunc_events);
	return accepted;
}

int ufw_stream_observe(const struct sk_buff *skb,
		       struct ufw_flow_facts *facts)
{
	struct ufw_stream_key key;
	struct ufw_stream_ctx *ctx;
	unsigned long lock_flags;
	unsigned int bucket;
	const __u8 *payload = NULL;
	__u32 payload_len = 0, offset = 0, accepted;
	__u64 now = ktime_get_ns();
	__u8 truncated = 0, l7;
	int matched = 0;

	if (facts->protocol == IPPROTO_TCP) {
		const struct tcphdr *th = tcp_hdr(skb);
		unsigned int hlen;

		if (!th)
			return 0;
		hlen = th->doff * 4u;
		if (hlen < sizeof(*th))
			return 0;
		/* Validate before subtracting: a short or malformed frame can
		 * leave transport_offset + hlen past skb->len, which would
		 * underflow payload_len to a near-4 GiB value. The bound check
		 * below would still reject it, but not underflowing in the
		 * first place keeps the arithmetic locally correct. */
		if (skb->len < skb_transport_offset(skb) + hlen)
			return 0;
		payload = (const __u8 *)th + hlen;
		payload_len = skb->len - skb_transport_offset(skb) - hlen;
		offset = ntohl(th->seq);
	} else if (facts->protocol == IPPROTO_UDP) {
		const struct udphdr *uh = udp_hdr(skb);

		if (!uh)
			return 0;
		/* uh->len is attacker-chosen. A value below the 8-byte UDP
		 * header would underflow payload_len; reject it before the
		 * subtraction rather than leaning on the later bound check to
		 * catch the wrapped result. */
		if ((unsigned int)ntohs(uh->len) < sizeof(*uh))
			return 0;
		payload = (const __u8 *)uh + sizeof(*uh);
		payload_len = (unsigned int)ntohs(uh->len) - (unsigned int)sizeof(*uh);
		/* A datagram is self-contained: there is no sequence space,
		 * so each one is scanned on its own. Accumulating datagrams
		 * into a stream would fabricate boundaries that the receiving
		 * application never sees. */
		offset = 0;
	} else {
		return 0;
	}

	if (!payload || !payload_len || payload_len > skb->len)
		return 0;

	build_key(facts, &key);
	bucket = bucket_of(&key);

	spin_lock_irqsave(&ufw_stream_lock, lock_flags);
	ctx = lookup(&key);

	if (!ctx) {
		if (ufw_stream_count >= UFW_STREAM_MAX_CONTEXTS)
			reclaim(bucket, now);
		if (ufw_stream_count >= UFW_STREAM_MAX_CONTEXTS) {
			/* Still no room. The flow is not inspected, and the
			 * fact that it was not is what `dpi_truncated`
			 * communicates: silence here would look identical to
			 * a clean scan that found nothing. */
			spin_unlock_irqrestore(&ufw_stream_lock, lock_flags);
			facts->dpi_valid = 1;
			facts->dpi_truncated = 1;
			facts->matched_count = 0;
			return 0;
		}

		/* kvzalloc: the context is 32 KiB, which is past the
		 * comfortable kmalloc range and will fragment the slab under
		 * load. Falling back to vmalloc is fine because this is never
		 * DMA'd and never touched from a context that cannot fault on
		 * a vmalloc'd page. */
		ctx = kvzalloc(sizeof(*ctx), GFP_ATOMIC);
		if (!ctx) {
			spin_unlock_irqrestore(&ufw_stream_lock, lock_flags);
			return 0;
		}
		ctx->key = key;
		hlist_add_head(&ctx->node, &ufw_stream_table[bucket]);
		ufw_stream_count++;
		UFW_COUNT(reassembly_contexts);
	}

	ctx->last_seen = now;

	if (facts->protocol == IPPROTO_TCP) {
		/* Normalize the raw sequence number to a buffer offset (and zero
		 * payload_len for a segment past the budget). Shared with the
		 * fuzzer via stream_place.h; unsigned wraparound is intentional,
		 * because TCP sequence numbers wrap and the distance is what
		 * indexes the buffer. */
		offset = ufw_stream_seq_offset(offset, &ctx->base_seq,
					       &ctx->seq_valid, &ctx->truncated,
					       ctx->len, UFW_STREAM_MAX_BYTES,
					       &payload_len);
	} else {
		/* Each datagram is scanned alone. */
		ctx->len = 0;
		ctx->truncated = 0;
		offset = 0;
	}

	accepted = payload_len ? place(ctx, offset, payload, payload_len) : 0;
	truncated = ctx->truncated;

	if (!ctx->l7 && ctx->len)
		ctx->l7 = ufw_dpi_identify(ctx->data, ctx->len, facts->dst_port);
	l7 = ctx->l7;

	if (accepted) {
		UFW_COUNT(dpi_scans);
		matched = ufw_dpi_scan(l7, ctx->data, ctx->len,
				       facts->matched_signatures,
				       UFW_MAX_SIGNATURES_PER_RULE,
				       &truncated);
		if (matched > 0) {
			facts->matched_count = (__u8)matched;
			UFW_ADD(dpi_hits, matched);
		} else {
			facts->matched_count = 0;
		}
	}
	spin_unlock_irqrestore(&ufw_stream_lock, lock_flags);

	facts->l7 = l7;
	facts->dpi_valid = 1;
	facts->dpi_truncated = truncated;
	return matched > 0;
}

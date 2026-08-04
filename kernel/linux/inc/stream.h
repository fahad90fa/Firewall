/*
 * Unified Firewall — TCP stream reassembly and its budget.
 *
 * # Why reassemble at all
 *
 * A signature that matches "POST /admin" does not match a stream where the
 * client sent "POST /ad" and "min" in two segments. An attacker who knows a
 * firewall matches per-packet only has to split the pattern, which costs them
 * nothing and defeats the signature entirely. Per-packet matching on a stream
 * protocol is not a weaker version of inspection; it is inspection that an
 * adversary can trivially turn off.
 *
 * # Why it is bounded, and bounded low
 *
 * Reassembly means holding attacker-controlled bytes in kernel memory,
 * indexed by an attacker-chosen flow key. Unbounded, that is a remote memory
 * exhaustion primitive: open ten thousand connections, send one byte on each,
 * never close them.
 *
 * So every context has a byte budget and every context has a deadline, and
 * the total number of contexts is capped. When any limit is hit the context
 * is marked *truncated* rather than silently dropped, and the truncation
 * travels with the scan result. That distinction is the whole point:
 *
 *   - A rule that DENIES on a signature treats a truncated miss as a
 *     non-match, because it did not see a match. But the log says the scan
 *     was truncated, so "no signature fired" is distinguishable from "we
 *     stopped looking".
 *   - A rule that ALERTS reports the truncation itself, because "we could
 *     not finish inspecting this flow" is a finding, not a non-event.
 *
 * The budget is 32 KiB, which is not chosen by Linux. It is the macOS
 * Network Extension's per-flow buffer, and matching it here is what keeps the
 * three platforms from disagreeing about whether a given signature fired. A
 * larger Linux budget would mean a signature that matches on Linux and
 * silently does not on macOS — an equivalence failure that no test would
 * catch, because it depends on stream length rather than on policy.
 */

#ifndef UFW_STREAM_H
#define UFW_STREAM_H

#include <linux/types.h>

#include "policy_structs.h"

/* Must equal ufw_shared::constants::STREAM_REASSEMBLY_MAX_BYTES_MACOS. See
 * the note above: this is a cross-platform equivalence constraint, not a
 * Linux memory decision. */
#define UFW_STREAM_MAX_BYTES (32u * 1024u)

/* Total contexts across all flows. At 32 KiB each this bounds reassembly
 * memory at 128 MiB, which is a lot — but the cap is on *contexts*, and most
 * carry far less than their budget. */
#define UFW_STREAM_MAX_CONTEXTS 4096

#define UFW_STREAM_BUCKETS 1024

/* A context with no traffic for this long is reclaimed. Short, because a
 * flow that has gone quiet has already shown the engine its interesting
 * prefix: signatures are anchored near the start of a stream precisely so
 * they resolve inside this window. */
#define UFW_STREAM_IDLE_NS (30ULL * NSEC_PER_SEC)

/* Flow key. Direction is part of it: a request and its response are two
 * streams with different content, and merging them would produce byte
 * sequences that never appeared on the wire — a source of both false
 * positives and, worse, false negatives where a pattern is split across the
 * boundary. */
struct ufw_stream_key {
	__u8  addr_a[16];
	__u8  addr_b[16];
	__u16 port_a;
	__u16 port_b;
	__u8  protocol;
	__u8  is_v6;
	__u8  direction;
	__u8  _pad;
};

struct ufw_stream_ctx {
	struct hlist_node node;
	struct ufw_stream_key key;
	__u64 last_seen;
	__u32 len;
	/* Set once the budget is reached. A truncated context stops
	 * accumulating but stays alive, so subsequent packets of the flow are
	 * still reported as truncated rather than looking like a fresh flow
	 * that has seen nothing. */
	__u8  truncated;
	__u8  l7;
	/* The first sequence number seen, so out-of-order segments can be
	 * placed rather than appended. Segments before this offset are
	 * discarded: a retransmission of already-scanned bytes is not new
	 * information, and accepting overlapping rewrites is how a TCP
	 * overlap attack makes the firewall and the endpoint see different
	 * streams. */
	__u32 base_seq;
	__u8  seq_valid;
	__u8  _pad;
	__u8  data[UFW_STREAM_MAX_BYTES];
};

#endif /* UFW_STREAM_H */

/*
 * Unified Firewall — Windows stream reassembly.
 *
 * The WFP stream layer already delivers in-order bytes, so this is not
 * reassembly in the Linux sense — there are no sequence numbers to place and
 * no overlaps to resolve. What it is is *accumulation*, and a budget.
 *
 * A signature that matches "POST /admin" does not match a stream where the
 * client sent "POST /ad" and "min" in two callbacks. Matching per callback is
 * not a weaker form of inspection; it is inspection an adversary can turn off
 * by choosing their write sizes. So the driver accumulates across callbacks.
 *
 * And accumulation means holding attacker-controlled bytes in non-paged pool,
 * keyed by an attacker-chosen flow. Unbounded, that is remote kernel memory
 * exhaustion: open ten thousand connections, send one byte on each, never
 * close them. Hence the budget, the context cap, and the idle sweep.
 *
 * The budget is 32 KiB, and it is not a Windows memory decision. It is the
 * macOS Network Extension's per-flow buffer, matched here so that the same
 * signature fires on all three platforms. A larger Windows budget would give
 * a signature that matches on Windows and silently does not on macOS — an
 * equivalence failure that depends on stream length rather than on policy, so
 * no policy test would catch it.
 */

#pragma once

#include "driver.h"

/* Must equal ufw_shared::constants::STREAM_REASSEMBLY_MAX_BYTES_MACOS. This
 * is a cross-platform equivalence constraint; see the header comment. */
#define UFW_STREAM_MAX_BYTES (32u * 1024u)

#define UFW_STREAM_MAX_CONTEXTS 4096
#define UFW_STREAM_BUCKETS 512

/* 30 seconds. A flow that has gone quiet has already shown the engine its
 * interesting prefix — signatures are anchored near the start of a stream
 * precisely so they resolve inside this window. */
#define UFW_STREAM_IDLE_100NS (30LL * 10000000LL)

typedef struct _UFW_STREAM_CONTEXT {
	LIST_ENTRY link;
	UINT64 flowId;
	LARGE_INTEGER lastSeen;
	UINT32 length;
	/* Set once the budget is reached. A truncated context stops growing
	 * but stays alive, so later callbacks are still reported as truncated
	 * rather than looking like a fresh flow that has seen nothing. */
	UINT8  truncated;
	UINT8  l7;
	UINT8  reserved[2];
	UINT8  data[UFW_STREAM_MAX_BYTES];
} UFW_STREAM_CONTEXT;

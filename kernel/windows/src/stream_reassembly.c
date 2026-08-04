/*
 * Unified Firewall — stream accumulation and its budget.
 *
 * See inc/stream_reassembly.h for why this exists and why the budget is what
 * it is. This file is the mechanics.
 */

#include "../inc/driver.h"
#include "../inc/stream_reassembly.h"

static LIST_ENTRY g_streamBuckets[UFW_STREAM_BUCKETS];
static KSPIN_LOCK g_streamLock;
static UINT32 g_streamCount;

static UINT32 UfwStreamBucket(_In_ UINT64 flowId)
{
	/* Fibonacci hashing: the flow handle's low bits are allocation-order
	 * sequential, so masking them directly would cluster every concurrent
	 * flow into a handful of buckets. */
	return (UINT32)((flowId * 11400714819323198485ULL) >> 55) %
	       UFW_STREAM_BUCKETS;
}

NTSTATUS UfwStreamInitialize(VOID)
{
	UINT32 i;

	KeInitializeSpinLock(&g_streamLock);
	for (i = 0; i < UFW_STREAM_BUCKETS; i++)
		InitializeListHead(&g_streamBuckets[i]);
	g_streamCount = 0;
	return STATUS_SUCCESS;
}

VOID UfwStreamFlush(VOID)
{
	KLOCK_QUEUE_HANDLE lock;
	UINT32 i;

	KeAcquireInStackQueuedSpinLock(&g_streamLock, &lock);
	for (i = 0; i < UFW_STREAM_BUCKETS; i++) {
		while (!IsListEmpty(&g_streamBuckets[i])) {
			PLIST_ENTRY entry = RemoveHeadList(&g_streamBuckets[i]);
			UFW_STREAM_CONTEXT *ctx =
				CONTAINING_RECORD(entry, UFW_STREAM_CONTEXT, link);

			ExFreePoolWithTag(ctx, UFW_POOL_TAG);
		}
	}
	g_streamCount = 0;
	KeReleaseInStackQueuedSpinLock(&lock);
}

VOID UfwStreamShutdown(VOID)
{
	UfwStreamFlush();
}

/* Caller holds the lock. */
static UFW_STREAM_CONTEXT *UfwStreamLookup(_In_ UINT64 flowId)
{
	PLIST_ENTRY head = &g_streamBuckets[UfwStreamBucket(flowId)];
	PLIST_ENTRY entry;

	for (entry = head->Flink; entry != head; entry = entry->Flink) {
		UFW_STREAM_CONTEXT *ctx =
			CONTAINING_RECORD(entry, UFW_STREAM_CONTEXT, link);

		if (ctx->flowId == flowId)
			return ctx;
	}
	return NULL;
}

/*
 * Reclaim idle contexts, and failing that the oldest in one bucket.
 *
 * Idle-first rather than pure LRU: a context that has not seen a callback in
 * 30 seconds has already shown the engine everything it is going to, whereas
 * evicting an active flow loses inspection on a flow still carrying data.
 *
 * Only one bucket is swept per call. Walking all 512 while holding a spin
 * lock at DISPATCH_LEVEL would stall every processor classifying a stream.
 *
 * Caller holds the lock.
 */
static VOID UfwStreamReclaim(_In_ UINT32 bucket, _In_ LARGE_INTEGER now)
{
	PLIST_ENTRY head = &g_streamBuckets[bucket];
	PLIST_ENTRY entry = head->Flink;
	UFW_STREAM_CONTEXT *oldest = NULL;

	while (entry != head) {
		UFW_STREAM_CONTEXT *ctx =
			CONTAINING_RECORD(entry, UFW_STREAM_CONTEXT, link);
		PLIST_ENTRY next = entry->Flink;

		if (now.QuadPart - ctx->lastSeen.QuadPart > UFW_STREAM_IDLE_100NS) {
			RemoveEntryList(entry);
			ExFreePoolWithTag(ctx, UFW_POOL_TAG);
			g_streamCount--;
		} else if (!oldest || ctx->lastSeen.QuadPart < oldest->lastSeen.QuadPart) {
			oldest = ctx;
		}
		entry = next;
	}

	if (g_streamCount >= UFW_STREAM_MAX_CONTEXTS && oldest) {
		RemoveEntryList(&oldest->link);
		ExFreePoolWithTag(oldest, UFW_POOL_TAG);
		g_streamCount--;
	}
}

VOID UfwStreamRelease(_In_ UINT64 flowId)
{
	KLOCK_QUEUE_HANDLE lock;
	UFW_STREAM_CONTEXT *ctx;

	KeAcquireInStackQueuedSpinLock(&g_streamLock, &lock);
	ctx = UfwStreamLookup(flowId);
	if (ctx) {
		RemoveEntryList(&ctx->link);
		g_streamCount--;
	}
	KeReleaseInStackQueuedSpinLock(&lock);

	if (ctx)
		ExFreePoolWithTag(ctx, UFW_POOL_TAG);
}

NTSTATUS UfwStreamObserve(_In_ UINT64 flowId,
			  _In_reads_bytes_(length) const UINT8 *data,
			  _In_ SIZE_T length,
			  _Inout_ UFW_FLOW_FACTS *facts)
{
	KLOCK_QUEUE_HANDLE lock;
	UFW_STREAM_CONTEXT *ctx;
	LARGE_INTEGER now;
	UINT32 bucket = UfwStreamBucket(flowId);
	UINT32 space;
	UINT8 truncated;
	UINT8 hits = 0;

	if (!data || !length)
		return STATUS_SUCCESS;

	KeQuerySystemTime(&now);

	KeAcquireInStackQueuedSpinLock(&g_streamLock, &lock);
	ctx = UfwStreamLookup(flowId);

	if (!ctx) {
		if (g_streamCount >= UFW_STREAM_MAX_CONTEXTS)
			UfwStreamReclaim(bucket, now);
		if (g_streamCount >= UFW_STREAM_MAX_CONTEXTS) {
			/* No room. The flow is not inspected, and saying so is
			 * what distinguishes it from a clean scan that found
			 * nothing. */
			KeReleaseInStackQueuedSpinLock(&lock);
			facts->dpiValid = 1;
			facts->dpiTruncated = 1;
			facts->matchedCount = 0;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		ctx = (UFW_STREAM_CONTEXT *)ExAllocatePool2(
			POOL_FLAG_NON_PAGED, sizeof(*ctx), UFW_POOL_TAG);
		if (!ctx) {
			KeReleaseInStackQueuedSpinLock(&lock);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		RtlZeroMemory(ctx, sizeof(*ctx));
		ctx->flowId = flowId;
		InsertHeadList(&g_streamBuckets[bucket], &ctx->link);
		g_streamCount++;
		UFW_COUNT(reassemblyContexts);
	}

	ctx->lastSeen = now;

	space = UFW_STREAM_MAX_BYTES - ctx->length;
	if (length > space) {
		length = space;
		if (!ctx->truncated) {
			ctx->truncated = 1;
			UFW_COUNT(reassemblyTruncated);
		}
	}
	if (length) {
		RtlCopyMemory(ctx->data + ctx->length, data, length);
		ctx->length += (UINT32)length;
	}

	if (!ctx->l7 && ctx->length)
		ctx->l7 = UfwDpiIdentify(ctx->data, ctx->length, facts->dstPort);

	truncated = ctx->truncated;
	if (length) {
		UFW_COUNT(dpiScans);
		hits = UfwDpiScan(ctx->l7, ctx->data, ctx->length,
				  facts->matchedSignatures,
				  UFW_MAX_SIGNATURES_PER_RULE, &truncated);
		facts->matchedCount = hits;
		if (hits)
			UFW_ADD(dpiHits, hits);
	}
	facts->l7 = ctx->l7;
	KeReleaseInStackQueuedSpinLock(&lock);

	facts->dpiValid = 1;
	facts->dpiTruncated = truncated;
	return STATUS_SUCCESS;
}

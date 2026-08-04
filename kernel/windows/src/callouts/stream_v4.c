/*
 * Unified Firewall — FWPM_LAYER_STREAM_V4.
 *
 * The stream layer does not authorise. ALE already permitted this flow; this
 * callout observes the reassembled bytes and can terminate a flow the payload
 * condemns. That asymmetry is exactly what `action: allow-inspect` means in
 * the policy language: permitted provisionally, still killable.
 *
 * # Why WFP's own reassembly is not enough
 *
 * The stream layer hands over in-order bytes, which is most of the work. What
 * it does not do is bound how many of them the driver keeps: a signature that
 * needs to match across segment boundaries needs a buffer, and the buffer has
 * to have a limit or a thousand idle connections become a memory exhaustion
 * primitive. UfwStreamObserve holds that buffer and that limit.
 *
 * # Why the budget is 32 KiB and not more
 *
 * Because the macOS Network Extension's per-flow buffer is 32 KiB, and a
 * larger Windows budget would mean a signature that fires on Windows and
 * silently does not on macOS. That is an equivalence failure which depends on
 * stream length rather than on policy, so no policy test would ever catch it.
 * The constraint is cross-platform, not a Windows memory decision.
 *
 * # Permitting the bytes we could not inspect
 *
 * When reassembly is truncated the flow is *not* blocked on that basis alone.
 * A truncated scan means "we stopped looking", not "we found nothing", and
 * blocking on it would make every long-lived connection fail once it exceeded
 * the budget. The truncation travels into the log instead, where a rule that
 * alerts reports it and an analyst can see inspection was incomplete.
 */

#include "../../inc/callout.h"

VOID NTAPI UfwStreamClassifyFn(
	_In_ const FWPS_INCOMING_VALUES *inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
	_Inout_opt_ VOID *layerData,
	_In_opt_ const VOID *classifyContext,
	_In_ const FWPS_FILTER *filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT *classifyOut)
{
	FWPS_STREAM_CALLOUT_IO_PACKET *packet =
		(FWPS_STREAM_CALLOUT_IO_PACKET *)layerData;
	FWPS_STREAM_DATA *stream;
	UFW_FLOW_FACTS facts;
	UFW_DECISION decision;
	UINT8 scratch[2048];
	SIZE_T copied;

	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(filter);

	if (!packet || !packet->streamData) {
		classifyOut->actionType = FWP_ACTION_CONTINUE;
		return;
	}
	stream = packet->streamData;

	packet->countBytesRequired = 0;
	packet->streamAction = FWPS_STREAM_ACTION_NONE;

	UfwFactsFromClassify(inFixedValues, inMetaValues,
			     (stream->flags & FWPS_STREAM_FLAG_RECEIVE)
				     ? UFW_DIR_INBOUND : UFW_DIR_OUTBOUND,
			     &facts);
	facts.flowId = flowContext;
	facts.protocol = IPPROTO_TCP;

	/*
	 * Copy a bounded slice out of the MDL chain rather than mapping the
	 * whole thing. The reassembly context accumulates across calls, so
	 * this only has to be large enough that a single callback is not
	 * artificially split; the real budget lives in UfwStreamObserve.
	 */
	copied = min(stream->dataLength, sizeof(scratch));
	if (copied) {
		FwpsCopyStreamDataToBuffer(stream, scratch, copied, &copied);
		UfwStreamObserve(flowContext, scratch, copied, &facts);
	}

	/* Identity was resolved at ALE for this flow and is cached against the
	 * process, so a stream-stage rule can still test it. */
	UfwIdentityFill(facts.processId, &facts);

	UfwClassify(&facts, UFW_SCOPE_CONNECTION_ORIENTED, &decision);

	if (decision.logged)
		UfwLogDecision(&facts, &decision);

	if (decision.action == FWP_ACTION_BLOCK &&
	    InterlockedCompareExchange(&g_ufw.mode, 0, 0) == UFW_MODE_ENFORCE) {
		/*
		 * Terminate rather than drop. A silently dropped stream leaves
		 * the application waiting on a connection that will never
		 * answer, which presents to a user as a hang and to an
		 * operator as "the network is slow". A reset is unambiguous.
		 */
		UFW_COUNT(flowsDenied);
		packet->streamAction = FWPS_STREAM_ACTION_DROP_CONNECTION;
		classifyOut->actionType = FWP_ACTION_BLOCK;
		classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
		return;
	}

	/* Not this layer's decision: ALE permitted the flow and nothing in the
	 * payload has changed that. */
	classifyOut->actionType = FWP_ACTION_CONTINUE;
}

NTSTATUS NTAPI UfwStreamNotifyFn(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID *filterKey,
	_Inout_ FWPS_FILTER *filter)
{
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);
	return STATUS_SUCCESS;
}

/*
 * Release the reassembly context when the flow ends.
 *
 * Without this, contexts would only be reclaimed by the idle sweep, and a host
 * churning short-lived connections would hold thousands of dead 32 KiB buffers
 * for the length of the timeout. The sweep still exists, because a flow can
 * also disappear without this notification arriving.
 */
VOID NTAPI UfwStreamFlowDeleteFn(_In_ UINT16 layerId, _In_ UINT32 calloutId,
				 _In_ UINT64 flowContext)
{
	UNREFERENCED_PARAMETER(layerId);
	UNREFERENCED_PARAMETER(calloutId);
	UfwStreamRelease(flowContext);
}

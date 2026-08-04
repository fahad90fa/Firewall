/*
 * Unified Firewall — ALE_AUTH_RECV_ACCEPT.
 *
 * The inbound counterpart of ale_connect.c: every inbound TCP connection and
 * inbound UDP flow is decided here, with the receiving process available.
 *
 * Note the address orientation. WFP calls the host's own address "local" and
 * the peer's "remote" at every ALE layer, regardless of direction. The policy
 * language speaks in source and destination, so for an inbound flow the
 * remote address is the *source* and the local address is the destination —
 * the reverse of what ale_connect.c does with the same field names.
 *
 * Getting this backwards produces a driver that works: every rule still
 * matches something, and inbound rules quietly match on the wrong end of the
 * connection. It is the single easiest mistake to make in this file and the
 * hardest to notice, which is why it has a comment rather than being left to
 * read as obvious.
 */

#include "../../inc/callout.h"

VOID NTAPI UfwAleRecvAcceptClassifyFn(
	_In_ const FWPS_INCOMING_VALUES *inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
	_Inout_opt_ VOID *layerData,
	_In_opt_ const VOID *classifyContext,
	_In_ const FWPS_FILTER *filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT *classifyOut)
{
	UFW_FLOW_FACTS facts;
	UFW_DECISION decision;
	BOOLEAN isV6;

	UNREFERENCED_PARAMETER(layerData);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);

	if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
		return;

	UFW_COUNT(flowsSeen);

	isV6 = (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6);
	UfwFactsFromClassify(inFixedValues, inMetaValues, UFW_DIR_INBOUND, &facts);
	facts.isV6 = (UINT8)isV6;

	if (isV6) {
		/* remote -> src, local -> dst. See the header comment. */
		RtlCopyMemory(facts.srcAddr,
			      inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS].value.byteArray16,
			      16);
		RtlCopyMemory(facts.dstAddr,
			      inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS].value.byteArray16,
			      16);
		facts.srcPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT].value.uint16;
		facts.dstPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT].value.uint16;
		facts.protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL].value.uint8;
	} else {
		UINT32 remote = RtlUlongByteSwap(
			inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS].value.uint32);
		UINT32 local = RtlUlongByteSwap(
			inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS].value.uint32);

		RtlCopyMemory(facts.srcAddr, &remote, 4);
		RtlCopyMemory(facts.dstAddr, &local, 4);
		facts.srcPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT].value.uint16;
		facts.dstPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT].value.uint16;
		facts.protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL].value.uint8;
	}

	facts.srcZone = UfwZoneOf(facts.srcAddr, isV6);
	facts.dstZone = UfwZoneOf(facts.dstAddr, isV6);

	/* The accepting process, which for an inbound flow is the listener.
	 * A rule like `application: sshd, direction: inbound` matches on this. */
	UfwIdentityFill(facts.processId, &facts);

	UfwClassify(&facts, UFW_SCOPE_CONNECTION_ORIENTED, &decision);

	if (decision.action == FWP_ACTION_BLOCK)
		UFW_COUNT(flowsDenied);
	else
		UFW_COUNT(flowsAllowed);

	if (decision.logged)
		UfwLogDecision(&facts, &decision);

	UfwApplyDecision(&decision, classifyOut);
}

NTSTATUS NTAPI UfwAleRecvAcceptNotifyFn(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID *filterKey,
	_Inout_ FWPS_FILTER *filter)
{
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);
	return STATUS_SUCCESS;
}

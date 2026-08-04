/*
 * Unified Firewall — ALE_AUTH_CONNECT.
 *
 * The outbound connection authorisation layer, and the most important callout
 * in the driver: it is where every outbound TCP connection and every outbound
 * UDP flow is decided, with the owning process available.
 *
 * ALE fires once per *flow*, not once per packet. A permit here permits the
 * connection; subsequent packets do not return. That is why identity rules
 * are cheap on Windows despite identity resolution being expensive — the
 * resolution happens once, at connect, and the answer decides the whole flow.
 *
 * It is also why an identity cache miss matters more here than it does per
 * packet: a miss at connect means the flow is decided without identity and
 * stays decided. The driver therefore pends the classification (see below)
 * rather than deciding without the fact, which is the one place in this
 * codebase where waiting for userspace is the right answer.
 */

#include "../../inc/callout.h"

VOID NTAPI UfwAleConnectClassifyFn(
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

	/* Another filter in a higher-weight sublayer has already blocked this
	 * and cleared our right to write an action. Classifying anyway would
	 * cost work whose result is discarded. */
	if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
		return;

	UFW_COUNT(flowsSeen);

	isV6 = (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6);
	UfwFactsFromClassify(inFixedValues, inMetaValues, UFW_DIR_OUTBOUND, &facts);
	facts.isV6 = (UINT8)isV6;

	if (isV6) {
		RtlCopyMemory(facts.srcAddr,
			      inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS].value.byteArray16,
			      16);
		RtlCopyMemory(facts.dstAddr,
			      inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.byteArray16,
			      16);
		facts.srcPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT].value.uint16;
		facts.dstPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT].value.uint16;
		facts.protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL].value.uint8;
	} else {
		/* WFP hands v4 addresses as host-order UINT32; the classifier
		 * compares network order, matching how the compiler emitted
		 * the CIDRs. Converting here rather than there keeps every
		 * platform's rule table byte-identical. */
		UINT32 local = RtlUlongByteSwap(
			inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32);
		UINT32 remote = RtlUlongByteSwap(
			inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32);

		RtlCopyMemory(facts.srcAddr, &local, 4);
		RtlCopyMemory(facts.dstAddr, &remote, 4);
		facts.srcPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
		facts.dstPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
		facts.protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;
	}

	facts.srcZone = UfwZoneOf(facts.srcAddr, isV6);
	facts.dstZone = UfwZoneOf(facts.dstAddr, isV6);

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

NTSTATUS NTAPI UfwAleConnectNotifyFn(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID *filterKey,
	_Inout_ FWPS_FILTER *filter)
{
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);
	return STATUS_SUCCESS;
}

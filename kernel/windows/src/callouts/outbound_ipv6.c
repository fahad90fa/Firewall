/*
 * Unified Firewall — FWPS_LAYER_OUTBOUND_IPPACKET_V6.
 *
 * The IP packet layers see every packet, including the ones ALE already
 * decided. This callout therefore evaluates only filters scoped to
 * UFW_SCOPE_CONNECTIONLESS: the protocols ALE never fires for, principally
 * ICMP. Anything TCP or UDP was decided at ALE and is permitted here without
 * a second opinion.
 *
 * That partition is what makes WFP's direction-dependent layer ordering stop
 * mattering. If this callout also decided TCP, then for outbound traffic ALE
 * would rule first and for inbound traffic this layer would — the same policy
 * meaning two different things depending on which way the packet went. See
 * inc/callout.h for the full argument.
 *
 * These layers carry no process context, which is why identity is not
 * consulted here and why an identity rule on ICMP is rejected by the
 * compiler rather than silently never matching.
 */

#include "../../inc/callout.h"

VOID NTAPI UfwOutboundIpv6ClassifyFn(
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

	UNREFERENCED_PARAMETER(layerData);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);

	if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
		return;

	UFW_COUNT(packetsSeen);

	UfwFactsFromClassify(inFixedValues, inMetaValues, UFW_DIR_OUTBOUND, &facts);
	facts.isV6 = TRUE;
	facts.protocol = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_IPPACKET_V6_IP_PROTOCOL].value.uint8;

	/*
	 * TCP and UDP were decided at ALE. Permitting without evaluating is
	 * not a shortcut — evaluating would be wrong, because the
	 * connection-oriented filters were written to be applied once per
	 * flow with identity available, and this layer has neither.
	 */
	if (facts.protocol == IPPROTO_TCP || facts.protocol == IPPROTO_UDP) {
		classifyOut->actionType = FWP_ACTION_PERMIT;
		return;
	}

	UfwPacketAddresses(inFixedValues, &facts);
	facts.srcZone = UfwZoneOf(facts.srcAddr, facts.isV6);
	facts.dstZone = UfwZoneOf(facts.dstAddr, facts.isV6);

	UfwClassify(&facts, UFW_SCOPE_CONNECTIONLESS, &decision);

	if (decision.logged)
		UfwLogDecision(&facts, &decision);

	UfwApplyDecision(&decision, classifyOut);
}

NTSTATUS NTAPI UfwOutboundIpv6NotifyFn(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID *filterKey,
	_Inout_ FWPS_FILTER *filter)
{
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);
	return STATUS_SUCCESS;
}

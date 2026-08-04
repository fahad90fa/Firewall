/*
 * Unified Firewall — reading addresses out of a WFP classify.
 *
 * WFP presents the same conceptual field at a different index in every layer,
 * with a different type, and — for IPv4 — in host byte order rather than
 * network order. This header is where that is dealt with once, because
 * spreading it across the callouts is how a v4 address ends up byte-swapped
 * in one layer and not another, which produces a driver where a /24 rule
 * matches an entirely different /24 depending on the direction of travel.
 *
 * The convention throughout the driver: addresses are stored network-byte-
 * order in UFW_FLOW_FACTS, IPv4 in the first four bytes, matching how the
 * compiler emits UFW_CIDR. That keeps the rule table byte-identical across
 * all three platforms, which is what lets one equivalence verifier check all
 * three.
 */

#pragma once

#include "driver.h"

/*
 * Fill srcAddr and dstAddr from an IP packet layer's fixed values.
 *
 * The IP packet layers use LOCAL/REMOTE naming like ALE does, so the source
 * and destination assignment depends on direction — which `facts->direction`
 * already carries by the time this is called.
 */
FORCEINLINE VOID UfwPacketAddresses(_In_ const FWPS_INCOMING_VALUES *inFixedValues,
				    _Inout_ UFW_FLOW_FACTS *facts)
{
	const FWPS_INCOMING_VALUE *values = inFixedValues->incomingValue;
	UINT8 local[16] = { 0 };
	UINT8 remote[16] = { 0 };

	switch (inFixedValues->layerId) {
	case FWPS_LAYER_INBOUND_IPPACKET_V4: {
		UINT32 l = RtlUlongByteSwap(
			values[FWPS_FIELD_INBOUND_IPPACKET_V4_IP_LOCAL_ADDRESS].value.uint32);
		UINT32 r = RtlUlongByteSwap(
			values[FWPS_FIELD_INBOUND_IPPACKET_V4_IP_REMOTE_ADDRESS].value.uint32);

		RtlCopyMemory(local, &l, 4);
		RtlCopyMemory(remote, &r, 4);
		break;
	}
	case FWPS_LAYER_OUTBOUND_IPPACKET_V4: {
		UINT32 l = RtlUlongByteSwap(
			values[FWPS_FIELD_OUTBOUND_IPPACKET_V4_IP_LOCAL_ADDRESS].value.uint32);
		UINT32 r = RtlUlongByteSwap(
			values[FWPS_FIELD_OUTBOUND_IPPACKET_V4_IP_REMOTE_ADDRESS].value.uint32);

		RtlCopyMemory(local, &l, 4);
		RtlCopyMemory(remote, &r, 4);
		break;
	}
	case FWPS_LAYER_INBOUND_IPPACKET_V6:
		RtlCopyMemory(local,
			      values[FWPS_FIELD_INBOUND_IPPACKET_V6_IP_LOCAL_ADDRESS].value.byteArray16,
			      16);
		RtlCopyMemory(remote,
			      values[FWPS_FIELD_INBOUND_IPPACKET_V6_IP_REMOTE_ADDRESS].value.byteArray16,
			      16);
		break;
	case FWPS_LAYER_OUTBOUND_IPPACKET_V6:
		RtlCopyMemory(local,
			      values[FWPS_FIELD_OUTBOUND_IPPACKET_V6_IP_LOCAL_ADDRESS].value.byteArray16,
			      16);
		RtlCopyMemory(remote,
			      values[FWPS_FIELD_OUTBOUND_IPPACKET_V6_IP_REMOTE_ADDRESS].value.byteArray16,
			      16);
		break;
	default:
		/* An unexpected layer. Leaving the addresses zeroed means
		 * every address-constrained rule fails to match, which sends
		 * the packet to the policy default — the fail-closed
		 * direction. Guessing would be worse. */
		return;
	}

	if (facts->direction == UFW_DIR_INBOUND) {
		RtlCopyMemory(facts->srcAddr, remote, 16);
		RtlCopyMemory(facts->dstAddr, local, 16);
	} else {
		RtlCopyMemory(facts->srcAddr, local, 16);
		RtlCopyMemory(facts->dstAddr, remote, 16);
	}
}

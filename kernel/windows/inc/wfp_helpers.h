/*
 * Unified Firewall — WFP engine helpers, and the weight scheme.
 *
 * # Filter weight
 *
 * WFP evaluates filters within a sublayer in *descending* weight order and
 * stops at the first one that produces a terminating action. The reference
 * implementation evaluates rules in *ascending* order of an evaluation key.
 * The bridge is:
 *
 *     weight = UINT64_MAX - evaluationOrderKey(rule)
 *
 * and the compiler emits exactly that, so `.weight` in the generated header
 * is already correct and nothing here recomputes it.
 *
 * The evaluation key is what matters:
 *
 *     key = (stage << 48) | (priority << 16) | (id & 0xFFFF)
 *
 * Stage above priority, and that ordering is the single most consequential
 * decision in this file. Priority orders rules *within* a stage; it does not
 * order the stages. A policy author who writes `priority: 10` on an identity
 * rule and `priority: 5000` on a packet rule gets the packet rule evaluated
 * first, because packet is an earlier stage — and if the Windows weights were
 * computed from priority alone, Windows would evaluate them the other way
 * round while every individual filter still looked correct. That is precisely
 * the kind of divergence the equivalence verifier exists to catch, and
 * precisely the kind that is invisible in review.
 *
 * The low 16 bits of the rule id break ties deterministically, so two rules
 * at the same stage and priority always evaluate in the same order on every
 * host — which matters because the *log* has to name the same rule everywhere.
 *
 * # Filter conditions
 *
 * The driver could install one WFP filter per rule with full conditions, and
 * let WFP do the matching. It does not. Every filter is installed with
 * conditions narrow enough to reach the right callout and no narrower, and
 * the actual matching happens in classify.c.
 *
 * The reason is equivalence. WFP's condition semantics are its own — how it
 * handles an absent field, how it orders multiple conditions on the same
 * field, what a v4-mapped v6 address matches — and reproducing them exactly
 * in the Linux module and the Swift extension would mean reverse-engineering
 * them and then depending on them not changing. Matching in our own code
 * means one decision procedure, three thin adapters, and a verifier that can
 * actually check the claim.
 *
 * What is lost is WFP's indexing: it can reject a non-matching filter without
 * calling us. What is gained is that "the three platforms agree" is a
 * statement about 400 lines of C that can be read side by side.
 */

#pragma once

#include "driver.h"

/* Sublayer weight. Deliberately high but below the maximum, so a deployment
 * that genuinely needs to override this firewall can install a sublayer above
 * it rather than having to uninstall it — and so that doing so is a visible,
 * deliberate act. */
#define UFW_SUBLAYER_WEIGHT 0xF000

/* Recompute the evaluation key, for asserting that a received table is sorted.
 * The compiler is the authority on weight; this is the check, not the source. */
FORCEINLINE UINT64 UfwEvaluationKey(_In_ const UFW_FILTER_SPEC *filter)
{
	return ((UINT64)filter->stage << 48) |
	       (((UINT64)filter->ruleId & 0xFFFFu));
}

FORCEINLINE UINT64 UfwWeightFromKey(_In_ UINT64 key)
{
	return MAXUINT64 - key;
}

/* Add a filter to the engine at a given layer, with the minimum conditions
 * needed to route the right traffic to the right callout. */
NTSTATUS UfwWfpAddFilter(_In_ HANDLE engine,
			 _In_ const GUID *layerKey,
			 _In_ const GUID *calloutKey,
			 _In_ const UFW_FILTER_SPEC *spec,
			 _Out_ UINT64 *filterId);

/* Map a policy stage onto the WFP layer family that should carry it. */
FORCEINLINE UFW_ENGINE UfwEngineForStage(_In_ UINT8 stage, _In_ UINT8 protocolScope)
{
	if (stage == UFW_STAGE_STREAM || stage == UFW_STAGE_APP_DPI)
		return UFW_ENGINE_WFP_STREAM;
	if (protocolScope == UFW_SCOPE_CONNECTIONLESS)
		return UFW_ENGINE_WFP_IPPACKET;
	return UFW_ENGINE_WFP_ALE;
}

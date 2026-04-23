"""The single before_tool_call async hook.

Three checks in order: identity → authorization → optional trust provider. First
failure returns a Deny carrying the reason, failed_check, and evidence (canonical
hash of whatever failed). All pass returns an Allow with the normalized context.
"""

from __future__ import annotations

from typing import Any

from .canonicalization import canonical_hash
from .delegation import DelegationChain, scope_covers, verify_chain
from .errors import Allow, Deny, DenyReason, GuardrailDecision
from .passport import Passport, verify_passport
from .trust_provider import TrustProvider, verify_trust_packet


async def governedToolCall(
    *,
    passport: Passport,
    delegation_chain: DelegationChain,
    tool_name: str,
    tool_args: dict[str, Any],
    principal_jwks: dict[str, Any],
    trust_provider: TrustProvider | None = None,
    min_trust_score: float | None = None,
) -> GuardrailDecision:
    """Run the three-check governance pipeline for a single tool call.

    Args:
        passport: Ed25519-signed binding of subject_did → public_key.
        delegation_chain: ordered list of DelegationHops from root to leaf.
        tool_name: the tool about to be called.
        tool_args: the arguments about to be passed.
        principal_jwks: JWKS of the root principal that issued the passport and
            rooted the delegation chain. Used for offline signature verification.
        trust_provider: optional TrustProvider. If supplied, its packet is fetched
            and verified. Its JWKS is fetched once and used for offline verify.
        min_trust_score: optional float in [0, 1]. If set and a trust_provider is
            supplied, packets below this score are denied. Ignored when no provider.

    Returns:
        Allow on all checks passing, Deny on first failure.
    """
    if not verify_passport(passport, principal_jwks):
        return Deny(
            reason=DenyReason.PASSPORT_SIGNATURE_INVALID,
            failed_check="identity",
            evidence=canonical_hash(passport.to_canonical_dict()),
        )

    if passport.subject_did != delegation_chain.subject_did():
        return Deny(
            reason=DenyReason.PASSPORT_KEY_MISMATCH,
            failed_check="identity",
            evidence=canonical_hash(passport.to_canonical_dict()),
        )

    if not verify_chain(delegation_chain, principal_jwks):
        return Deny(
            reason=DenyReason.DELEGATION_CHAIN_BROKEN,
            failed_check="authorization",
            evidence=canonical_hash(
                {"hops": [h.to_canonical_dict() for h in delegation_chain.hops]}
            ),
        )

    if not scope_covers(delegation_chain, tool_name, tool_args):
        return Deny(
            reason=DenyReason.SCOPE_DOES_NOT_COVER_TOOL,
            failed_check="authorization",
            evidence=canonical_hash(
                {
                    "leaf_scope": list(delegation_chain.leaf_scope()),
                    "tool_name": tool_name,
                }
            ),
        )

    trust_score: float | None = None
    if trust_provider is not None:
        try:
            packet = await trust_provider.fetch_trust_packet(passport.subject_did)
            jwks = await trust_provider.advertised_jwks()
        except Exception as exc:
            return Deny(
                reason=DenyReason.TRUST_PROVIDER_UNREACHABLE,
                failed_check="trust_provider",
                evidence=canonical_hash({"subject_did": passport.subject_did, "err": repr(exc)}),
            )

        if not verify_trust_packet(packet, jwks):
            return Deny(
                reason=DenyReason.TRUST_PACKET_SIGNATURE_INVALID,
                failed_check="trust_provider",
                evidence=canonical_hash(packet.to_canonical_dict()),
            )

        if min_trust_score is not None and packet.score < min_trust_score:
            return Deny(
                reason=DenyReason.TRUST_SCORE_BELOW_THRESHOLD,
                failed_check="trust_provider",
                evidence=canonical_hash({"subject_did": packet.subject_did, "score": packet.score}),
            )

        trust_score = packet.score

    return Allow(
        subject_did=passport.subject_did,
        tool_name=tool_name,
        effective_scope=delegation_chain.leaf_scope(),
        trust_score=trust_score,
    )

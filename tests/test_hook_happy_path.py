"""Full governedToolCall with a valid fixture: returns Allow."""

from __future__ import annotations

import pytest

from autogen_governance_adapter import governedToolCall
from autogen_governance_adapter.trust_provider import TrustPacket


class _StaticTrustProvider:
    """Deterministic in-memory trust provider for testing.

    Conforms structurally to the TrustProvider Protocol. Does not need to inherit.
    """

    def __init__(self, packet: TrustPacket, jwks: dict):
        self._packet = packet
        self._jwks = jwks

    async def fetch_trust_packet(self, subject_did: str) -> TrustPacket:
        return self._packet

    async def advertised_jwks(self) -> dict:
        return self._jwks


@pytest.mark.asyncio
async def test_happy_path_allows(happy_path):
    provider = _StaticTrustProvider(happy_path["trust_packet"], happy_path["provider_jwks"])
    decision = await governedToolCall(
        passport=happy_path["passport"],
        delegation_chain=happy_path["delegation_chain"],
        tool_name=happy_path["tool_name"],
        tool_args=happy_path["tool_args"],
        principal_jwks=happy_path["principal_jwks"],
        trust_provider=provider,
        min_trust_score=happy_path["min_trust_score"],
    )

    assert decision.kind == "allow"
    assert decision.subject_did == happy_path["passport"].subject_did
    assert decision.tool_name == happy_path["tool_name"]
    assert decision.trust_score == happy_path["trust_packet"].score


@pytest.mark.asyncio
async def test_happy_path_without_trust_provider_allows(happy_path):
    decision = await governedToolCall(
        passport=happy_path["passport"],
        delegation_chain=happy_path["delegation_chain"],
        tool_name=happy_path["tool_name"],
        tool_args=happy_path["tool_args"],
        principal_jwks=happy_path["principal_jwks"],
    )

    assert decision.kind == "allow"
    assert decision.trust_score is None

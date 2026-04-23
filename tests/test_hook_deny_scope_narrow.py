"""Deny when requested tool falls outside delegation scope.

Asserts the deny lands at the authorization step — trust provider is never consulted.
"""

from __future__ import annotations

import pytest

from autogen_governance_adapter import DenyReason, governedToolCall
from autogen_governance_adapter.trust_provider import TrustPacket


class _ShouldNeverBeCalledProvider:
    async def fetch_trust_packet(self, subject_did: str) -> TrustPacket:
        raise AssertionError("trust provider must not be consulted when authorization fails")

    async def advertised_jwks(self) -> dict:
        raise AssertionError("trust provider must not be consulted when authorization fails")


@pytest.mark.asyncio
async def test_deny_out_of_scope_tool(deny_scope_narrow):
    decision = await governedToolCall(
        passport=deny_scope_narrow["passport"],
        delegation_chain=deny_scope_narrow["delegation_chain"],
        tool_name=deny_scope_narrow["tool_name"],
        tool_args=deny_scope_narrow["tool_args"],
        principal_jwks=deny_scope_narrow["principal_jwks"],
        trust_provider=_ShouldNeverBeCalledProvider(),
        min_trust_score=0.9,
    )

    assert decision.kind == "deny"
    assert decision.failed_check == "authorization"
    assert decision.reason == DenyReason.SCOPE_DOES_NOT_COVER_TOOL
    assert decision.evidence, "deny must carry non-empty evidence hash"

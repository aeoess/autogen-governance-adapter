"""Delegation chain: valid chain, scope widening rejected, wrong signature rejected, scope match."""

from __future__ import annotations

from dataclasses import replace

from autogen_governance_adapter.delegation import (
    DelegationChain,
    scope_covers,
    verify_chain,
)


def test_valid_chain_verifies(happy_path):
    assert verify_chain(happy_path["delegation_chain"], happy_path["principal_jwks"]) is True


def test_scope_widening_attempt_rejected(scope_widening_attempt):
    # Second hop tries to widen scope beyond parent. Must fail.
    assert (
        verify_chain(
            scope_widening_attempt["delegation_chain"],
            scope_widening_attempt["principal_jwks"],
        )
        is False
    )


def test_chain_with_tampered_hop_signature_fails(happy_path):
    hop = happy_path["delegation_chain"].hops[0]
    tampered_sig = bytearray(hop.signature)
    tampered_sig[0] ^= 0x01
    tampered_hop = replace(hop, signature=bytes(tampered_sig))
    tampered_chain = DelegationChain(hops=(tampered_hop,))
    assert verify_chain(tampered_chain, happy_path["principal_jwks"]) is False


def test_scope_covers_matching_tool(happy_path):
    assert (
        scope_covers(
            happy_path["delegation_chain"],
            happy_path["tool_name"],
            happy_path["tool_args"],
        )
        is True
    )


def test_scope_does_not_cover_out_of_scope_tool(deny_scope_narrow):
    assert (
        scope_covers(
            deny_scope_narrow["delegation_chain"],
            deny_scope_narrow["tool_name"],
            deny_scope_narrow["tool_args"],
        )
        is False
    )

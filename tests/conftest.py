"""Shared pytest fixtures: load JSON fixtures into typed dataclasses."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from autogen_governance_adapter.delegation import DelegationChain
from autogen_governance_adapter.passport import Passport
from autogen_governance_adapter.trust_provider import TrustPacket

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def happy_path() -> dict:
    raw = _load("happy_path.json")
    return {
        "principal_jwks": raw["principal_jwks"],
        "provider_jwks": raw["provider_jwks"],
        "passport": Passport.from_dict(raw["passport"]),
        "delegation_chain": DelegationChain.from_list(raw["delegation_chain"]),
        "trust_packet": TrustPacket.from_dict(raw["trust_packet"]),
        "tool_name": raw["tool_name"],
        "tool_args": raw["tool_args"],
        "min_trust_score": raw["min_trust_score"],
    }


@pytest.fixture
def deny_scope_narrow() -> dict:
    raw = _load("deny_scope_narrow.json")
    return {
        "principal_jwks": raw["principal_jwks"],
        "passport": Passport.from_dict(raw["passport"]),
        "delegation_chain": DelegationChain.from_list(raw["delegation_chain"]),
        "tool_name": raw["tool_name"],
        "tool_args": raw["tool_args"],
    }


@pytest.fixture
def scope_widening_attempt() -> dict:
    raw = _load("scope_widening_attempt.json")
    return {
        "principal_jwks": raw["principal_jwks"],
        "delegation_chain": DelegationChain.from_list(raw["delegation_chain"]),
    }

"""Regenerate test fixtures deterministically.

Run: python scripts/generate_fixtures.py

Writes:
- tests/fixtures/happy_path.json
- tests/fixtures/deny_scope_narrow.json

Keys are derived from fixed SHA-256 seeds so the fixtures are byte-identical
across runs. Dates are set far in the future (year 2099) so the validity-window
checks stay green without ever needing to edit this file.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import jcs
from nacl.signing import SigningKey


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _mkkey(seed: str) -> SigningKey:
    digest = hashlib.sha256(seed.encode()).digest()
    return SigningKey(digest)


def _canonical(obj: dict[str, Any]) -> bytes:
    stripped = {k: v for k, v in obj.items() if k != "signature"}
    return jcs.canonicalize(stripped)


def _sign(sk: SigningKey, obj: dict[str, Any]) -> str:
    sig = sk.sign(_canonical(obj)).signature
    return _b64u(sig)


NOT_BEFORE = "2020-01-01T00:00:00Z"
NOT_AFTER = "2099-12-31T23:59:59Z"


def _jwks_for(public_key: bytes, kid: str) -> dict[str, Any]:
    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": kid,
                "x": _b64u(public_key),
            }
        ]
    }


def _passport(principal_sk: SigningKey, subject_did: str, subject_pk: bytes) -> dict[str, Any]:
    principal_did = "did:aps:principal:test"
    passport = {
        "subject_did": subject_did,
        "public_key": _b64u(subject_pk),
        "issuer_did": principal_did,
        "issued_at": NOT_BEFORE,
        "not_after": NOT_AFTER,
    }
    passport["signature"] = _sign(principal_sk, passport)
    return passport


def _hop(
    delegator_sk: SigningKey,
    delegator_did: str,
    delegator_pk: bytes,
    delegate_did: str,
    delegate_pk: bytes,
    scope: list[str],
) -> dict[str, Any]:
    hop = {
        "delegator_did": delegator_did,
        "delegator_public_key": _b64u(delegator_pk),
        "delegate_did": delegate_did,
        "delegate_public_key": _b64u(delegate_pk),
        "scope": scope,
        "not_before": NOT_BEFORE,
        "not_after": NOT_AFTER,
    }
    hop["signature"] = _sign(delegator_sk, hop)
    return hop


def _trust_packet(
    provider_sk: SigningKey,
    provider_did: str,
    subject_did: str,
    score: float,
    context: str,
) -> dict[str, Any]:
    packet = {
        "subject_did": subject_did,
        "issuer_did": provider_did,
        "score": score,
        "context": context,
        "issued_at": NOT_BEFORE,
        "payload": _b64u(b""),
    }
    packet["signature"] = _sign(provider_sk, packet)
    return packet


def build_happy_path() -> dict[str, Any]:
    principal_sk = _mkkey("aps/principal/test-root")
    principal_pk = principal_sk.verify_key.encode()
    principal_did = "did:aps:principal:test"

    subject_sk = _mkkey("aps/subject/test-agent-1")
    subject_pk = subject_sk.verify_key.encode()
    subject_did = "did:aps:agent:alice"

    provider_sk = _mkkey("aps/trust-provider/test-moltbridge")
    provider_pk = provider_sk.verify_key.encode()
    provider_did = "did:aps:trust:moltbridge"

    passport = _passport(principal_sk, subject_did, subject_pk)
    chain = [
        _hop(
            delegator_sk=principal_sk,
            delegator_did=principal_did,
            delegator_pk=principal_pk,
            delegate_did=subject_did,
            delegate_pk=subject_pk,
            scope=["action:call", "resource:weather_api", "inference_substrate:approved_set_42"],
        )
    ]
    trust_packet = _trust_packet(
        provider_sk, provider_did, subject_did, 0.85, "behavioral_trust_v1"
    )

    return {
        "principal_jwks": _jwks_for(principal_pk, principal_did),
        "provider_jwks": _jwks_for(provider_pk, provider_did),
        "passport": passport,
        "delegation_chain": chain,
        "trust_packet": trust_packet,
        "tool_name": "weather_api",
        "tool_args": {"verb": "call", "city": "Vancouver"},
        "min_trust_score": 0.7,
    }


def build_deny_scope_narrow() -> dict[str, Any]:
    principal_sk = _mkkey("aps/principal/test-root")
    principal_pk = principal_sk.verify_key.encode()
    principal_did = "did:aps:principal:test"

    subject_sk = _mkkey("aps/subject/test-agent-2")
    subject_pk = subject_sk.verify_key.encode()
    subject_did = "did:aps:agent:bob"

    passport = _passport(principal_sk, subject_did, subject_pk)
    chain = [
        _hop(
            delegator_sk=principal_sk,
            delegator_did=principal_did,
            delegator_pk=principal_pk,
            delegate_did=subject_did,
            delegate_pk=subject_pk,
            scope=["action:call", "resource:weather_api"],
        )
    ]

    return {
        "principal_jwks": _jwks_for(principal_pk, principal_did),
        "passport": passport,
        "delegation_chain": chain,
        "tool_name": "email_send",
        "tool_args": {"verb": "call", "to": "bob@example.com"},
    }


def build_scope_widening_attempt() -> dict[str, Any]:
    """Second hop tries to widen scope beyond what the first hop granted. Must be rejected."""
    principal_sk = _mkkey("aps/principal/test-root")
    principal_pk = principal_sk.verify_key.encode()
    principal_did = "did:aps:principal:test"

    agent_sk = _mkkey("aps/subject/test-agent-3")
    agent_pk = agent_sk.verify_key.encode()
    agent_did = "did:aps:agent:carol"

    subagent_sk = _mkkey("aps/subject/test-subagent-3")
    subagent_pk = subagent_sk.verify_key.encode()
    subagent_did = "did:aps:agent:carol-sub"

    hop_narrow = _hop(
        delegator_sk=principal_sk,
        delegator_did=principal_did,
        delegator_pk=principal_pk,
        delegate_did=agent_did,
        delegate_pk=agent_pk,
        scope=["action:call", "resource:weather_api"],
    )
    hop_widened = _hop(
        delegator_sk=agent_sk,
        delegator_did=agent_did,
        delegator_pk=agent_pk,
        delegate_did=subagent_did,
        delegate_pk=subagent_pk,
        scope=["action:*", "resource:weather_api", "resource:email_send"],
    )

    return {
        "principal_jwks": _jwks_for(principal_pk, principal_did),
        "delegation_chain": [hop_narrow, hop_widened],
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    fixtures_dir = root / "tests" / "fixtures"
    fixtures_dir.mkdir(parents=True, exist_ok=True)

    (fixtures_dir / "happy_path.json").write_text(
        json.dumps(build_happy_path(), indent=2, sort_keys=True) + "\n"
    )
    (fixtures_dir / "deny_scope_narrow.json").write_text(
        json.dumps(build_deny_scope_narrow(), indent=2, sort_keys=True) + "\n"
    )
    (fixtures_dir / "scope_widening_attempt.json").write_text(
        json.dumps(build_scope_widening_attempt(), indent=2, sort_keys=True) + "\n"
    )
    print(f"wrote 3 fixtures to {fixtures_dir}")


if __name__ == "__main__":
    main()

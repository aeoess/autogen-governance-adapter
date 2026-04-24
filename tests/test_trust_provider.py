"""Trust packet verification: JWKS kid match is required."""

from __future__ import annotations

from dataclasses import replace

from autogen_governance_adapter.trust_provider import verify_trust_packet


def test_trust_packet_verifies_with_matching_kid(happy_path):
    assert verify_trust_packet(happy_path["trust_packet"], happy_path["provider_jwks"]) is True


def test_trust_packet_fails_when_kid_missing(happy_path):
    jwks = {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "did:aps:trust:someone-else",
                "x": happy_path["provider_jwks"]["keys"][0]["x"],
            }
        ]
    }
    assert verify_trust_packet(happy_path["trust_packet"], jwks) is False


def test_trust_packet_fails_when_kid_omitted(happy_path):
    jwks = {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": happy_path["provider_jwks"]["keys"][0]["x"],
            }
        ]
    }
    assert verify_trust_packet(happy_path["trust_packet"], jwks) is False


def test_trust_packet_rejects_tampered_signature(happy_path):
    packet = happy_path["trust_packet"]
    tampered = replace(
        packet, signature=packet.signature[:-1] + bytes([packet.signature[-1] ^ 0x01])
    )
    assert verify_trust_packet(tampered, happy_path["provider_jwks"]) is False

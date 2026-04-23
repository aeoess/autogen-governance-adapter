"""Passport signature verification: valid, invalid, expired."""

from __future__ import annotations

import base64
from dataclasses import replace

from autogen_governance_adapter.passport import verify_passport


def test_valid_passport_verifies(happy_path):
    assert verify_passport(happy_path["passport"], happy_path["principal_jwks"]) is True


def test_passport_with_tampered_signature_fails(happy_path):
    tampered_sig = bytearray(happy_path["passport"].signature)
    tampered_sig[0] ^= 0x01
    tampered = replace(happy_path["passport"], signature=bytes(tampered_sig))
    assert verify_passport(tampered, happy_path["principal_jwks"]) is False


def test_expired_passport_fails(happy_path):
    expired = replace(happy_path["passport"], not_after="2020-01-02T00:00:00Z")
    assert verify_passport(expired, happy_path["principal_jwks"]) is False


def test_passport_with_unknown_issuer_fails(happy_path):
    foreign_jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "did:aps:principal:test",
                "n": base64.urlsafe_b64encode(b"\x00" * 32).rstrip(b"=").decode(),
            }
        ]
    }
    assert verify_passport(happy_path["passport"], foreign_jwks) is False

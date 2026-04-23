"""Passport Ed25519 verification.

A Passport is an Ed25519-signed binding between a subject DID and its public key,
issued by a principal identified in the caller's JWKS. Verification is offline —
no network calls, no SDK imports.
"""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .canonicalization import canonicalize, strip_signature


def _b64d(s: str) -> bytes:
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _parse_rfc3339(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


@dataclass(frozen=True)
class Passport:
    subject_did: str
    public_key: bytes
    issuer_did: str
    issued_at: str
    not_after: str
    signature: bytes

    def to_canonical_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["public_key"] = base64.urlsafe_b64encode(self.public_key).rstrip(b"=").decode()
        d["signature"] = base64.urlsafe_b64encode(self.signature).rstrip(b"=").decode()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Passport:
        return cls(
            subject_did=d["subject_did"],
            public_key=_b64d(d["public_key"]),
            issuer_did=d["issuer_did"],
            issued_at=d["issued_at"],
            not_after=d["not_after"],
            signature=_b64d(d["signature"]),
        )


def _lookup_issuer_key(jwks: dict[str, Any], issuer_did: str) -> bytes | None:
    """Find the Ed25519 public key for ``issuer_did`` in ``jwks``.

    Accepts standard JWKS ``{"keys": [...]}`` shape. Matches by ``kid`` == issuer_did
    or by the kty=="OKP" / crv=="Ed25519" entry when only one principal is advertised.
    """
    keys = jwks.get("keys", [])
    match = None
    for k in keys:
        if k.get("kty") != "OKP" or k.get("crv") != "Ed25519":
            continue
        if k.get("kid") == issuer_did:
            match = k
            break
        if match is None:
            match = k
    if match is None:
        return None
    return _b64d(match["x"])


def verify_passport(passport: Passport, principal_jwks: dict[str, Any]) -> bool:
    """Verify an Ed25519 passport signature offline against ``principal_jwks``.

    Checks, in order:
    1. Issuer public key resolves in JWKS
    2. Signature verifies over JCS-canonical bytes of the passport (signature stripped)
    3. Validity window covers "now" (not_before <= now < not_after)

    Returns True on all passes. False on any failure. Does not raise.
    """
    issuer_pk = _lookup_issuer_key(principal_jwks, passport.issuer_did)
    if issuer_pk is None:
        return False

    canonical = canonicalize(strip_signature(passport.to_canonical_dict()))
    try:
        VerifyKey(issuer_pk).verify(canonical, passport.signature)
    except BadSignatureError:
        return False

    now = datetime.now(timezone.utc)
    try:
        iat = _parse_rfc3339(passport.issued_at)
        nat = _parse_rfc3339(passport.not_after)
    except ValueError:
        return False
    if now < iat or now >= nat:
        return False

    return True

"""Pluggable trust-provider interface.

MoltBridge, MolTrust, and any future behavioral-trust system implement this
Protocol. The adapter core is provider-agnostic: it fetches a TrustPacket from
the provider (the only network-touching call in the hook) and verifies the
packet signature offline against the provider's advertised JWKS.
"""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
from typing import Any, Protocol, runtime_checkable

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .canonicalization import canonicalize, strip_signature


def _b64d(s: str) -> bytes:
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


@dataclass(frozen=True)
class TrustPacket:
    subject_did: str
    issuer_did: str
    score: float
    context: str
    issued_at: str
    signature: bytes
    payload: bytes = b""

    def to_canonical_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["signature"] = base64.urlsafe_b64encode(self.signature).rstrip(b"=").decode()
        d["payload"] = base64.urlsafe_b64encode(self.payload).rstrip(b"=").decode()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> TrustPacket:
        return cls(
            subject_did=d["subject_did"],
            issuer_did=d["issuer_did"],
            score=float(d["score"]),
            context=d["context"],
            issued_at=d["issued_at"],
            signature=_b64d(d["signature"]),
            payload=_b64d(d.get("payload", "")),
        )


@runtime_checkable
class TrustProvider(Protocol):
    """Trust-provider interface. Two async methods, both required.

    ``fetch_trust_packet`` is the only network-touching call in the governedToolCall
    hook. Its result is verified offline against the JWKS returned by
    ``advertised_jwks``. Implementations should cache JWKS responses appropriately.
    """

    async def fetch_trust_packet(self, subject_did: str) -> TrustPacket: ...

    async def advertised_jwks(self) -> dict[str, Any]: ...


def _lookup_issuer_key(jwks: dict[str, Any], issuer_did: str) -> bytes | None:
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


def verify_trust_packet(packet: TrustPacket, jwks: dict[str, Any]) -> bool:
    """Verify an Ed25519 trust-packet signature offline against ``jwks``.

    Returns True if the signature verifies and the score is a finite float in
    [0.0, 1.0]. False on any failure. Does not raise.
    """
    issuer_pk = _lookup_issuer_key(jwks, packet.issuer_did)
    if issuer_pk is None:
        return False

    canonical = canonicalize(strip_signature(packet.to_canonical_dict()))
    try:
        VerifyKey(issuer_pk).verify(canonical, packet.signature)
    except BadSignatureError:
        return False

    if not (0.0 <= packet.score <= 1.0):
        return False

    return True

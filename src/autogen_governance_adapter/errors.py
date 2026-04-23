"""Decision types returned by the governedToolCall hook."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

FailedCheck = Literal["identity", "authorization", "trust_provider"]


class DenyReason(str, Enum):
    PASSPORT_SIGNATURE_INVALID = "passport_signature_invalid"
    PASSPORT_EXPIRED = "passport_expired"
    PASSPORT_NOT_YET_VALID = "passport_not_yet_valid"
    PASSPORT_KEY_MISMATCH = "passport_key_mismatch"
    DELEGATION_SIGNATURE_INVALID = "delegation_signature_invalid"
    DELEGATION_SCOPE_WIDENED = "delegation_scope_widened"
    DELEGATION_CHAIN_BROKEN = "delegation_chain_broken"
    DELEGATION_EXPIRED = "delegation_expired"
    DELEGATION_NOT_YET_VALID = "delegation_not_yet_valid"
    SCOPE_DOES_NOT_COVER_TOOL = "scope_does_not_cover_tool"
    TRUST_PACKET_SIGNATURE_INVALID = "trust_packet_signature_invalid"
    TRUST_SCORE_BELOW_THRESHOLD = "trust_score_below_threshold"
    TRUST_PROVIDER_UNREACHABLE = "trust_provider_unreachable"


@dataclass(frozen=True)
class Allow:
    """All checks passed."""

    kind: Literal["allow"] = field(default="allow", init=False)
    subject_did: str = ""
    tool_name: str = ""
    effective_scope: tuple[str, ...] = ()
    trust_score: float | None = None


@dataclass(frozen=True)
class Deny:
    """At least one check failed. Deny carries the reason and which check failed."""

    reason: DenyReason
    failed_check: FailedCheck
    evidence: str
    kind: Literal["deny"] = field(default="deny", init=False)


GuardrailDecision = Allow | Deny

"""Delegation chain walker, scope-match, monotonic narrowing check.

A DelegationChain is an ordered list of DelegationHops. The first hop is signed by
the root principal (identified in the caller's JWKS). Each subsequent hop is signed
by the delegator of the previous hop. The invariant: each hop's scope is a subset
of the previous hop's scope — authority can only decrease.

Scope tokens supported:
- ``action:<verb>`` where ``<verb>`` is ``*``, ``read``, ``call``, or any custom verb
- ``resource:<name>`` matching the tool name
- ``inference_substrate:<id>`` riding inside scope per the scope-bound design
- ``min_capability_tier:<T>`` riding inside scope

``scope_covers`` is a string-and-token comparison. Richer policy composes on top
of the ``Allow`` result (e.g., via SINT).
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
class DelegationHop:
    delegator_did: str
    delegator_public_key: bytes
    delegate_did: str
    delegate_public_key: bytes
    scope: tuple[str, ...]
    not_before: str
    not_after: str
    signature: bytes

    def to_canonical_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["delegator_public_key"] = (
            base64.urlsafe_b64encode(self.delegator_public_key).rstrip(b"=").decode()
        )
        d["delegate_public_key"] = (
            base64.urlsafe_b64encode(self.delegate_public_key).rstrip(b"=").decode()
        )
        d["scope"] = list(self.scope)
        d["signature"] = base64.urlsafe_b64encode(self.signature).rstrip(b"=").decode()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> DelegationHop:
        return cls(
            delegator_did=d["delegator_did"],
            delegator_public_key=_b64d(d["delegator_public_key"]),
            delegate_did=d["delegate_did"],
            delegate_public_key=_b64d(d["delegate_public_key"]),
            scope=tuple(d["scope"]),
            not_before=d["not_before"],
            not_after=d["not_after"],
            signature=_b64d(d["signature"]),
        )


@dataclass(frozen=True)
class DelegationChain:
    hops: tuple[DelegationHop, ...]

    @classmethod
    def from_list(cls, lst: list[dict[str, Any]]) -> DelegationChain:
        return cls(hops=tuple(DelegationHop.from_dict(d) for d in lst))

    def leaf_scope(self) -> tuple[str, ...]:
        if not self.hops:
            return ()
        return self.hops[-1].scope

    def subject_did(self) -> str | None:
        if not self.hops:
            return None
        return self.hops[-1].delegate_did


def _lookup_root_key(jwks: dict[str, Any], root_did: str) -> bytes | None:
    keys = jwks.get("keys", [])
    for k in keys:
        if k.get("kty") != "OKP" or k.get("crv") != "Ed25519":
            continue
        if k.get("kid") == root_did:
            return _b64d(k["x"])
    for k in keys:
        if k.get("kty") == "OKP" and k.get("crv") == "Ed25519":
            return _b64d(k["x"])
    return None


def _scope_subset(child: tuple[str, ...], parent: tuple[str, ...]) -> bool:
    """Return True if every token in ``child`` is covered by some token in ``parent``.

    Wildcards: ``action:*`` covers any ``action:<verb>``. All other tokens require
    exact match.
    """
    parent_set = set(parent)
    has_action_wildcard = "action:*" in parent_set
    for token in child:
        if token in parent_set:
            continue
        if has_action_wildcard and token.startswith("action:"):
            continue
        return False
    return True


def verify_chain(chain: DelegationChain, root_principal_jwks: dict[str, Any]) -> bool:
    """Verify the delegation chain offline.

    Walks root → leaf, verifying each hop signature against the delegator's public
    key (the root's key comes from JWKS; each subsequent delegator's key must match
    the previous hop's delegate_public_key). Enforces monotonic narrowing: each
    hop's scope must be a subset of its parent's. Enforces validity windows.

    Returns True on all passes. False on any failure. Does not raise.
    """
    if not chain.hops:
        return False

    root_hop = chain.hops[0]
    root_pk = _lookup_root_key(root_principal_jwks, root_hop.delegator_did)
    if root_pk is None:
        return False
    if root_pk != root_hop.delegator_public_key:
        return False

    now = datetime.now(timezone.utc)
    prev_scope: tuple[str, ...] | None = None
    prev_delegate_pk: bytes | None = None
    prev_delegate_did: str | None = None

    for hop in chain.hops:
        expected_pk = prev_delegate_pk if prev_delegate_pk is not None else root_pk
        expected_did = (
            prev_delegate_did if prev_delegate_did is not None else root_hop.delegator_did
        )
        if hop.delegator_public_key != expected_pk:
            return False
        if hop.delegator_did != expected_did:
            return False

        canonical = canonicalize(strip_signature(hop.to_canonical_dict()))
        try:
            VerifyKey(hop.delegator_public_key).verify(canonical, hop.signature)
        except BadSignatureError:
            return False

        try:
            nbf = _parse_rfc3339(hop.not_before)
            naf = _parse_rfc3339(hop.not_after)
        except ValueError:
            return False
        if now < nbf or now >= naf:
            return False

        if prev_scope is not None and not _scope_subset(hop.scope, prev_scope):
            return False

        prev_scope = hop.scope
        prev_delegate_pk = hop.delegate_public_key
        prev_delegate_did = hop.delegate_did

    return True


def scope_covers(chain: DelegationChain, tool_name: str, tool_args: dict[str, Any]) -> bool:
    """Return True if the leaf-hop scope covers a call to ``tool_name`` with ``tool_args``.

    Required for coverage:
    - an ``action:*`` or ``action:call`` token (or any ``action:<verb>`` where the verb
      matches a ``verb`` kwarg in ``tool_args`` if present)
    - a ``resource:<tool_name>`` token or no ``resource:`` tokens (unconstrained)

    Additional scope tokens (``inference_substrate:``, ``min_capability_tier:``) are
    substrate signals consumed by substrate-aware trust providers. This function
    does not enforce them; it enforces only the action + resource dimensions.
    """
    scope = set(chain.leaf_scope())
    if not scope:
        return False

    verb = tool_args.get("verb", "call") if isinstance(tool_args, dict) else "call"
    action_tokens = {s for s in scope if s.startswith("action:")}
    if not action_tokens:
        return False
    if "action:*" not in action_tokens and f"action:{verb}" not in action_tokens:
        return False

    resource_tokens = {s for s in scope if s.startswith("resource:")}
    if resource_tokens and f"resource:{tool_name}" not in resource_tokens:
        return False

    return True

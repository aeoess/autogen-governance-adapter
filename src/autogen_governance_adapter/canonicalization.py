"""JCS (RFC 8785) canonicalization + SHA-256 helpers.

The byte-identical shape APS, MoltBridge, and MolTrust all agree on. Every signable
artifact in this adapter (passport, delegation hop, trust packet) is signed over
the JCS-canonical bytes of the artifact with its ``signature`` field omitted.
"""

from __future__ import annotations

import hashlib
from typing import Any

import jcs


def canonicalize(obj: dict[str, Any]) -> bytes:
    """Return JCS-RFC8785 canonical bytes of ``obj``."""
    return jcs.canonicalize(obj)


def canonical_hash(obj: dict[str, Any]) -> str:
    """Return hex SHA-256 of the JCS-canonical bytes of ``obj``."""
    return hashlib.sha256(canonicalize(obj)).hexdigest()


def strip_signature(obj: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy of ``obj`` with the ``signature`` key removed."""
    return {k: v for k, v in obj.items() if k != "signature"}

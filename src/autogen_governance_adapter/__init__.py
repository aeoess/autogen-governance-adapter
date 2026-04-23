"""APS + SINT + pluggable trust provider governance adapter for AutoGen.

Public surface:

- governedToolCall: the single before_tool_call async hook
- Passport, DelegationHop, DelegationChain: identity + authorization artifacts
- TrustProvider, TrustPacket: pluggable trust layer
- GuardrailDecision, Allow, Deny: hook return types
- DenyReason, FailedCheck: categorized denial metadata
"""

from .delegation import DelegationChain, DelegationHop, scope_covers, verify_chain
from .errors import Allow, Deny, DenyReason, FailedCheck, GuardrailDecision
from .hook import governedToolCall
from .passport import Passport, verify_passport
from .trust_provider import TrustPacket, TrustProvider, verify_trust_packet

__version__ = "0.1.0"

__all__ = [
    "Allow",
    "DelegationChain",
    "DelegationHop",
    "Deny",
    "DenyReason",
    "FailedCheck",
    "GuardrailDecision",
    "Passport",
    "TrustPacket",
    "TrustProvider",
    "__version__",
    "governedToolCall",
    "scope_covers",
    "verify_chain",
    "verify_passport",
    "verify_trust_packet",
]

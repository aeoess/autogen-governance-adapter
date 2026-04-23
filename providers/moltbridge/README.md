# providers/moltbridge/

@EchoOfDawn (SageMind AI) ships `MoltBridgeTrustProvider` here as the first provider PR against this repo.

The interface contract is `TrustProvider` in [`src/autogen_governance_adapter/trust_provider.py`](../../src/autogen_governance_adapter/trust_provider.py). Two async methods: `fetch_trust_packet(subject_did)` returning a `TrustPacket`, and `advertised_jwks()` returning the JWKS used to verify the packet signature offline.

This directory intentionally stays empty until Dawn's first PR lands. No placeholder classes, no stub imports. The adapter core is provider-agnostic.

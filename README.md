# autogen-governance-adapter

APS + SINT + pluggable trust provider governance adapter for the AutoGen `before_tool_call` hook.

One hook. Three checks. Provider-agnostic.

```
┌─────────────────────────────────────────────────────────────────┐
│  autogen agent                                                  │
│                                                                 │
│   before_tool_call  ──►  governedToolCall()                     │
│                              │                                  │
│                              ├─ 1. identity    (Ed25519)        │
│                              ├─ 2. authorization (delegation)   │
│                              └─ 3. trust provider (optional)    │
│                                                                 │
│                          Allow / Deny(reason, failed_check)     │
└─────────────────────────────────────────────────────────────────┘
```

## Install

```bash
pip install autogen-governance-adapter
```

Python 3.10+. Deps: `cryptography`, `pynacl`, `jcs`, `httpx`.

This adapter does **not** import any specific SDK. APS is one implementation of the underlying primitives, not the namespace owner. MoltBridge, MolTrust, and others plug in via the `TrustProvider` interface.

## Quickstart

```python
from autogen_governance_adapter import governedToolCall, TrustProvider

# passport and delegation_chain come from the caller's identity layer
# (APS SDK, AgentID, did:key — anything that produces Ed25519-signed artifacts)

async def before_tool_call(tool_name, tool_args, *, passport, delegation_chain):
    decision = await governedToolCall(
        passport=passport,
        delegation_chain=delegation_chain,
        tool_name=tool_name,
        tool_args=tool_args,
        principal_jwks=my_principal_jwks,
        trust_provider=my_trust_provider,  # optional
        min_trust_score=0.7,               # optional
    )
    if decision.kind == "deny":
        raise PermissionError(f"{decision.failed_check}: {decision.reason}")
    return decision
```

## Composition

The adapter separates three layers so each can evolve independently:

| Check            | Input                                         | Offline? | Required |
| ---------------- | --------------------------------------------- | -------- | -------- |
| 1. Identity      | passport (Ed25519 over canonical bytes)       | yes      | yes      |
| 2. Authorization | delegation chain, tool name, tool args        | yes      | yes      |
| 3. Trust         | subject DID → attestation from provider       | no       | optional |

Identity and authorization verification are fully offline. The only network touch is optional: fetching a trust packet from a provider's endpoint. The packet signature is then verified offline against the provider's advertised JWKS.

## Scope-bound substrate

Inference-substrate requirements ride inside delegation scope, not as a parallel gate:

```
scope: ["action:call", "resource:weather_api",
        "inference_substrate:approved_set_42",
        "min_capability_tier:T3"]
```

The hook checks scope-match. Substrate-aware trust providers can consume substrate attestations as additional signal, but the authorization path stays single-gate. See [the design rationale on autogen#7525](https://github.com/microsoft/autogen/issues/7525).

## Providers

The `TrustProvider` Protocol defines two methods. Implementations live under `providers/`.

| Provider           | Status     | Maintainer                        |
| ------------------ | ---------- | --------------------------------- |
| MoltBridge         | pending    | @EchoOfDawn (SageMind AI)         |
| MolTrust           | pending    | @MoltyCel                         |
| Your trust system  | open       | PRs welcome                       |

```python
from typing import Protocol
from autogen_governance_adapter import TrustPacket

class TrustProvider(Protocol):
    async def fetch_trust_packet(self, subject_did: str) -> TrustPacket: ...
    async def advertised_jwks(self) -> dict: ...
```

A provider's `TrustPacket` is an Ed25519-signed attestation: `{subject_did, issuer_did, score, context, issued_at, signature}`. The adapter verifies the signature offline against the advertised JWKS.

## Running tests

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

## Contributing

PRs welcome. Priority lanes:

- `providers/moltbridge/` — @EchoOfDawn lands `MoltBridgeTrustProvider` here as the first provider PR
- autogen-side integration fixtures — follow-up after the provider lands
- Additional trust providers — open a PR at `providers/<name>/`

See AGENTS.md for dev-env expectations and the coding-agent contract.

## Related

- [microsoft/autogen#7525](https://github.com/microsoft/autogen/issues/7525) — composition discussion that seeded this repo
- [APS SDK](https://github.com/aeoess/agent-passport-system) — one identity + delegation implementation
- [SINT](https://github.com/sint-labs/sint) — authorization policy engine
- [MoltBridge](https://github.com/sagemind-ai/moltbridge) — behavioral trust provider (pending)
- [MolTrust](https://github.com/moltycel/moltrust) — constraint envelopes (pending)

## License

MIT. See LICENSE.

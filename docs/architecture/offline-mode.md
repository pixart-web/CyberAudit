# Offline mode

CyberAudit's core functionality does not require Internet connectivity, and
does not require any commercial AI API at any time. This page describes what
stays available offline, what depends on connectivity, and how the invariant
is tested.

## What works with no Internet connection

Everything that was already local-only in earlier phases keeps working
exactly as before: authentication (local or a reachable on-prem OIDC
provider), RBAC, tenant/workspace access, engagements, scope, asset
inventory, imported evidence, findings, risk scoring, the deterministic
security engines, the Attack Graph and Knowledge Graph, GRC, and audit logs.
None of that depends on outbound network access; it never has.

Phase 10.3 adds the sovereign AI runtime (see
[`adr-026-sovereign-local-ai-runtime.md`](adr-026-sovereign-local-ai-runtime.md))
and the agent framework (see
[`adr-027-cyber-agent-runtime.md`](adr-027-cyber-agent-runtime.md)) on top of
that baseline, under the same rule:

- **`AI_RUNTIME_BACKEND=disabled`** (the default) means no component ever
  opens a socket for inference or embeddings. `DeterministicGroundedProvider`
  answers every AI/agent question directly from the tenant's own Knowledge
  Graph, with facts, citations and a confidence score computed locally.
- **`AI_RUNTIME_BACKEND=ollama`** points at a *self-hosted* Ollama server —
  infrastructure the customer runs and controls, not a commercial API. If
  that server later becomes unreachable (network down, service stopped), the
  runtime's `health_check()` reports `healthy=false` and every caller
  (`LocalFirstProvider`, `CyberAgentRuntime`) falls back to the deterministic
  answer instead of failing the request.
- **Local retrieval** (`cyberaudit/local_retrieval.py`) uses a local
  embedding model when one is configured and healthy, and a deterministic
  lexical (Jaccard) ranking otherwise — never a remote embedding API.

## What genuinely needs connectivity

Only optional, explicitly enhancement-only features:

- vulnerability feed / threat intelligence synchronization;
- CyberAudit software and knowledge-pack updates;
- downloading a *new* local model (once implemented — see ADR-026's
  "riscos e dívida" section for current status);
- any external OIDC identity provider that is itself hosted off-site.

Losing connectivity to any of these degrades that one capability; it never
takes down authentication, evidence, findings, risk, GRC, the Knowledge
Graph, or the AI/agent surface.

## How this is tested

`apps/api/tests/test_offline_mode.py` simulates "no network" by making every
outbound socket connection raise `OSError`, then exercises the parts of the
system most likely to secretly depend on reachability:

- `HardwareCapabilityService.detect()` still returns a real hardware
  profile (GPU detection degrades to "none found", never an exception);
- the default (`disabled`) inference and embedding backends report a clear
  `healthy=false`, not a crash;
- a backend explicitly configured to point at Ollama also degrades to
  `healthy=false` when that Ollama host is unreachable, instead of raising;
- every one of the ten cataloged agents (`AGENT_CATALOG`) answers a question
  successfully with zero local models installed;
- retrieval still ranks and narrows a 50-row candidate pool using the
  lexical fallback.

Run it directly with:

```bash
pytest apps/api/tests/test_offline_mode.py
```

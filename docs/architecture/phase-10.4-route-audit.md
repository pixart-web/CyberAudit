# Phase 10.4.0 — Repository audit and product experience inventory

## Baseline verified

- Source branch: `codex/sovereign-ai-local-runtime`
- Source SHA: `cebd0cd` (matches the Phase 10.4 prompt's stated SHA exactly)
- PR #6: Draft, `backend`/`frontend`/`migrations`/`secret-scan` all `SUCCESS`
- No uncommitted work (only an untracked, gitignored `.venv` symlink used for
  local test execution)
- Phase 10.4 branch created from that exact HEAD: `codex/security-os-local-distribution`

## Route inventory

103 `page.tsx` routes under `apps/web/app`. Architecture is far leaner than
103 implies:

- **60 routes** are thin config wrappers around one shared component,
  `components/resource-page.tsx` (31 lines): a generic table with search,
  an optional "Criar" button, and a handful of heuristic cell renderers
  (status/result → badge tone by a hardcoded string allowlist, ISO dates,
  booleans). No filters beyond free-text search, no column selection, no
  bulk actions, no severity semantics beyond the single badge heuristic.
- **42 routes** are hand-written pages (detail/dashboard/graph pages: e.g.
  `engagements/[id]`, `command-center`, `asset-graph`, `attack-paths`,
  `soc`, `grc`, `ai-assistant`, and the `cyber-agents` page added in Phase
  10.3).
- **14 navigation entries** (`shell.tsx`) point at routes with no literal
  page — they render the generic `app/[...slug]/page.tsx` "Em
  desenvolvimento" placeholder honestly, not broken links: `/authorizations`,
  `/organizations`, `/coverage`, `/laboratory` (+2 sub-routes), and 7
  `/assessments/*` category pages.
- The **design system is minimal**: `packages/ui/src/index.tsx` is 17
  lines (`Card`, `Badge`, `Button` only — no tokens file, no Table/Dialog/
  Drawer/Tabs/EmptyState/Skeleton components). Visual language comes from
  Tailwind utility classes and a handful of CSS classes (`.field`,
  `.table`, `.badge-*`) in `globals.css`.
- `components/shell.tsx` (61 lines) is the entire application shell: a
  fixed sidebar built from a hardcoded `groups` array, and a header with a
  tenant selector, a non-functional search input placeholder, a "MODO
  CLIENTE" badge, a notification bell and a user chip. No breadcrumbs, no
  command palette, no environment/health indicator, no AI panel.
- `components/enterprise-command-center.tsx` holds `SocCommandCenter`,
  `GrcCommandCenter` and `AiAssistant` — the only page that already talks
  to the Phase 10.3 `AiProvider` contract (via `/ai/assist`) before this
  phase's `cyber-agent-workspace.tsx` (Phase 10.3.9–11) added the agent
  framework equivalent.
- **The Engagement detail page (`engagements/[id]/page.tsx`) is a static
  mock**: six tab labels are rendered as inert buttons with no click
  handler and no per-tab content; the engagement ID, status and
  "checklist" shown are hardcoded, not fetched from `/api/v1/engagements`.
  This is the single clearest gap between the backend (Phase 10.3.6:
  engagement notes, timeline, scope, findings, evidence, reports all
  exist and are tested) and the frontend, and is Phase 10.4's highest-value
  target.

## What this means for Phase 10.4

Given the actual architecture (lean, config-driven, not 103 independently
diverging implementations), the highest-leverage work is:

1. A real design-system layer (tokens + a handful of genuinely reusable
   primitives: severity/status badges, empty/error/loading states,
   tabs, drawer) that every existing page already benefits from through
   `ResourcePage` and `Shell`, rather than touching 103 files individually.
2. A real `CyberShell` evolution (breadcrumbs/context bar, global search,
   command palette, health indicator) — one file, used everywhere.
3. A first, complete **Workspace** implementation for Engagement (the
   newest, richest backend domain and the clearest existing mock), used as
   the template pattern for future workspaces (Incident, Asset) rather than
   building all three in this phase.
4. Contextual Cyber AI wired through the existing `CyberAgentRuntime`/
   `AgentToolGateway` (never bypassed), starting where it has the most
   value: the Engagement Workspace's "Summarize Assessment" action and the
   Findings list's "Explain Finding" action.

Full parity across all 42 hand-written pages (SOC/Identity/Cloud/GRC full
consolidation, Attack/Knowledge Graph UX overhauls, native installers for
three OSes) is explicitly **not** attempted in one phase; see the final
Phase 10.4 report for what was implemented vs. deferred, per section 60's
"no placeholder product" requirement — this audit exists so that claim is
falsifiable against the actual repository rather than the plan.

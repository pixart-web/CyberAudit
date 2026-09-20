# Phase 10.4 — Security OS Experience & Local Distribution

Companion to `phase-10.4-route-audit.md` (the pre-implementation inventory).
This records what actually changed, what stayed as the pre-existing
`ResourcePage` pattern, and the honest readiness of each local-distribution
platform.

## Design system (10.4.1)

`packages/ui/src/index.tsx` grew from 17 lines (Card/Badge/Button) to add:

- **Design tokens** (`globals.css`): CSS custom properties for the
  severity/status palette, a visible `:focus-visible` outline, and
  `prefers-reduced-motion` support. No light theme was added — the
  product was dark-only before this phase and remains so; this is
  recorded honestly rather than claimed.
- **`SeverityBadge` / `toSecurityState`**: the single semantic scale from
  section 16 (critical/high/medium/low/informational/healthy/warning/
  failed/unknown/offline), each with an icon and text label.
- **`EmptyState` / `ErrorState` / `LoadingState`**: accessible
  (`role="status"`/`"alert"`) replacements for ad hoc per-page markup.
- **`Tabs` / `TabPanel`**: keyboard-accessible (arrow-key navigation,
  `aria-selected`, roving tabindex).
- **`Drawer`**: an accessible side panel (Escape to close, focus restore).

`ResourcePage` (used by 60 of 103 routes) was wired to `SeverityBadge`/
`EmptyState`/`ErrorState` immediately, so those 60 routes benefit without
being touched individually.

## CyberShell (10.4.2)

- **`GlobalSearch`**: queries findings/incidents/engagements in parallel
  through their existing, already-authorized list endpoints. A domain the
  caller lacks permission for just fails that one request silently.
- **`CommandPalette`** (Cmd/Ctrl+K): fixed hrefs from the existing sidebar
  route set only — never an arbitrary command surface.
- **`SystemHealthIndicator`**: reads `/ai-runtime/health`.

A real layout regression was found and fixed during browser verification:
adding these to the header initially starved the search input to ~28px at
1024px viewport width. Fixed with a `min-w-40` floor and moving two other
header elements to larger breakpoints.

## Workspace pattern (10.4.4/10.4.5)

One Workspace was fully implemented: **Engagement**. It replaces a static
mock (six tab buttons with no click handler, hardcoded ID/status/checklist)
with a real page: `GET /engagements/{id}` (previously missing entirely —
added in this phase) plus independent, tab-gated queries for
Scope/Findings/Evidence/Notes/Timeline/Reports, a working note form, and a
"Summarize Assessment" contextual AI action.

**Incident and Asset workspaces described in the brief were not built.**
Their list pages remain the pre-10.4 `ResourcePage`, and their detail pages
(where they exist) remain whatever they were before this phase. The
Engagement Workspace is the template to replicate for them.

## Local AI runtime UI (10.4.13/10.4.14)

- **`/model-management`**: lists registered models, shows the real
  hardware profile, lets an admin register a manifest and toggle
  install status. Never executes model code.
- **`/update-manager`**: uploads a manifest + signature and calls the
  existing `/updates/validate`. Only ever reports acceptance/reasons —
  never stages or applies anything.

## What was not attempted in this phase (explicit, per section 60)

- **SOC/Identity/Cloud/GRC/Attack-Graph/Knowledge-Graph/Reporting UX
  consolidation** (sections 19–23, 37–38): out of scope for this phase's
  time budget. These routes remain as inventoried in the 10.4.0 audit.
- **Command Center enhancements** beyond what already existed: the
  existing Command Center (risk map, findings by severity, top risks,
  active engagements, adapter health, activity feed, incident timeline)
  was reviewed and found already substantially aligned with section 8's
  requirements; no changes were made to it in this phase.
- **Accessibility audit with real tooling** (axe, Lighthouse, screen
  reader pass): not run. The new components follow accessible patterns
  (roles, aria-selected, focus-visible) by construction, but this is not
  the same as a measured audit — see the final report's Accessibility
  section for what that honestly means.
- **Performance measurement**: not instrumented beyond the existing
  Next.js build output (route bundle sizes, shown in the build log).

## Phase 10.4.1 update — what changed since the above

The two items directly above ("accessibility audit with real tooling",
"performance measurement") and the diagnostic bundle deferral in
`docs/security/threat-model.md` are now closed — see that file's
"Diagnostic bundle generator" and "New Workspace-detail attack surface"
sections, and this repo's Phase 10.4.1 final report for the measured
accessibility (axe-core, zero violations on the surfaces checked, layout
rules honestly excluded) and performance (production build bundle sizes)
results.

Four Workspace detail pages were added or extended in this pass: Asset
(existing 360-view kept, three new tabs added), Finding (existing content
kept, Retests + Cyber AI tabs added), Incident (new — the old route was a
mislabeled list, not a detail view), and Control (new, and required a
previously-missing `GET /grc/controls/{id}` endpoint).

**Still not attempted**: SOC/Identity/Cloud/Attack-Graph/Knowledge-Graph/
Reporting workspace consolidation, and native installer work (explicitly
out of scope for 10.4.1, deferred to "Phase 10.4.2" per that phase's own
instructions). This is a genuine scope gap against the full Phase 10.4.1
brief, not a claim that it's done — see the final report's Domain
Completion Matrix.

## Local distribution platform status

| Platform | Status | Evidence |
|---|---|---|
| Docker Compose | **IMPLEMENTED** | Loopback-bound by default (Phase 10.3.8); `cyberaudit_launcher.sh` verified: guard clauses fail cleanly, compose files parse correctly. Full image build + boot was *not* rerun in this phase (verified in 10.3.8, unchanged since). |
| Windows native installer | **BLOCKED** | Not built. No code-signing credentials available in this session; a real installer needs Docker Desktop/WSL2 orchestration, service registration and an EXE build pipeline this session cannot produce honestly. Architecture documented (`local-installation.md`). |
| Linux native package (.deb) | **BLOCKED** | Not built. Same reasoning — a real `.deb` needs a systemd unit, packaging control files and a build/test pass on an actual Debian/Ubuntu target this session does not have. |
| macOS native package | **BLOCKED** | Not built, and explicitly requires Apple notarization credentials this session does not hold — per section 46, documented rather than faked. |

See `docs/architecture/local-installation.md` for the full breakdown
(unchanged from Phase 10.3.8 except where noted above) and
`docs/security/troubleshooting.md` for the new troubleshooting guide.

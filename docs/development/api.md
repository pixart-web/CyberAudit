# API da Fase 3

## Enterprise domain expansion

The OpenAPI contract includes:

- `/enterprise-connectors` lifecycle, local test, controlled sync, health and
  execution history;
- `/identity`, `/identity/active-directory`, `/identity/entra` and `/saas`
  inventories and posture;
- `/cloud` accounts, resources, networks, identities, roles, posture, risk,
  changes and bounded graph;
- `/kubernetes`, `/container-runtime`, `/endpoints` and `/mobile-devices`;
- `/zero-trust` overview, assessments, deterministic evaluation and trends.

All routes are under `/api/v1`, require granular RBAC and derive
`organization_id` from the authenticated user. Connector credential values are
never part of a response schema.

OpenAPI permanece em `/docs`. Recursos novos: `/evidence`, `/imports`, `/retests`, `/asset-observations`, `/asset-suggestions`, `/network-policies` e `/jobs/{id}/network-summary`. Todos derivam o tenant do JWT, exigem permissões granulares e usam o envelope de erro comum.
# APIs Enterprise

Os endpoints das Fases 7–9 usam `/api/v1`, JWT, RBAC, paginação e isolamento por
tenant. Grupos principais:

- `/soc/dashboard`, `/security-events`, `/detections/*`, `/incidents`,
  `/cases`, `/iocs`, `/threat-intelligence/feeds`, `/hunts`, `/playbooks`,
  `/security-data-lake`, `/purple-team/exercises`;
- `/grc/dashboard`, `/grc/frameworks`, `/grc/controls`, `/grc/risks`,
  `/grc/policies`, `/grc/evidence-links`, `/grc/exceptions`;
- `/knowledge-graph`, `/knowledge-nodes`, `/ai/services`, `/ai/assist`,
  `/ai/requests`, `/enterprise/health`.

OpenAPI em `/docs` é a referência dos payloads e códigos de validação.

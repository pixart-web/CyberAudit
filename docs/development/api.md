# API da Fase 3

OpenAPI permanece em `/docs`. Recursos novos: `/evidence`, `/imports`, `/retests`, `/asset-observations`, `/asset-suggestions`, `/network-policies` e `/jobs/{id}/network-summary`. Todos derivam o tenant do JWT, exigem permissões granulares e usam o envelope de erro comum.

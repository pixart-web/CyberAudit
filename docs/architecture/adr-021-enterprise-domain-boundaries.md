# ADR-021 — Fronteiras dos domínios Enterprise

Estado: aceite em 2026-07-29.

## Contexto

As Fases 7–9 acrescentam SOC, GRC e assistência inteligente a um sistema já
multi-tenant. Misturar estes registos com jobs de avaliação criaria acoplamento,
permitiria automação acidental e dificultaria retenção.

## Decisão

São criados três domínios sobre PostgreSQL:

1. SOC recebe eventos normalizados, produz deteções determinísticas e gere
   incidentes/casos.
2. GRC mantém um catálogo único de controlos, mapeado para vários referenciais,
   e um risk register independente de findings.
3. Knowledge Graph projeta factos dos outros domínios. Assistentes consomem
   apenas esta projeção através de uma interface de fornecedor.

Todos os registos empresariais incluem `organization_id`; todos os endpoints
derivam o tenant do utilizador autenticado. Redis transporta apenas IDs.

## Consequências

- Não há ações autónomas, comandos ou carregamento dinâmico.
- Correlação e IA podem evoluir sem alterar as fontes de verdade.
- A implementação atual usa PostgreSQL; um data lake ou graph database futuro
  será uma projeção, não um segundo sistema de registo.
- A Fase 6 não existe no histórico atual. Esta lacuna é registada, mas não é
  preenchida implicitamente por este ADR.

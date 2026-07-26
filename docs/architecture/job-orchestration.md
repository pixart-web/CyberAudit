# Orquestração de jobs

O `JobOrchestrator` é a única camada autorizada a publicar jobs na fila Dramatiq/Redis.

```mermaid
sequenceDiagram
  actor U as Utilizador
  participant API
  participant P as ScopePolicyEngine
  participant Q as Redis
  participant W as Worker
  participant A as AdapterRegistry
  U->>API: Criar job
  API->>API: RBAC e tenant
  API->>P: Avaliar âmbito
  P-->>API: allowed / denied / requires_approval
  API->>Q: Publicar job autorizado
  Q->>W: Entregar id do job
  W->>P: Revalidar imediatamente
  W->>A: Obter adapter permitido
  A-->>W: Demo adapter
  W->>W: Executar, normalizar e deduplicar
  W-->>API: Estado, eventos e findings persistidos
```

A máquina de estados explícita rejeita transições arbitrárias. Cada transição produz `JobEvent` e, quando existe ator humano, `AuditLog`. O progresso é monotónico.

O endpoint SSE transmite apenas estado, progresso e mensagem do job do tenant autenticado. O frontend usa polling autenticado como fallback.

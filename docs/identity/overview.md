# Identity Security

O domínio normaliza providers, identidades, grupos, papéis, permissões,
relações e postura de autenticação. Todos os registos têm `organization_id`,
IDs externos únicos por provider e timestamps de observação. Estados
desconhecidos são preservados; ausência de telemetria não equivale a controlo
implementado.

Risco de identidade considera privilégio, MFA, contas ativas sem uso, guests e
falta de owner. A projeção para o Knowledge Graph é idempotente e limitada.

# Enterprise Synchronization

1. Um utilizador com `enterprise_connectors.execute` pede sync.
2. A API valida tenant, estado ativo e read-only.
3. É criada uma `ConnectorExecution` idempotente e auditada.
4. O worker recarrega execução e connector e repete as validações.
5. Dados são sanitizados, normalizados, comparados e projetados.
6. Cursor, contagens, health e métricas são atualizados.

O worker atual processa apenas imports controlados; recolha externa permanece
desativada. Retries são limitados e não existe escrita no provider.

# Criar um adapter

1. Implementar `ToolAdapter` num módulo versionado do backend.
2. Definir um schema Pydantic com `extra="forbid"`.
3. Declarar target types, intensidades, rede e timeout.
4. Registar estaticamente no `AdapterRegistry`.
5. Criar `ToolAdapterDefinition` por migration/seed administrativo.
6. Testar configuração, alvo, cancelamento, timeout, parsing, sanitização e health check.
7. Documentar isolamento e egress necessários.

É proibido aceitar comandos shell, argumentos livres, paths arbitrários, URLs alternativas, variáveis de ambiente fornecidas pelo utilizador ou módulos carregados dinamicamente.

Nenhum router ou componente web pode invocar um adapter; apenas o worker, depois de receber um job publicado pelo `JobOrchestrator`.

Adaptadores com rede recebem `NetworkExecutionPolicy` e destinos já autorizados no contexto. É proibido usar `httpx`, `urllib`, sockets ou resolvers diretamente; devem chamar `SecureHttpClient` ou `SecureDnsResolver`. Testes de integração usam apenas `infrastructure/docker-compose.lab.yml`.

# Desenvolvimento

1. Instalar Docker, Docker Compose, pnpm e Python 3.12.
2. Copiar `.env.example` para `.env` e trocar `JWT_SECRET`.
3. Executar `make setup`, `make up`, `make migrate` e `make seed`.
4. Abrir `http://localhost:3000` e usar a conta de demonstração.

Para trabalho sem Docker: inicie PostgreSQL/Redis, configure `.env`, execute `uvicorn cyberaudit.main:app --reload` em `apps/api` e `pnpm --filter @cyberaudit/web dev`.

# CyberAudit

Plataforma profissional para gestão e execução segura de auditorias de cibersegurança autorizadas. Inclui o domínio da Fase 1, o motor de execução da Fase 2 e avaliações de baixo risco da Fase 3.

## Requisitos

- Docker 24+ e Docker Compose v2
- pnpm 9+ e Node.js 22+ (desenvolvimento local)
- Python 3.12 (desenvolvimento local)

## Arranque

```bash
cp .env.example .env
# Alterar JWT_SECRET antes do primeiro arranque
make up
make migrate
make seed
make seed-jobs
make seed-phase3
```

Web: `http://localhost:3000`  
API/OpenAPI: `http://localhost:8000/docs`

Credenciais de desenvolvimento:

- Email: `admin@cyberaudit.local`
- Password: `ChangeMe123!`

Esta password é apenas para `ENVIRONMENT=development`; ambientes diferentes devem forçar a alteração e usar OIDC na fase de produção.

## Comandos

Além dos comandos anteriores: `make seed-phase3`, `make test-adapters`, `make test-network-safety`, `make lab-services-up`, `make lab-services-down`, `make import-demo-results`, `make purge-evidence` e `make retest-demo`.

## Estrutura

- `apps/web`: Next.js App Router, Tailwind, React Query, RHF/Zod e gráficos.
- `apps/api`: FastAPI, SQLAlchemy assíncrono, Alembic, autenticação e políticas.
- `apps/worker`: processo Dramatiq isolado logicamente, sem ferramentas ofensivas.
- `packages`: UI, tipos, configuração e helpers de segurança.
- `infrastructure`: imagens Docker e espaço para nginx/scripts.
- `docs`: arquitetura, segurança e desenvolvimento.

## Variáveis

Consulte `.env.example`. Nunca versionar `.env`, tokens, passwords reais ou chaves. Uploads são privados e gravados em `UPLOAD_DIR`.

## Segurança

CyberAudit não concede autorização para testar sistemas. Uma auditoria do tipo cliente só pode avançar com responsável, PDF válido, scope ativo e target autorizado. O motor de políticas volta a validar contexto, tenant, janela, técnica, intensidade e emergency stop.

Não existem scanners agressivos, exploração, credenciais ou comandos arbitrários. Os adapters reais apenas fazem inventário consolidado, DNS exato, uma ligação TLS, HTTP limitado, deteção passiva, configuração pública allowlisted e importação privada. DNS/IP/redirect passam por proteção SSRF central.

## Fluxo de demonstração

Entre como `auditor@cyberaudit.local` com `ChangeMe123!`, abra **Jobs → Novo Job**, selecione a auditoria ativa, scope privado e perfil de demonstração. Cenários `warning`, `failure` e `timeout` exercitam os estados controlados. Intensidades de maior risco exigem aprovação por um utilizador com `approvals.review`.

## Testes e qualidade

```bash
make lint
make test
```

O backend usa Ruff, Black, mypy, pytest e coverage. O frontend usa TypeScript strict, ESLint, Prettier, Vitest e Testing Library.

## Laboratório controlado

`make lab-services-up` inicia apenas serviços locais em `127.0.0.1:8080`. Use o engagement `LAB-PHASE3`; nunca execute os testes de integração contra serviços públicos.

## Próximos passos

Fase 4: OIDC/MFA de produção, object storage, sandbox efémero com egress allowlisted, scheduler/reconciliador, reporting exportável e fontes de vulnerabilidades aprovadas.

# CyberAudit

Plataforma profissional para gestão e execução segura de auditorias de cibersegurança autorizadas. Inclui o domínio da Fase 1, o motor de execução da Fase 2, avaliações de baixo risco da Fase 3 e o CyberAudit OS da Fase 4: inventário vivo, Cyber Asset Graph e exposure intelligence.

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
make seed-phase4
```

Web: `http://localhost:3000`  
API/OpenAPI: `http://localhost:8000/docs`

Credenciais de desenvolvimento:

- Email: `admin@cyberaudit.local`
- Password: `ChangeMe123!`

Esta password é apenas para `ENVIRONMENT=development`; ambientes diferentes devem forçar a alteração e usar OIDC na fase de produção.

## Comandos

Fase 4 acrescenta `make seed-phase4`, `make test-discovery`, `make test-graph`, `make test-vulnerability-intelligence`, `make test-risk`, `make lab-network-up`, `make lab-network-down`, `make sync-vulnerability-feeds`, `make recalculate-risk`, `make refresh-attack-paths` e `make coverage-report`.

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

Não existem scanners agressivos, exploração, credenciais ou comandos arbitrários. A descoberta de rede da Fase 4 usa apenas TCP connect com perfis internos fechados, limites de hosts/portas/taxa/timeout, scope duplamente validado e laboratório isolado. Correlação de vulnerabilidades é local e conservadora; um match heurístico nunca se torna finding confirmado sem revisão.

## Fluxo de demonstração

Entre como `auditor@cyberaudit.local` com `ChangeMe123!`, abra **Jobs → Novo Job**, selecione a auditoria ativa, scope privado e perfil de demonstração. Cenários `warning`, `failure` e `timeout` exercitam os estados controlados. Intensidades de maior risco exigem aprovação por um utilizador com `approvals.review`.

## Testes e qualidade

```bash
make lint
make test
```

O backend usa Ruff, Black, mypy, pytest e coverage. O frontend usa TypeScript strict, ESLint, Prettier, Vitest e Testing Library.

## Laboratório controlado

`make lab-network-up` inicia apenas serviços inertes locais em `127.0.0.1` (HTTP, TLS e banners sem protocolo real). Use o engagement `LAB-PHASE3`; nunca execute os testes de integração contra serviços públicos.

## Próximos passos

Fase 5: OIDC/MFA de produção, object storage, runner efémero com egress por job, scheduler distribuído/reconciliador, graph store opcional, reporting executivo e conectores de feeds aprovados.

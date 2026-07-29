# CyberAudit

Plataforma profissional para gestão e execução segura de auditorias de cibersegurança autorizadas. Inclui o domínio da Fase 1, o motor de execução da Fase 2, avaliações de baixo risco da Fase 3, Cyber Asset Graph e exposure intelligence da Fase 4, Application Security da Fase 5 e os domínios Enterprise defensivos das Fases 7–9: SOC, GRC, Knowledge Graph e assistência fundamentada.

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
make seed-phase5
make seed-enterprise
```

Web: `http://localhost:3000`  
API/OpenAPI: `http://localhost:8000/docs`

Credenciais de desenvolvimento:

- Email: `admin@cyberaudit.local`
- Password: `ChangeMe123!`

Esta password é apenas para `ENVIRONMENT=development`; ambientes diferentes devem forçar a alteração e usar OIDC na fase de produção.

## Comandos

Fase 5 acrescenta `make seed-phase5`, `make test-appsec`, `make appsec-lab-up`, `make appsec-lab-down`, os alvos de teste por domínio AppSec, `make generate-demo-sbom` e `make import-demo-api-spec`.

Enterprise acrescenta `make seed-enterprise`, `make test-soc`, `make test-grc`,
`make test-ai`, `make test-enterprise` e `make rebuild-knowledge-graph`.

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

Na Fase 5, especificações OpenAPI e SBOM CycloneDX são analisadas offline, com limites de tamanho e sem resolver referências externas. O inventário web aceita apenas pedidos seguros através do cliente HTTP central com proteção SSRF. Repositórios não são clonados pelo processo da API, imagens não são executadas, package managers não são invocados e observações de segredos guardam apenas fingerprint e máscara.

Nas Fases 7–9, eventos usam schemas allowlist, regras de deteção nunca executam
código, playbooks são checklists não-executáveis e assistentes não efetuam
ações. Respostas assistidas indicam fontes, factos, inferências, confiança e
limitações. Fornecedores externos de IA começam desativados.

## Fluxo de demonstração

Entre como `auditor@cyberaudit.local` com `ChangeMe123!`, abra **Jobs → Novo Job**, selecione a auditoria ativa, scope privado e perfil de demonstração. Cenários `warning`, `failure` e `timeout` exercitam os estados controlados. Intensidades de maior risco exigem aprovação por um utilizador com `approvals.review`.

## Testes e qualidade

```bash
make lint
make test
```

O backend usa Ruff, Black, mypy, pytest e coverage. O frontend usa TypeScript strict, ESLint, Prettier, Vitest e Testing Library.

## Laboratório controlado

`make lab-network-up` inicia apenas serviços inertes locais em `127.0.0.1` (HTTP, TLS e banners sem protocolo real). `make appsec-lab-up` serve apenas fixtures estáticas sintéticas em `127.0.0.1:8090`. Nunca execute os testes de integração contra serviços públicos.

## Estado das fases e próximos passos

O histórico recebido não contém uma implementação da Fase 6. Permanecem
pendentes OIDC/MFA de produção, object storage, runners efémeros reforçados,
integrações SCM por aplicação instalada, validação de assinaturas/proveniência,
feeds assinados e reporting executivo. Esta lacuna deve ser encerrada antes de
um lançamento de produção.

Fase 10 recomendada: hardening operacional, políticas PostgreSQL RLS,
particionamento/retention de eventos, conectores defensivos assinados,
notificações aprovadas, secret manager, avaliação de fornecedor de IA e testes
de carga multi-tenant.

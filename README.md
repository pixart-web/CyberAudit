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

Web: `http://127.0.0.1:3000`  
API/OpenAPI: `http://127.0.0.1:8000/docs`

Alternativa com diagnóstico e supervisão (arranque, `status`, `logs`, `restart`, `down`):
`./infrastructure/scripts/cyberaudit_launcher.sh up`. Por omissão, a API e o web só ficam
acessíveis em loopback; ver `docs/architecture/local-installation.md` e `docker-compose.remote.yml`
para expor explicitamente na LAN.

Credenciais de desenvolvimento:

- Email: `admin@cyberaudit.local`
- Password: `ChangeMe123!`

Esta password é apenas para `ENVIRONMENT=development`; ambientes diferentes devem forçar a alteração e usar OIDC na fase de produção.

## Comandos

Fase 5 acrescenta `make seed-phase5`, `make test-appsec`, `make appsec-lab-up`, `make appsec-lab-down`, os alvos de teste por domínio AppSec, `make generate-demo-sbom` e `make import-demo-api-spec`.

Enterprise acrescenta `make seed-enterprise`, `make test-soc`, `make test-grc`,
`make test-ai`, `make test-enterprise` e `make rebuild-knowledge-graph`.

A expansão Enterprise acrescenta `make enterprise-domain-seed`,
`make enterprise-domain-test`, `make identity-test`, `make cloud-test`,
`make kubernetes-test`, `make zero-trust-test` e
`make enterprise-domain-health`.

Product Hardening acrescenta `make seed-hardening`, `make test-hardening`,
`make verify-production-config`, `make backup`, `make restore-drill` e
`make load-smoke`. A consola **Sistema → Definições** mostra configuração,
sessões, continuidade, SLOs, feature flags e edição sem revelar segredos.

Production Readiness Closure acrescenta WebAuthn, RLS PostgreSQL, DLQ universal,
Vault KV v2, S3 e o contrato HTTPS para runners efémeros. A vista
**Sistema → Definições** apresenta o gate e os seus bloqueadores sanitizados.
Use `make test-production-readiness` e `make test-rls`; o segundo exige
`CYBERAUDIT_RLS_TEST_DATABASE_URL` apontado exclusivamente para PostgreSQL local.

Infrastructure Validation acrescenta o laboratório production-like com TLS,
Keycloak, Vault, MinIO, PostgreSQL, Redis, runners Docker/Kubernetes, métricas e
tracing. O fluxo principal é `make readiness-environment-check`,
`make readiness-up`, os alvos `readiness-*-test` e `make readiness-evidence`.
`make readiness-gate` falha deliberadamente enquanto existir qualquer evidência
ausente, falhada, expirada ou sem revisão humana obrigatória. O alvo
`release-candidate` nunca cria uma tag local: a publicação é exclusiva do
workflow protegido e só é alcançável depois do gate.

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

Os domínios Identity, Active Directory, Entra ID, Microsoft 365, Google
Workspace, AWS, Azure, GCP, Kubernetes, runtime, endpoint e mobile usam
inventário tenant-isolated e conectores read-only. A base de dados guarda
apenas referências a secret managers, nunca o valor das credenciais. Nesta
entrega os adaptadores Enterprise funcionam exclusivamente em modo
fixture/importação controlada: não abrem sockets, não executam processos e não
alteram sistemas externos. O Zero Trust score é determinístico, explica os
fatores usados e reduz a confiança quando a telemetria é desconhecida.

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

Fase 10 estabelece a baseline de configuração segura, OIDC/PKCE, MFA TOTP,
sessões server-side, políticas centrais, referências de segredos, SDK de
conectores read-only, runners fechados, object storage abstrato, retenção,
licenciamento, telemetria opt-in, CI de segurança, Compose de produção e Helm.
Consulte `docs/architecture/product-hardening.md` e
`docs/testing/product-hardening.md`.

Vault KV v2 e S3 têm implementações SDK com identidade de workload, limites,
checksums e isolamento por tenant; os providers cloud alternativos continuam a
falhar de forma fechada. Os runners efémeros usam um controlador HTTPS e imagens
fixas por digest, sem aceitar comandos ou Pod specs.

Esta branch é uma **Production-Ready Candidate em construção**, não uma
declaração de prontidão. Keycloak, Vault/MinIO, PostgreSQL/Redis, runners
Docker/Kubernetes, backup/restore, SBOM, scans e carga pública sintética foram
exercitados localmente e deixaram evidência sanitizada. Permanecem bloqueadores:
segundo IdP independente, WebAuthn num browser com origem confiável, HA completa
da camada de dados, DR num segundo ambiente, findings HIGH/CRITICAL sem
aceitação, assinatura/proveniência keyless, instalação/upgrade/rollback e
avaliação externa. O endpoint `/api/v1/operations/production-readiness` combina
registos tenant-scoped com o manifesto externo e nunca se autoaprova.

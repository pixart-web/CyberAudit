# Relatório final — CyberAudit OS, ativação do produto real

**Estado final: `IN_PROGRESS`** (nem `EVALUATION_READY` nem `DEMO_READY` declarados na Hetzner, porque a instância nunca foi acedida.)
**Prontidão de produção (reportada em separado): NÃO PRONTA** — ProductionReadinessGate permanece BLOCKED; nada foi enfraquecido.

| # | Ponto | Resultado |
|---|-------|-----------|
| 1 | Diagnóstico | A Hetzner corre `origin/main` (d3a182f, 52 rotas, verificado por OpenAPI idêntico); o branch tem 305+. UI sem formulários de criação, `POST /organizations` era stub, duplicados davam 500, login trazia credenciais de demo. Ver `commercial-readiness-m0-audit.md`. |
| 2 | Bootstrap/auth | `/setup` de uso único com token; CLI `ensure-rbac`, `rotate-password`; mudança de palavra-passe forçada; sessões revogadas. |
| 3 | Organização/RBAC | Catálogo canónico com teste anti-deriva; criação de tenant sob RLS; `platform.manage` só para Platform Administrator. |
| 4 | Clientes/engagements/âmbito | CRUD real com formulários; autorização assinada (PDF) obrigatória para ativar. |
| 5 | Ativos/jobs/findings/evidência | Importação CSV, jobs via Dramatiq, evidência manual privada com SHA-256. |
| 6 | Risco/AI/relatórios | Dashboard calculado da BD; AI apenas com factos suportados; relatório PDF profissional. |
| 7 | Demo "Northstar" | `seed-northstar` protegido (BD `*_demo`); guião em `northstar-demo-script.md`. Sem dados cloud/Kubernetes. |
| 8 | CRUD | Matriz em `commercial-readiness-acceptance.md`. |
| 9 | Segurança | Validação sem eco de segredos; RLS/isolamento testados; pip-audit limpo; `pnpm audit --audit-level high` limpo; Trivy HIGH/CRITICAL: 0 vulnerabilidades, 0 segredos, 0 misconfigs. `braces` (sem patch upstream) substituído por shim local sobre `brace-expansion` corrigido (`tools/braces-shim`; remover quando houver patch). |
| 10 | Deploy Hetzner | Pacote `deploy/hetzner-evaluation` pronto e **não executado**; sem acesso SSH. |
| 11 | CI | backend, frontend, migrations, secret-scan: **todos verdes** no PR #9; cobertura ≥75%. |

## Jornada E2E
setup → login → utilizador (mudança forçada) → cliente → engagement → âmbito/alvo → autorização PDF → ativação → ativo → importação → findings → relatório → PDF → auditoria → isolamento entre tenants. Verificada no browser (1920×1080 e 1366×768) sobre PostgreSQL 16 e como regressão automática (`tests/test_customer_journey.py`).

## Desempenho / recuperação
30 008 ativos e 60 009 findings; backup 0,38 s; restauro 1,58 s com contagens, versão Alembic 0018 e 135 políticas RLS idênticas (`restore-test.sh`).

## Lacunas conhecidas
- Hetzner nunca acedida: nada verificado no servidor real; matriz de deployment por executar.
- Servidor existente deve correr `ensure-rbac`; rodar `admin@cyberaudit.local` se o seed de demo alguma vez correu.
- Sem dados sintéticos de cloud/Kubernetes no demo.
- Shim `braces` é código mantido por nós (apenas ferramentas de desenvolvimento).
- ProductionReadinessGate: BLOCKED.

## Recomendação e próximas ações exatas
1. Rever e aprovar o PR #9 (draft; sem merge automático).
2. Fornecer acesso SSH ou correr a inspeção só de leitura do `RUNBOOK.md`.
3. Após aprovação explícita: executar `deploy.sh` num ambiente de avaliação, `smoke-test.sh`, `restore-test.sh`, ensaio do guião e só depois decidir sobre a instância pública.

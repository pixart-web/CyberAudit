# Decisões de arquitetura

## ADR-033 — Product Completion: real filters over ResourcePage duplication (Phase 10.4.1)

Accepted. Rather than building a bespoke detail-fetch layer per domain,
each new Workspace (Asset/Finding/Incident/Control) reuses the existing
generic `page()`/`_page()` tenant-scoped query helpers with one additional
`AND`-ed filter condition per related collection, and the pre-existing
`ResourcePage`'s `rowHref` prop for list→detail navigation. No new
authorization path is introduced: every new query parameter narrows an
already-tenant-scoped result set, never widens it, which
`test_workspace_filters_tenant_isolation.py` verifies directly (a caller
supplying another tenant's id gets an empty list, never that tenant's
row). The diagnostic bundle generator follows the same discipline: an
explicit allowlist of settings fields (never a blanket dump) plus the
existing `redact()` pipeline as a second layer, per ADR guidance that
"upload/export is never trusted merely because it happened" applies
equally to bundle *generation* — the code must positively justify why
each field is safe to leave, not merely fail to notice it isn't.

A correction is recorded here deliberately: an earlier pass in this same
phase overwrote two pre-existing, tested pages
(`apps/web/app/assets/[id]/page.tsx`, `apps/web/app/findings/[id]/page.tsx`)
outright with `Write` instead of reading them first, which also
introduced a data bug (wrong Asset field names — `hostname`/`ip_address`
instead of the schema's actual `fqdn`/`primary_ip`/`lifecycle_status`).
It was caught by the pre-existing `asset-360.test.tsx` failing immediately
after the change, both files were restored from git history, and the new
tabs were re-added around the original content instead of replacing it.
Documented here as a reminder that "read before write" is not optional
even under autonomous-milestone instructions.

## ADR-032 — Native distribution strategy honesty (Phase 10.4)

Accepted. Docker Compose remains the only tested deployment mode. No
native Windows/macOS/Linux installer was built in Phase 10.4 either —
building and signing a real per-OS installer is a substantial,
platform-specific undertaking (service registration, code signing,
upgrade/uninstall flows, notarization credentials this session does not
hold) that would only produce something that *looks* like an installer if
attempted without the real infrastructure. `docs/architecture/
phase-10.4-security-os-ux.md` records the concrete architecture for each
platform and marks each one's actual readiness (BLOCKED for all three
native paths) rather than claiming otherwise.

## ADR-031 — Security OS information architecture and Workspace pattern

Accepted. `CyberShell` (sidebar + header) is extended, not replaced:
`GlobalSearch` and `CommandPalette` route every query and every navigation
target through the same authorized, tenant-scoped endpoints and fixed
hrefs the rest of the app already uses -- neither introduces a new
authorization path. A `Workspace` is a page that fetches one root object
by ID plus its related collections as independent, lazily-enabled
queries, and presents them through the design system's `Tabs`. Only one
Workspace (Engagement) was fully built in this phase; it is the template
for Incident/Asset workspaces the brief describes, which remain deferred
-- see `phase-10.4-security-os-ux.md` for the explicit list of what
changed vs. what is still the pre-10.4 `ResourcePage` pattern.

## ADR-030 — Local-first deployment and installer honesty

Accepted. Docker Compose is the one deployment mode that actually exists,
is tested, and is loopback-bound by default (`127.0.0.1`, with an explicit
`docker-compose.remote.yml` opt-in for LAN exposure). Native Windows/macOS/
Linux installers are documented as an architecture sketch, not built —
`docs/architecture/local-installation.md` states this plainly rather than
claiming installer readiness that does not exist, per section 24 of the
implementation brief ("do not claim installers are production-ready unless
they are actually built and tested").

## ADR-029 — Offline update bundle format and signing

Accepted. A `.caup` bundle is a signed JSON manifest (Ed25519) plus a
checksum per file it carries; `UpdateBundleService.validate()` verifies the
signature against an administrator-configured `TrustedKeyStore`, checks
every file's SHA-256, and checks app-version compatibility — a bundle is
never trusted merely because it was manually uploaded. Validation only:
this phase does not stage, extract or apply a bundle, which are installer/
runtime concerns left to Phase 10.3.8 packaging work. See
`adr-029-offline-update-bundles.md`.

## ADR-028 — Engagement domain completion and reporting

Accepted. The Client → Engagement → Scope/Assets/Evidence/Findings chain
already existed; this closes the remaining gaps the engagement domain
needed (structured notes, a timeline, and generated reports) without
duplicating any of it. `EngagementNote` and `EngagementTimelineEntry` are
new, directly tenant- and engagement-scoped tables with PostgreSQL RLS
policies. `ReportService` assembles a `Report`/`ReportSection` tree purely
from already-recorded findings and evidence; an optional AI-generated
executive-summary section (via the existing `report_agent`) is always
tagged `content_type="ai_generated"` with its citations attached, and is
never merged into the `finding`/`evidence` sections it summarizes. See
`docs/architecture/adr-026-sovereign-local-ai-runtime.md` and
`adr-027-cyber-agent-runtime.md` for the AI/agent pieces it reuses.

## ADR-027 — CyberAgentRuntime and AgentToolGateway

Accepted. Ten specialized agents are one shared runtime parameterized by
configuration (mission, knowledge scope, allowed tools), not ten duplicated
chatbot classes. Agents never call a tool directly: every tool call passes
through `AgentToolGateway`, which enforces the agent's own tool allowlist,
RBAC permission, tenant-scoped data access and input validation, and writes
an audit event. No tool executes a shell command, SQL, or reaches
Docker/Kubernetes; each one only reads already-persisted, tenant-scoped
rows. See `adr-027-cyber-agent-runtime.md`.

## ADR-026 — Sovereign local AI runtime

Accepted. No core CyberAudit capability may require a commercial AI API; the
default `ai_runtime_backend=disabled` keeps the existing deterministic,
evidence-grounded `AiProvider` fully offline. A second, local-first provider
routes by *capability* (never by model brand) through a host-scoped model
registry and hardware profile, and only ever uses a local model to phrase
already-deterministic facts — never to invent findings, citations or
confidence. See `adr-026-sovereign-local-ai-runtime.md`.

## ADR-025 — Infrastructure evidence and release gating

Accepted. Production-like validation uses version-pinned local infrastructure
and stores only sanitized, checksum-bound summaries. An artefact's declared
`failed`, `partial` or `blocked` status overrides its mere existence. Backup,
restore, HA, DR, signing, provenance, vulnerabilities and external identity or
assessment controls require a non-automation reviewer. Same-host failover is
never DR, local provenance is never keyless identity, and the local release
target cannot create a tag. The protected release workflow depends on the
evidence gate and rejects unaccepted HIGH/CRITICAL vulnerabilities.

## ADR-024 — Production readiness closure

Production readiness is evidence-driven and tenant-scoped. PostgreSQL RLS is a
second authorization boundary using a restricted runtime role; identity
bootstrap exposes only an active organization UUID from a public slug. External
secrets and objects use Vault/S3 SDK boundaries with workload identity.
Ephemeral execution is delegated to a separately privileged HTTPS controller
using immutable operation-to-image mappings. Release promotion requires verified
SBOM, provenance and signatures. See
`adr-024-production-readiness-closure.md` and the closure evidence report.

## ADR-022 — Identity and cloud domain expansion

Accepted. Use common normalized records and a closed adapter registry instead
of provider-specific execution paths. Store secret-manager references only,
default connectors to read-only, preserve unknown posture, version
deterministic scores and prevent all external writes. See
`adr-022-identity-cloud-domain-expansion.md`.

1. **Tenant no token e na query.** O `organization_id` enviado pelo cliente nunca seleciona o tenant da operação.
2. **PostgreSQL como sistema de registo.** Redis fica reservado a rate limiting, filas e revogação de curta duração.
3. **Soft delete.** Clientes, auditorias, scopes, ativos, organizações e utilizadores conservam rastreabilidade.
4. **Storage abstraído.** Uploads usam nomes aleatórios, ficam fora da pasta pública e poderão migrar para S3.
5. **OIDC-ready.** A identidade está isolada no módulo de segurança; JWT local existe apenas para desenvolvimento.
6. **Sem execução ofensiva.** A Fase 1 cria guardrails e domínio, não integra ferramentas de pentesting.
7. **Dramatiq/Redis.** Jobs transportam apenas identificadores; o worker volta a ler e validar o estado persistido.
8. **Orquestrador único.** Routers não publicam diretamente na fila e adaptadores não são acessíveis pelo frontend.
9. **Registry fechado.** Não existe carregamento dinâmico de código fornecido por utilizadores.
10. **Resultados não confiáveis.** Raw output é limitado, sanitizado, tratado como texto não confiável e nunca renderizado como HTML.
11. **Rede centralizada.** Adaptadores não criam clientes HTTP; DNS, sockets, redirects, rate e bytes pertencem a `SecureHttpClient`/`SecureDnsResolver`.
12. **IP fixado por resolução.** A ligação usa o IP validado com Host/SNI original, impedindo uma segunda resolução implícita pelo cliente.
13. **Resultados reais explícitos.** `simulated`, `imported` e `verification_status` impedem misturar demonstrações, importações e observações confirmadas.
14. **XML defensivo.** Importações XML usam `defusedxml`; `cryptography` é usado apenas para parsing estruturado de certificados DER.
15. **PostgreSQL primeiro para o grafo.** Nós e relações vivem no sistema de registo relacional através de um repository; uma graph database é uma otimização futura, não uma fonte paralela de verdade.
16. **Descoberta TCP connect bounded.** Não há raw sockets, UDP, stealth, spoofing, evasão ou listas de portas livres; só perfis internos intersectados com políticas calculadas pelo backend.
17. **Sugestão antes de ativo.** Descobertas criam sugestões/observações. Promoção e merge requerem revisão para impedir inventory poisoning.
18. **Correlação conservadora.** CPE/PURL exatos podem produzir matches; similaridade é sempre heurística e exige revisão humana.
19. **AppSec offline-first.** OpenAPI e CycloneDX são analisados em storage privado, com limites estritos e sem resolver referências externas, clonar repositórios, instalar dependências ou executar imagens.
20. **Segredos como observações.** A persistência aceita fingerprint, tipo, localização, comprimento e máscara; não existe coluna para o valor bruto.
21. **Attack paths são hipóteses.** A análise é limitada por profundidade/quantidade, distingue factos de inferências e nunca executa passos do caminho.
22. **SOC defensivo e declarativo.** Regras e hunts usam campos e operadores allowlist; não existe `eval`, SQL livre ou resposta automática.
23. **Controlo GRC único.** Referenciais apontam para `UnifiedControl`, evitando duplicar implementação, owners e evidências.
24. **IA advisory-only.** Fornecedores implementam `AiProvider`; o contrato separa factos/inferências, exige fontes e mantém `action_executed=false`.
25. **PostgreSQL continua source of truth.** Security Data Lake e Knowledge Graph são projeções privadas e reconstruíveis.
26. **Lacuna da Fase 6 explícita.** O histórico recebido contém Fases 1–5. As Fases 7–9 não fingem fornecer OIDC/MFA/object storage/runners de produção previstos para a Fase 6.
27. **Produção falha fechada.** Configuração insegura impede startup em vez de degradar para SQLite, JWT local, filesystem ou runner local.
28. **Segredos são referências.** Só a fronteira do fornecedor pode resolver valores; persistência, filas, respostas e telemetria recebem referências/metadados.
29. **Sessão e token são independentes.** Tokens mantêm compatibilidade API; browsers recebem também uma sessão opaca revogável e CSRF separado.
30. **Conectores live são read-only.** Manifestos fechados, origens HTTPS exatas, sem redirects e contract test kit precedem qualquer ativação.
31. **Sem contentor genérico.** O runner recebe operações internas tipadas; descritores Docker/Kubernetes permanecem indisponíveis sem controlador de isolamento.
32. **Licença não apaga acesso.** Expiração bloqueia capacidades licenciadas e preserva leitura/extração de dados do cliente.
33. **Telemetria é opt-in.** Só campos agregados allowlisted podem sair; evidência, identidade, segredos e conteúdo ficam excluídos.
34. **IA local é opt-in e nunca decide.** Sem modelo instalado o CyberAudit responde de forma determinística; com modelo, este só reformula factos já calculados, nunca substitui o motor de segurança, o RBAC ou o Policy Engine.
35. **Agentes não têm acesso direto.** Todo o tool call de um agente passa pelo `AgentToolGateway`; nunca há acesso direto a base de dados, socket Docker ou shell a partir de um agente.
36. **Relatórios distinguem origem.** Cada `ReportSection` marca `content_type` (evidence/finding/analyst_conclusion/ai_generated); conteúdo gerado por IA nunca se torna evidência ou finding silenciosamente.
37. **Upload nunca é confiança.** Um bundle de atualização só é aceite com assinatura Ed25519 válida contra uma chave configurada pelo administrador, checksums corretos e versão compatível — nunca por ter sido carregado manualmente.
38. **Loopback por omissão.** A API e o web só ficam acessíveis em `127.0.0.1`; exposição na LAN exige um override explícito (`docker-compose.remote.yml`), nunca o padrão.
39. **Workspace nunca contorna o AgentToolGateway.** Ações contextuais de Cyber AI (ex.: "Summarize Assessment") chamam sempre endpoints existentes que passam pelo CyberAgentRuntime; nenhum atalho de frontend gera conteúdo de IA diretamente.
40. **Gestão de modelos nunca executa código.** A UI de Model Management só altera `install_status`/`trust_status` através da API já existente; nunca corre um artefacto descarregado.
41. **Instalador nunca é reclamado sem prova.** Docker Compose é o único modo de distribuição testado; instaladores nativos Windows/macOS/Linux permanecem arquitetura documentada, não construída.
42. **Diagnóstico é allowlist, nunca dump.** O gerador de diagnóstico só lê campos de configuração explicitamente listados (nunca `vars(settings)` ou equivalente) e passa tudo pelo `redact()` partilhado antes de sair do processo.
43. **Filtro nunca alarga o tenant.** Todo `?xxx_id=` novo adicionado a um endpoint de lista é sempre um `AND` sobre o `organization_id` já existente, nunca um `OR` ou uma substituição — verificado por teste de isolamento dedicado por cada filtro novo.
44. **Acessibilidade medida, não reclamada.** Uma alegação de acessibilidade sem uma execução real de uma ferramenta (axe-core, Lighthouse, leitor de ecrã) documentada não é feita; limitações da ferramenta (ex.: jsdom sem layout real) são registadas explicitamente, nunca omitidas.

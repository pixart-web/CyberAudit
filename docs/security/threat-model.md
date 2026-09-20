# Threat model

## Production-readiness boundary additions

- **Tenant-context omission or spoofing:** the API derives context from verified
  identity, PostgreSQL denies missing context and a non-bypass runtime role
  enforces read/write RLS. The OIDC bootstrap function returns only an active
  tenant UUID and has a fixed search path.
- **Phishing/session takeover:** OIDC uses PKCE/state/nonce and WebAuthn provides
  user-verified step-up. Challenge replay, credential counter rollback and
  inactive/unverified IdP identities fail closed.
- **Poison asynchronous messages:** the universal DLQ stores only sanitized
  metadata and opaque references. Replay requires step-up, schema/feature checks
  and a closed handler.
- **Secret/object exfiltration:** Vault and S3 endpoints are fixed deployment
  configuration; workload identity, tenant key prefixes, size/checksum controls
  and short-lived URLs constrain access.
- **Runner escape:** no user commands, arguments, images, environment or mounts
  enter the runner contract. Immutable images and a locked-down ephemeral
  security profile are mandatory.
- **Supply-chain substitution:** release jobs build once, identify artifacts by
  digest, generate SBOM/provenance, keylessly sign and verify identity before
  publication.

Residual risk remains high until these controls are exercised against real IdPs,
Vault/object storage, container/cluster controllers and an HA/DR environment.

## Enterprise connectors

New threats include credential disclosure, cross-tenant inventory access,
over-privileged provider consent, malicious or oversized connector payloads,
SSRF, change-event amplification, graph exhaustion and posture presented with
false confidence.

Controls are closed connector/adaptor allowlists, secret references, recursive
redaction, passive adapters, pagination, indexed tenant filters, bounded graph
responses, double validation in the worker, immutable external operation,
explicit unknown states, audit logs and low-cardinality metrics. External
provider collection remains disabled until provider SDK threat models and
integration tests are approved.

## Phase 5 additions

- **Malicious specifications/SBOMs:** bounded JSON parsing, record caps and
  external/file/traversal reference rejection.
- **Repository and dependency execution:** no clone, hooks, package manager,
  scripts or user-chosen filesystem paths.
- **Secret disclosure:** fingerprint-and-mask persistence only; field-level RBAC.
- **SSRF and rebinding:** all networked adapters require the central HTTP policy,
  pinned destination and safe methods.
- **Supply-chain confusion:** releases use immutable hashes/digests and gates
  distinguish declared, signed and verified provenance.
- **Cross-tenant inference:** every root query filters the authenticated
  organization; component access is joined through a tenant-owned SBOM.

## Ativos protegidos

Autorizações, âmbito, targets, dados de clientes, evidências futuras, tokens e audit logs.

## Ameaças principais e controlos

- Acesso cross-tenant: tenant derivado do JWT, filtros obrigatórios e testes.
- Escalada de privilégios: permissões granulares verificadas na API.
- Reutilização de refresh token: rotação por família e revogação em caso de replay.
- Password guessing: Argon2 e bloqueio temporário após cinco falhas.
- Upload malicioso: extensão, MIME, assinatura PDF, limite, SHA-256, nome aleatório e storage privado.
- Execução fora de âmbito: motor de políticas no backend e bloqueio explícito.
- Fuga de segredos por logs: metadados sanitizados e proibição de tokens/passwords.
- SSRF: scheme/porta/hostname são validados, DNS é fixado, classes especiais e metadata são bloqueadas e cada redirect volta a passar pelo scope.
- Bypass do âmbito entre fila e execução: revalidação obrigatória pelo worker.
- Job adulterado na base: nova validação de perfil, adapter, configuração, target e aprovação.
- Código malicioso em adapters: registry estático, sem imports indicados pelo utilizador.
- Injeção em raw output: limite, SHA-256, sanitização e armazenamento como conteúdo não confiável.
- Execução órfã: timeout e cancelamento cooperativo, com futura terminação pelo sandbox externo.
- Importação ativa/XXE: formatos allowlisted, tamanho/MIME/extensão, storage privado, `defusedxml`, preview e conteúdo inerte.
- Fuga por evidência: redação central, excertos limitados, downloads autorizados e headers defensivos.
- Inventory poisoning: descoberta cria sugestões, mantém fonte/confiança e regista mudanças; relações e matches ambíguos exigem revisão.
- Descoberta abusiva: CIDR, hosts, portas, taxa, concorrência e timeout têm máximos backend; perfis e portas são allowlisted.
- Pivot pelo worker: a rede de controlo é separada do laboratório e destinos continuam limitados ao scope calculado.
- Feed comprometido: schemas fechados, tamanho máximo, hash, sincronização auditada e sem código ou URLs executáveis vindos do feed.
- Falsos positivos de CVE: versões ausentes ou ambíguas produzem “insufficient information”/review, nunca confirmação automática.
- Grafo excessivo ou cíclico: limites progressivos de nós, profundidade, caminhos e proteção contra ciclos.
- Simulador destrutivo: cenários são projeções isoladas e não alteram findings, ativos ou estado operacional.

## Risco residual

O JWT local, storage local e execução in-process são adequados apenas a desenvolvimento. Produção requer OIDC, KMS/secret manager, malware scanning, object storage, runner efémero não-root e egress enforcement externo ao processo Python.
# Extensão Enterprise (Fases 7–9)

## Novos ativos

- eventos, IOCs, deteções, casos e timelines;
- controlos, evidências GRC e decisões de aceitação de risco;
- nós/arestas do Knowledge Graph e respostas assistidas.

## Novas ameaças e controlos

- **Event poisoning:** schema allowlist, deduplicação, `trusted=false` por
  defeito e proveniência.
- **Detection-as-code injection:** operadores fechados, sem regex/SQL/eval.
- **Cross-tenant correlation:** todas as leituras e fingerprints incluem
  `organization_id`.
- **Playbook abuse:** passos não-executáveis e `automatic_execution=false`.
- **Evidence tampering:** hashes, storage privado, timeline append-only e audit
  logs.
- **Framework confusion:** mapeamentos versionados para um controlo único e
  seeds explicitamente demonstrativos.
- **Prompt injection e hallucination:** fontes internas selecionadas pelo
  backend, saída estruturada, factos/inferências separados, confiança,
  limitações e recusa sem fontes.
- **AI data exfiltration:** fornecedores externos desativados, política de
  classificação/residência e nenhum segredo na configuração.
- **Autonomous action:** não existe tool calling nem endpoint que converta uma
  resposta em mutação.

# Product Hardening (Fase 10)

- **Configuração insegura em produção:** validação tipada rejeita defaults,
  SQLite, HTTP/cookies inseguros, autenticação local, storage local, fixtures e
  runner in-process.
- **OIDC mix-up/replay:** issuer e endpoints fixos, PKCE, nonce, state Redis
  single-use e validação de assinatura/audience/expiry.
- **Session theft:** apenas hashes server-side, idle/absolute expiry, limite de
  sessões, cookies SameSite/Secure e revogação remota.
- **Escalada por mapeamento externo:** JIT pendente por defeito, mapeamentos
  versionados por tenant e step-up para permissões administrativas.
- **Supply-chain connector:** registry/manifesto fechado, versão mínima,
  permissões read-only e nenhuma carga dinâmica fornecida pelo utilizador.
- **Runner/container escape:** nenhum comando livre; produção exige workload
  efémero não-root, read-only, sem capabilities/host mounts/socket e egress
  allowlist. O controlador externo continua bloqueado até ser validado.
- **Upload/archive abuse:** limites, MIME allowlist, basename, double-extension,
  archive entry/ratio limits, zip-slip defense e quarentena.
- **License/telemetry abuse:** assinaturas Ed25519 e preview allowlist opt-in;
  expiração não impede acesso aos dados do cliente.

## Riscos residuais da Fase 10

Integrações reais de secret manager/object storage, WebAuthn, controladores
efémeros, PostgreSQL RLS por sessão e HA/DR medido dependem de infraestrutura
externa. As interfaces falham fechadas, mas esses controlos só podem ser
considerados eficazes após testes nos ambientes de destino.

# Infrastructure Validation (Fase 10.2)

- **Evidência forjada ou obsoleta:** manifesto tipado, paths confinados,
  artefactos não vazios, SHA-256, ambiente/versão, timestamps com timezone,
  expiração e rejeição de reviewers automáticos nos controlos humanos.
- **CA de laboratório abusada:** chaves privadas ficam em runtime ignorado; os
  testes não ignoram TLS e a instalação de confiança global exige decisão
  explícita do operador.
- **Falso HA/DR:** réplica de aplicação no mesmo host é marcada `partial`; restore
  no mesmo Docker host nunca conta como DR completo.
- **Compromisso da supply chain:** versões fixas, SBOM CycloneDX/SPDX, scans de
  filesystem/imagens/manifests e bloqueio em HIGH/CRITICAL sem aceitação formal.
- **Assinatura local não atribuível:** nenhuma chave local é fabricada como
  substituto; a assinatura keyless exige identidade OIDC do workflow protegido.
- **Publicação prematura:** o alvo local avalia primeiro o gate e não cria tags;
  controlos externos continuam a exigir revisão humana independente.

# Security OS Experience & Local Distribution (Phase 10.4)

New attack surfaces introduced in this phase, per section 66.

- **GlobalSearch as an authorization bypass:** it queries findings/incidents/
  engagements through their own existing, already-authorized endpoints
  (`?q=`), never a new aggregate search index. A tenant/permission a caller
  lacks simply fails that one request; there is no separate search-index
  service that could drift out of sync with RBAC/RLS.
- **CommandPalette as a command-injection surface:** it is a static list of
  fixed `href`s built from the existing sidebar route table; there is no
  free-text-to-action mapping, no eval, and no way to name a route that
  is not already in that table. It cannot become a shell.
- **Engagement Workspace "Summarize Assessment" as an AI bypass:** the
  button calls the existing `POST /engagements/{id}/reports` with
  `include_ai_summary=true` — the same `CyberAgentRuntime`/
  `AgentToolGateway` path Phase 10.3 already threat-modeled (ADR-027).
  No new AI invocation path was added; the frontend cannot construct a
  request that skips tenant/permission checks, because those checks live
  in the backend route, not in the browser.
- **Model Management UI as a code-execution vector:** every action
  (register, activate, deactivate) is a metadata write through the
  existing `ai_runtime_api` endpoints. There is no "run" or "load" action
  in the UI, and the backend never executes a model artifact's bundled
  code (ADR-026's existing invariant, unchanged by this phase).
- **Update Manager UI as a blind-trust vector:** it only ever calls
  `POST /updates/validate`; there is no upload path that stages, extracts
  or applies a bundle. A malicious or malformed bundle can only ever
  produce a rejection with a reason string — it cannot reach the
  filesystem or the database.
- **Local Docker Compose exposure:** the base `docker-compose.yml` binds
  API/web to `127.0.0.1` only (Phase 10.3.8); `docker-compose.remote.yml`
  is an explicit, separately-invoked opt-in, never the default.

## Deferred, not fabricated

A privacy-safe diagnostic bundle generator (section 49) was **not**
implemented in this phase — building it correctly requires wiring the
existing redaction pipeline (`cyberaudit/redaction.py`) into a new export
path with an explicit allowlist of what may leave the environment, which
is real, non-trivial work. Attempting a shortcut version risked exactly
the "no fake implementations" failure mode this phase's brief warns
against, so it is recorded here as deferred rather than half-built.

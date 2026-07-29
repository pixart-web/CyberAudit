# ADR-022 — Identity, Cloud e Zero Trust Domain Expansion

Estado: aceite em 2026-07-29.

## Contexto e baseline

A expansão parte de `b0954cc`, com Fases 1–5 e 7–9 operacionais. Reutiliza:

- `Organization`, `User`, RBAC, `AuditLog`, `Evidence`, `Finding`, jobs e scopes;
- `EnterpriseRisk` e os endpoints Risk Engine 3.0;
- `KnowledgeNode`/`KnowledgeEdge` e o worker de projeção;
- `SecurityDataObject`, `SecurityEvent`, alertas, incidentes e casos;
- `UnifiedControl`, mappings, assessments e evidence links;
- `AiProvider` e o contrato advisory-only.

Identidades externas nunca são `User` do CyberAudit. Inventário, postura,
findings, eventos e riscos permanecem conceitos separados.

## Decisão

### Fronteiras

- **Connector** gere autorização local, scope, cursor, saúde e execuções. Nunca
  contém uma primitiva de alteração externa.
- **Identity** representa providers, identidades, grupos, roles, permissões,
  relações e postura de autenticação.
- **Directory/SaaS** usa objetos tipados extensíveis para AD, Entra, Microsoft
  365 e Google Workspace; dados específicos vivem em metadata limitada.
- **Cloud** usa contas, recursos, redes, identidades, roles, assignments e
  snapshots comuns a AWS, Azure e GCP.
- **Workload** separa Kubernetes e runtimes de containers.
- **Device** separa endpoints e mobile.
- **Zero Trust** é um cálculo determinístico versionado, não uma decisão de
  acesso.

### Credenciais e read-only

`ConnectorCredential` guarda apenas um `secret_reference`, fingerprint, tipo e
datas. O segredo pertence a um secret manager. A implementação local aceita
referências `development://` sintéticas, nunca valores. APIs omitem referências
internas e nunca devolvem material secreto.

Conectores começam `read_only=true`, exigem scope e capabilities allowlist.
Syncs recebem apenas IDs, são auditados, canceláveis, incrementais e
idempotentes. Não há SDKs cloud, LDAP, PowerShell, comandos, alteração de
políticas ou execução remota nesta expansão; os adaptadores iniciais processam
fixtures/imports sintéticos e autorizados.

### Graph, Risk, SOC e GRC

Projeções escrevem no Knowledge Graph existente com chave
`organization_id + node_type + source_id`. Arestas são idempotentes, incluem
fontes, confiança e `inferred`.

Identity/Cloud risk são evaluators do modelo Risk 3.0 e produzem fatores
explicáveis; não criam um motor paralelo. Attack Graph 3.0 consulta apenas
relações observadas ou inferências declaradas e nunca afirma comprometimento.

Change events podem alimentar timeline, deteções e recálculo, mas não efetuam
ações. Evidências e mappings GRC reutilizam as tabelas existentes.

### Escala

As tabelas usam índices compostos por tenant, provider/type, external ID,
status, risco e `last_seen_at`. Endpoints são paginados e grafos têm limites
explícitos. Sync incremental preserva cursor e hash de snapshot; não recalcula
todo o tenant em cada alteração.

## Riscos e dívida

- Não existe secret manager de produção, OIDC/MFA de produção ou runners
  efémeros; são bloqueadores.
- Os conectores iniciais não contactam fornecedores reais. Integrações futuras
  exigem apps read-only, consentimento, egress allowlist, rate limits e revisão.
- Metadata JSON é limitada por schemas, mas domínios de grande escala deverão
  evoluir para particionamento e retenção.
- O catálogo Security Data Lake continua metadata-only.
- Zero Trust é postura/evidência e não substitui enforcement.
- Conteúdo normativo e certificação automática continuam fora de âmbito.

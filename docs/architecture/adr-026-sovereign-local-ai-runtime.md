# ADR-026 — Sovereign Local AI Runtime

Estado: aceite em 2026-09-20.

## Contexto e baseline

A expansão parte de `98209c3` (branch `codex/sovereign-ai-local-runtime`), com
as Fases 1–9 e o hardening/readiness da Fase 10 operacionais. Reutiliza:

- `AiProvider`, `AiQuestion`, `GroundedAnswer` e `AiAssistantService`
  (`enterprise_services.py`), já com contrato advisory-only, citações e
  `reproducibility_key`;
- `AiAssistantRequest` e `KnowledgeNode`/`KnowledgeEdge` (`enterprise_models.py`);
- `DeterministicGroundedProvider`, o único provider até agora, que responde
  offline sem qualquer modelo.

Esta ADR não substitui esse contrato: estende-o com um segundo `AiProvider`
local-first e introduz a infraestrutura de que esse provider depende (perfil
de hardware, registo de modelos, encaminhamento por capability).

## Decisão

### Princípio de soberania

Nenhuma funcionalidade central do CyberAudit pode depender de uma API de IA
comercial (OpenAI, Anthropic, Gemini, etc.). O backend por omissão
(`ai_runtime_backend=disabled`, ver `config.py`) não contacta nenhum serviço:
`DeterministicGroundedProvider` continua a responder com factos, citações e
`confidence` calculados apenas a partir do Knowledge Graph do tenant. Um
administrador ativa explicitamente um backend local self-hosted (`ollama`)
apontando para infraestrutura sob o controlo do próprio cliente.

### Camadas (`cyberaudit/ai_runtime.py`)

```
AiAssistantService (existente)
        |
LocalFirstProvider (AiProvider)
        |
CapabilityRouter  --  ModelRegistryService  --  ai_model_manifests (DB)
        |
InferenceBackend (Disabled | Ollama)
```

- **HardwareCapabilityService** deteta SO, arquitetura, CPU, RAM total/livre,
  disco e GPU (best-effort via `nvidia-smi`/Apple Silicon), sem acesso
  privilegiado. Classifica em `lite/standard/professional/enterprise`.
- **ModelRegistryService** é a fronteira CRUD sobre `AiModelManifest`
  (`ai_runtime_models.py`): metadata do modelo (família, quantização,
  contexto, requisitos de RAM/VRAM, licença, `sha256`, `install_status`,
  `trust_status`). A tabela é deliberadamente *host-scoped*, não
  tenant-scoped — os pesos existem uma vez no disco do host e são partilhados
  por todos os tenants dessa instalação, tal como o broker Redis. O acesso é
  controlado por RBAC (`ai_runtime.read`/`ai_runtime.manage`), não por RLS.
- **CapabilityRouter** resolve uma capability (ex.: `"knowledge_query"`) para
  um manifesto instalado, com trust não revogado, que caiba na RAM disponível.
  Nenhum módulo de negócio escolhe uma marca de modelo diretamente.
- **InferenceBackend** é uma interface mínima (`health_check`, `generate`).
  `DisabledInferenceBackend` é o padrão sem rede; `OllamaInferenceBackend` é
  um cliente HTTP real para um servidor Ollama local (aceita `transport`
  injetável para testes, tal como `VaultSecretProvider`).
- **Local embeddings e retrieval** (`cyberaudit/local_retrieval.py`,
  10.3.3): `EmbeddingBackend` segue o mesmo padrão (`DisabledEmbeddingBackend`
  por omissão; `OllamaEmbeddingBackend` real via `/api/embeddings`).
  `LocalRetrievalService.rank()` usa o embedding local quando saudável e
  configurado (`AI_RUNTIME_EMBEDDING_MODEL`); caso contrário cai para um
  score lexical determinístico (Jaccard sobre palavras), nunca ficando
  indisponível. `CyberAgentRuntime` usa este serviço para reduzir um lote
  de candidatos do Knowledge Graph às 20 fontes mais relevantes para a
  pergunta — o mesmo limite que `DeterministicGroundedProvider` já aplicava
  arbitrariamente por ordem alfabética de `source_id`. O ranking nunca lê a
  base de dados por si próprio: recebe sempre um conjunto já filtrado por
  `organization_id` pelo chamador, preservando a fronteira de tenant.

### O modelo nunca inventa factos

`LocalFirstProvider.answer()` constrói sempre a resposta determinística
primeiro (via `DeterministicGroundedProvider`, reaproveitado como fallback).
Se um modelo local está instalado e saudável, o modelo é usado **apenas** para
reformular esses factos em texto (`build_grounded_prompt`); `facts`,
`citations`, `confidence` e `reproducibility_key` nunca vêm do modelo. Se o
router não resolve nenhum modelo, ou o `health_check` falha, ou a geração
falha, a resposta degrada de imediato para o texto determinístico, anotando a
razão em `limitations` — nunca fica indisponível.

### Defesa contra prompt injection

`build_grounded_prompt` separa explicitamente instruções de sistema de
`RETRIEVED_FACTS`, instrui o modelo a nunca seguir comandos aí contidos e
passa cada facto por `redact_text` antes de o incluir. As fontes retidas
podem conter conteúdo hostil (relatórios importados, logs); o modelo é
instruído a tratá-las como dados, nunca como instruções — ver também
`docs/security/threat-model.md`.

### Migração e permissões

`0016_ai_runtime_model_registry.py` cria `ai_model_manifests` seguindo o
padrão `Base.metadata.create_all` já usado nas migrações 0008+. As permissões
`ai_runtime.read`/`ai_runtime.manage` seguem o seed de `seed_enterprise.py`:
Administrator e Auditor têm ambas, Reviewer só leitura, Client nenhuma.

## Riscos e dívida

- Não existe ainda descarregamento real de pesos de modelo, verificação de
  assinatura de manifesto, nem UI. `install_status`/`trust_status` são
  campos de estado geridos pelo administrador via API; o "download" em si
  fica fora de âmbito desta fase e está documentado como tal (ver seção 55
  do pedido: sem implementações fingidas).
- `OllamaInferenceBackend` é o único backend real implementado; llama.cpp e
  vLLM ficam como extensões futuras da mesma interface `InferenceBackend`,
  sem alterar `CapabilityRouter` nem `LocalFirstProvider`.
- A classificação de hardware é heurística (thresholds de RAM/VRAM) e não uma
  benchmark real de desempenho.
- `AiAssistantService` continua, por omissão, a usar
  `DeterministicGroundedProvider`; wiring de `LocalFirstProvider` no router
  HTTP (`enterprise_api.py`) fica para um milestone seguinte, para não
  acoplar a ativação do runtime a uma alteração de comportamento por omissão
  não solicitada.

# ADR-027 — CyberAgentRuntime and AgentToolGateway

Estado: aceite em 2026-09-20.

## Contexto e baseline

Continua diretamente de ADR-026: reutiliza `AiProvider`,
`DeterministicGroundedProvider`, `AiQuestion`/`GroundedAnswer` e
`KnowledgeNode` (`enterprise_services.py`, `enterprise_models.py`), e as
permissões RBAC já existentes (`findings.read`, `incidents.read`,
`scopes.read`, `ai_assistant.read/use`).

O pedido de implementação (secção 17) exige dez agentes lógicos (Security
Analyst, SOC Analyst, Incident Analyst, Identity Analyst, Cloud Analyst,
Risk Analyst, GRC Analyst, Knowledge Analyst, Report Agent, Remediation
Advisor) sem os implementar como "dez wrappers de chatbot duplicados", e um
`AgentToolGateway` que impede um LLM de aceder diretamente à base de dados,
ao socket Docker ou a um shell.

## Decisão

### Um runtime, dez configurações

`cyberaudit/agent_runtime.py` define `AgentDefinition` (código, missão,
`service_literal` que mapeia para o `Literal` já existente em `AiQuestion`,
`knowledge_scopes` e `allowed_tools`) e um único `AGENT_CATALOG`. Não existe
uma classe por agente: `CyberAgentRuntime.ask()` é o único ponto de entrada,
parametrizado pelo `agent_code`. `knowledge_scopes=()` (Knowledge Analyst)
significa "sem restrição de `node_type`", nunca "sem tenant" — o filtro por
`organization_id` é incondicional.

### AgentToolGateway

```
Agent -> allowed_tools (estático, por AgentDefinition)
      -> RBAC (user_has_permission, cyberaudit.security)
      -> validação de input (pydantic, por tool)
      -> execução (handler read-only, filtrado por organization_id)
      -> audit event (write_audit)
```

`user_has_permission` foi extraído de `require_permission` em `security.py`
para ser reutilizável fora do contexto HTTP (`Depends`), sem duplicar a
lógica de verificação de permissões.

As três tools iniciais (`get_finding`, `list_incidents`,
`get_engagement_scope`) só leem linhas já persistidas, sempre filtradas por
`user.organization_id`; nenhuma aceita SQL livre, comandos ou identificação
de recursos fora do tenant do chamador. Uma tool não listada em
`agent.allowed_tools` é recusada antes de qualquer verificação de permissão
— o agente nunca "tenta e falha", o gateway nem chega a resolver a tool.

### Saída estruturada e aprovação humana

`AgentAnswer` estende o contrato de `GroundedAnswer` com `agent_code`,
`correlation_id` (auditável, gerado por pedido) e
`required_human_approval` — verdadeiro quando a confiança determinística é
baixa (`< 0.5`) ou quando o agente é o `remediation_advisor` (que só propõe,
nunca executa remediação).

### Defesa contra prompt injection

Como em ADR-026, factos vindos do Knowledge Graph podem conter texto
adversarial. `CyberAgentRuntime.ask()` nunca interpreta o conteúdo de um
`KnowledgeNode.label`/`facts` como instrução; é passado como dado opaco ao
`AiProvider` configurado. Não existe nenhum caminho por onde responder a uma
pergunta possa desencadear uma chamada a uma tool — a única forma de invocar
`AgentToolGateway` é um pedido HTTP explícito e autorizado separado
(`POST /api/v1/agents/{agent_code}/tools/{tool_name}`).

## Riscos e dívida

- `AiAssistantRequest` (persistência existente para `ai_assistant.use`) não
  é reutilizado para respostas de agentes nesta fase — `AgentAnswer` fica
  apenas na resposta HTTP mais o evento de auditoria
  (`agent.answered`/`agent.tool_invoked`). Uma tabela dedicada para histórico
  de execuções de agentes é trabalho futuro.
- Apenas três tools estão implementadas. Novas tools devem seguir o mesmo
  padrão (`AgentTool` + handler read-only tenant-scoped) e nunca expor
  escrita, execução remota ou acesso a infraestrutura.
- `LocalFirstProvider` (ADR-026) ainda não está ligado como provider por
  omissão de `CyberAgentRuntime`; usa `DeterministicGroundedProvider` tal
  como `AiAssistantService`.

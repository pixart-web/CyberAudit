# NODUS integration contract v1

Estado: contrato preparatório. Nenhuma integração NODUS está ativa.

## Princípios

- CyberAudit funciona sem NODUS e sem Internet.
- Integração é opt-in, permissionada e revogável.
- Não existe upload automático de dados de clientes.
- Endpoints, chaves e identidade de NODUS são configuração futura, não defaults.
- Eventos preservam tenant, ator, timestamp, origem e versão do schema.

## Identidade da aplicação

```json
{
  "contract_version": "1.0",
  "application_id": "com.pixart.cyberaudit",
  "product": "CyberAudit OS",
  "capabilities": [],
  "instance_id": "installation-scoped UUID",
  "offline_capable": true
}
```

`instance_id` não identifica uma pessoa e não é enviado sem consentimento.

## Contexto recebido

Uma integração futura pode fornecer:

- subject externo verificável;
- organização externa e mapping local explícito;
- locale e timezone;
- entitlement assinado;
- destino de navegação allowlisted.

O contexto externo nunca substitui diretamente `organization_id`, roles ou
permissions locais. O backend valida um mapping administrado e auditado.

## Module registration

CyberAudit publica metadados declarativos: código do módulo, label localizada,
rota interna allowlisted, permissions necessárias e estado de disponibilidade.
Não aceita código, comandos, SQL ou componentes remotos como módulos.

## Eventos

Envelope mínimo:

```json
{
  "schema": "pixart.nodus.event/1",
  "event_id": "UUID",
  "occurred_at": "RFC3339",
  "application_id": "com.pixart.cyberaudit",
  "instance_id": "UUID",
  "organization_ref": "opaque mapping reference",
  "type": "cyberaudit.resource.changed",
  "classification": "internal",
  "payload": {}
}
```

Payloads usam schemas fechados, limites de tamanho, idempotency por `event_id` e
redação antes de sair do processo. Evidência, passwords, tokens, secrets e raw
outputs não são eventos.

## Licensing

NODUS pode fornecer no futuro um entitlement assinado. CyberAudit mantém
verificação offline Ed25519 e comportamento seguro em expiração. Falha de NODUS
não bloqueia acesso aos dados do cliente.

## Navegação e notificações

Destinos são códigos registados, nunca URLs livres. Notificações contêm apenas
metadata mínima e uma referência local. Abrir uma notificação volta a executar
RBAC/RLS dentro do CyberAudit.

## Sincronização futura

Qualquer sync exige decisão adicional sobre propriedade, consentimento,
conflitos, retenção, residência, chaves e recuperação. Este contrato não ativa
sync nem define um endpoint de produção.

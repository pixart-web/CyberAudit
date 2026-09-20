# Network & Systems Intelligence

O fluxo é API → RBAC → ScopePolicyEngine → JobOrchestrator → Redis → worker → segunda avaliação → adapter allowlisted → normalização → inventário.

Os adapters `host_discovery`, `port_discovery` e `service_identification` usam exclusivamente TCP connect. Portas vêm de perfis internos e são intersectadas com a política imutável calculada pelo backend. OS, exposição e vulnerabilidades são inferidos apenas quando existe evidência suficiente; caso contrário devolvem limitações explícitas.

Observações têm fonte, confiança, timestamps e histórico. Hosts descobertos entram como `AssetSuggestion`; serviços e IPs observados são atualizados de forma idempotente.

# Guião de demonstração — Northstar Industries

Pré-requisitos: base `*_demo` com `admin_cli seed-northstar`; `ENVIRONMENT=demo`. Palavra-passe de demo definida por `DEMO_ADMIN_PASSWORD` (nunca em docs). Resoluções validadas: 1920×1080 e 1366×768.

| # | Cena | Utilizador | Ação | Resultado esperado |
|---|------|-----------|------|--------------------|
| 1 | Login | ana.costa@northstar-demo.example.com | Entrar | Nome/organização reais no topo |
| 2 | Dashboard | Ana | Ver métricas | Valores calculados da BD (sem números fixos) |
| 3 | Clientes/Engagements | Ana | Abrir engagement ativo, ver âmbito e autorização | Autorização assinada visível |
| 4 | Ativos e findings | Rui (Analyst) | Filtrar findings críticos, abrir um | Evidência e estado de verificação |
| 5 | Nova evidência | Rui | Carregar ficheiro | SHA-256 registado; ficheiro privado |
| 6 | Importação | Rui | Importar CSV, pré-visualizar, confirmar | Findings criados + notificação |
| 7 | Cyber AI | Ana | Pedir análise de incidente | Resposta só com factos suportados por evidência |
| 8 | Relatório | Ana | Gerar relatório e exportar PDF | PDF profissional descarregado |
| 9 | Controlo de acesso | Inês (Viewer) | Tentar criar cliente | Botões ausentes / 403 |
| 10 | Saúde do sistema | Ana | Abrir saúde | Migração, versão e fila reais |
| 11 | Auditoria | Ana | Ver registo de auditoria | Ações das cenas anteriores |
| 12 | Conta | Ana | Alterar palavra-passe | Sessões antigas revogadas |

Limitações a declarar honestamente: dados de cloud/Kubernetes não semeados; produção NÃO declarada pronta (ProductionReadinessGate BLOCKED); Hetzner não verificado.

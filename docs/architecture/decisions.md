# Decisões de arquitetura

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

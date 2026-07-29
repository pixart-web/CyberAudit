# Decisões de arquitetura

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
19. **Attack paths são hipóteses.** A análise é limitada por profundidade/quantidade, distingue factos de inferências e nunca executa passos do caminho.

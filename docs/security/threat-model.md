# Threat model

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

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

## Risco residual

O JWT local e o storage local são adequados apenas a desenvolvimento. Produção requer OIDC, KMS/secret manager, malware scanning, object storage e controlos de rede adicionais.

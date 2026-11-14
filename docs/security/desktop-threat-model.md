# Threat model do runtime desktop

Estado: revisão D3 parcial, 2026-11-07. O runtime ainda não é uma distribuição
instalável e este documento não substitui validação em Windows/macOS limpos.

## Âmbito e ativos

O âmbito cobre o shell Tauri, servidor Next local, API FastAPI, worker,
PostgreSQL, broker Redis-compatible e diretórios locais. Os ativos principais
são credenciais, tokens, dados multi-tenant, evidência, relatórios, modelos,
knowledge packs, backups, logs e artefactos de atualização.

Não estão no âmbito desta revisão o kernel do sistema operativo, firmware,
full-disk encryption, modelos de IA de terceiros ou um atacante que já controla
a conta/host com privilégios administrativos.

## Fronteiras de confiança

```text
utilizador
  -> webview Tauri
  -> Next loopback (proxy same-origin)
  -> FastAPI loopback (capability efémera + autenticação/RBAC)
  -> PostgreSQL / Valkey privados
  -> worker e adaptadores allowlist
  -> dados locais fora do bundle
```

O Internet, NODUS, feeds, IdP, modelos e updates são fronteiras opcionais e não
podem ser necessários para o core offline. O renderer/webview é conteúdo menos
privilegiado; não recebe o segredo da API nem uma API de shell/processo.

## Ameaças e controlos

| Ameaça                                                | Impacto                         | Controlos implementados nesta etapa                                                                                                                                                           | Risco residual / próximo controlo                                                                                                                                          |
| ----------------------------------------------------- | ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Processo local chama diretamente a API                | ações privilegiadas             | bind loopback; capability de sessão com comparação constante; health/readiness são as únicas exceções; RBAC continua obrigatório                                                              | o proxy Next ainda é uma superfície loopback; autenticação de utilizador, rate limit e origin estrito reduzem abuso, mas deve ser migrado para canal Tauri autenticado/IPC |
| Browser externo faz CSRF/DNS rebinding contra o proxy | alteração de dados              | web origin exato; rejeição de `Origin`, `Host` lógico e `Sec-Fetch-Site` cross-site; CORS não wildcard                                                                                        | clientes nativos conseguem omitir headers de browser; continuam sujeitos a autenticação/RBAC                                                                               |
| Segredo fica no JavaScript, argumentos ou logs        | bypass local                    | capability efémera de 256 bits em ficheiro server-only 0600; segredos persistentes têm contas fixas numa abstração Keychain/Credential Manager; launch plan sanitizado não serializa ambiente | ligação do cofre e do launch plan ao lifecycle real e validação em Windows/macOS limpos continuam pendentes                                                                |
| Sidecar ou dependência substituído/adulterado         | execução de código              | manifesto v2 cobre recursivamente executáveis, bibliotecas e módulos; ausência, extra, duplicado ou hash errado falha fechado                                                                 | SHA-256 local não prova origem; bundles e updates precisam de assinatura e proveniência                                                                                    |
| Path traversal/symlink no manifesto                   | leitura/execução fora do bundle | paths absolutos, componentes não normais, `\\`, symlinks e ficheiros não regulares são rejeitados; entrypoints continuam numa allowlist fixa                                                  | validar também permissões, owner e assinatura do bundle                                                                                                                    |
| Dados gravados dentro da aplicação                    | perda em upgrade/uninstall      | layout OS-specific; backup offline atómico com manifesto, SHA-256 e restore apenas para destino inexistente                                                                                   | restore entre máquinas requer exportação cifrada de credenciais; uninstall e upgrade de package anterior continuam por validar                                             |
| Listener exposto na LAN                               | roubo/acesso remoto             | configurações desktop exigem HTTP loopback; origem também loopback; quatro listeners são reservados exclusivamente em `127.0.0.1`                                                             | o supervisor deve manter a posse até cada spawn e confirmar a identidade/readiness do processo                                                                             |
| Password de serviço exposta em argumentos/config      | descoberta por processo local   | PostgreSQL usa ficheiro temporário 0600 removido após `initdb`; clientes usam ambiente fechado; broker recebe configuração e password por pipe; nenhum segredo entra nos argumentos           | validar ACL Windows, crash durante bootstrap e inspeção de memória em builds nativos                                                                                       |
| Renderer comprometido tenta shell arbitrário          | RCE                             | capability Tauri apenas `core:default`; sem shell plugin; launch plan contém executáveis/argumentos fixos, limpa o ambiente e redireciona logs privados                                       | rever cada futura permission/capability e manter comandos nativos tipados                                                                                                  |
| Crash deixa serviços órfãos                           | disponibilidade/porta exposta   | arquitetura define children conhecidos e shutdown inverso                                                                                                                                     | supervisor e kill-on-parent por plataforma ainda estão parciais                                                                                                            |
| Restore/update malicioso                              | corrupção/RCE                   | restore rejeita traversal, symlink, ficheiro extra, hash/tamanho incorreto e versão incompatível; staging é removido em falha e nunca sobrepõe destino                                        | updates continuam a exigir assinatura, backup pré-migração e política para migrações irreversíveis                                                                         |
| Debug e release partilham credenciais                 | perda de acesso ou mistura      | namespaces development/production separados; dados legacy exigem migração explícita, preflight de conflitos e preservação da origem                                                           | produção requer Developer ID estável; bundles ad-hoc não oferecem identidade de upgrade                                                                                    |
| Outro utilizador do host lê dados                     | confidencialidade               | diretórios 0700 e segredo 0600 no Unix                                                                                                                                                        | ACL Windows, Keychain/DPAPI, backup encryption e full-disk encryption devem ser validados                                                                                  |

## Propriedades que não podem regredir

- autenticação, RBAC, RLS e tenant isolation continuam ativos em desktop;
- nenhum `organization_id` fornecido pelo renderer estabelece contexto de
  autorização;
- nenhum adaptador recebe comandos, paths ou ambiente arbitrários;
- demo e resultados sintéticos permanecem identificados e separados;
- o produto funciona sem IA, NODUS, Hetzner ou Internet;
- logs não incluem tokens, passwords, segredo de sessão ou evidência crua.

## Bloqueadores para produção

Faltam supervisor completo, integração/validação do Keychain/Credential Manager, binários sidecar redistribuíveis,
assinatura do manifesto, backup/restore real, updater assinado, testes offline,
clean install, upgrade e uninstall em Windows x64, macOS ARM64 e macOS x64. A
ausência destes controlos mantém o desktop em estado `PARTIAL`.

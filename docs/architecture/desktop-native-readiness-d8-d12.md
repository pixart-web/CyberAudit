# Desktop native readiness — D8–D12

Estado: implementação em curso em 2026-11-13. Este documento distingue build
nativo, instalação limpa e release de produção; não converte CI em evidência de
máquina limpa.

## Keychain e identidade da aplicação

O diagnóstico comparou os bundles reais sem ler qualquer segredo. Ambos eram
assinados ad-hoc, não tinham Team ID e tinham requisitos designados ligados a
CDHash diferentes:

| Bundle  | identifier observado                  | CDHash observado                           |
| ------- | ------------------------------------- | ------------------------------------------ |
| debug   | `cyberaudit_desktop-33a8d8ba5d45f643` | `03cebf6f8d7f49b5dfa94f2cf756b1156ca7253a` |
| release | `cyberaudit_desktop-0abe744ce67ac467` | `add6c323d5cc93b5162ebd8a6c2cb3acb2d7a130` |

O Keychain associa o ACL ao requisito de código. Por isso, o release ad-hoc não
podia reutilizar automaticamente items criados pelo debug, apesar de ambos
usarem o antigo serviço `com.pixart.cyberaudit.desktop`.

A correção separa namespaces:

- development: `com.pixart.cyberaudit.desktop.development.v1`;
- production: `com.pixart.cyberaudit.desktop.production.v1`;
- legacy, apenas como origem explícita: `com.pixart.cyberaudit.desktop`.

Uma instalação limpa cria um conjunto completo no namespace atual. Se existirem
dados persistentes sem o conjunto atual, o runtime não cria nem roda segredos:
entra em `credential_migration_required`. A ação explícita lê e valida o conjunto
legacy, faz preflight de todos os destinos, copia apenas valores ausentes e
preserva a origem. Conflitos, conjuntos parciais ou valores inválidos falham
fechado. Depois da cópia é exigido restart.

Isto resolve a separação debug/release e a recuperação controlada. A identidade
production só fica estável entre upgrades quando o bundle for assinado com o
mesmo Apple Developer ID. Como as credenciais Apple não estão disponíveis, a
assinatura Developer ID e notarização permanecem **BLOCKED**; não é aplicado
qualquer bypass de Gatekeeper.

## Builds nativos

`desktop-native.yml` contém runners nativos distintos:

- `macos-15` / ARM64;
- `macos-15-intel` / x86_64;
- `windows-2025` / x64, atualmente como gate de blocker.

Cada build macOS compila PostgreSQL 16.15 e Valkey 8.1.10 a partir de fontes com
SHA-256 fixo, inclui Node 22.17.1 oficial do target, constrói sidecars Python e
hosts Rust no próprio runner, monta o runtime manifestado e produz `.app` e
`.dmg`. O pipeline valida arquitetura Mach-O, assinatura ad-hoc, `hdiutil`,
SHA-256 e tamanho. Os artefactos têm retenção curta e sufixo `unsigned`; não são
releases de produção.

No runner Intel, `cryptography` não disponibilizou uma wheel compatível e o
primeiro build a partir de source misturou headers e uma `libssl.3.dylib`
incompatível. A pipeline Intel força agora uma compilação sem cache contra um
único prefixo OpenSSL, com ligação estática. Antes do PyInstaller, um gate
confirma a arquitetura x86_64 do binding Rust e rejeita dependências dinâmicas
de `libssl` ou `libcrypto`. O run nativo `43577870610` validou a correção até ao
smoke test dos sidecars e ao package final.

O package Windows continua **BLOCKED**. Não foi encontrado um broker Windows
suportado que simultaneamente satisfaça o contrato Dramatiq/Redis e aceite a
password da instalação sem a expor nos argumentos ou persistir fora de
Credential Manager. O job publica um relatório estruturado do blocker e não
gera um installer inseguro ou incompleto.

## Backup e restore offline

O executável contém operações fechadas:

```text
cyberaudit-desktop offline-backup <data-root-absoluto> <backup-novo-absoluto>
cyberaudit-desktop offline-restore <backup-absoluto> <novo-data-root-absoluto>
```

O backup exige runtime parado, recusa `postmaster.pid`, symlinks e ficheiros
especiais, exclui a capability efémera `desktop-session` e inclui configuração
persistente, PostgreSQL, evidências, modelos e knowledge packs. Um manifesto
versionado guarda tamanho e SHA-256 de cada ficheiro. A escrita usa staging e
rename; restore verifica tudo antes de copiar, exige versão compatível e recusa
qualquer destino existente. Assim, um restore interrompido ou corrupto não
sobrepõe dados do cliente.

As credenciais do cofre do SO não são exportadas para o backup. Nesta versão, o
restore é suportado apenas na mesma instalação/namespace de credenciais. Uma
migração segura entre máquinas exigirá um formato cifrado e uma cerimónia de
recovery separada.

## Estado de validação

| Gate                            | macOS ARM64                                   | macOS x64             | Windows x64                                     |
| ------------------------------- | --------------------------------------------- | --------------------- | ----------------------------------------------- |
| código/pipeline de build nativo | PASS local e CI nativo                        | PASS CI nativo        | BLOCKED pelo broker                             |
| package nativo                  | PASS local e CI, ad-hoc                       | PASS CI, ad-hoc       | BLOCKED                                         |
| máquina limpa                   | NOT TESTED                                    | NOT TESTED            | NOT TESTED                                      |
| assinatura de distribuição      | BLOCKED                                       | BLOCKED               | BLOCKED                                         |
| notarização                     | BLOCKED                                       | BLOCKED               | N/A                                             |
| backup/restore isolado          | PASS em testes Rust                           | PASS por código comum | PASS por código comum, execução nativa pendente |
| upgrade desde package anterior  | BLOCKED: não existe package anterior assinado | BLOCKED               | BLOCKED                                         |

`NATIVE_BUILD_READY` só pode ser atribuído a um target depois do respetivo job
nativo passar. `DESKTOP_EVALUATION_READY` exige instalação limpa e customer
journey real. `PRODUCTION_RELEASE_READY` exige ainda assinatura, notarização,
recovery e todas as plataformas declaradas; não é o estado atual.

### Evidência local ARM64 de 2026-11-14

- `.app`: 473,05 MiB, executável principal Mach-O `arm64`;
- `.dmg`: 208,85 MiB / 218 991 452 bytes;
- SHA-256 do DMG:
  `de111570266ce7a11cb738472db8fb99dac21aa08b3a26b0b720fbbf79d65309`;
- `codesign --verify --deep --strict`: PASS com identidade ad-hoc;
- `hdiutil verify`: PASS;
- teste integrado do runtime empacotado, dois arranques, CRUD, job e
  persistência: PASS em 98,30 s;
- notarização: BLOCKED, sem credenciais Apple;
- instalação genuinamente limpa: NOT TESTED.

O package local é `NATIVE_BUILD_READY` para avaliação técnica ARM64. Não é
`DESKTOP_EVALUATION_READY` nem `PRODUCTION_RELEASE_READY`.

### Evidência CI ARM64 de 2026-11-14

O job nativo ARM64 do run `43576308459` concluiu com sucesso em runner
`macos-15`: dependências nativas, runtime Next standalone, hosts Rust, sidecars
PyInstaller, smoke tests, montagem integral sem symlinks, `.app`, `.dmg`, gates
de arquitetura/integridade/assinatura e upload do artefacto unsigned. Esta
evidência promove apenas o target ARM64 a `NATIVE_BUILD_READY`; instalação numa
máquina limpa, assinatura Developer ID e notarização continuam por validar.

### Evidência CI Intel x64 de 2026-11-14

O job nativo Intel do run `43577870610` concluiu com sucesso em runner
`macos-15-intel`. A compilação estática de `cryptography` passou o gate x86_64 e
não apresentou dependências dinâmicas de `libssl` ou `libcrypto`; os sidecars
PyInstaller passaram o smoke test que anteriormente falhava. O runtime integral,
`.app`, `.dmg`, gates de arquitetura/integridade/assinatura e upload do artefacto
unsigned também passaram. O artefacto CI `cyberaudit-desktop-macos-x64-unsigned`
tem 450 412 904 bytes. Isto promove apenas o target x64 a
`NATIVE_BUILD_READY`; instalação numa máquina limpa, assinatura Developer ID e
notarização continuam por validar.

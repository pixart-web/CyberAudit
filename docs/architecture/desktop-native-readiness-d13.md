# Desktop native readiness — D13

Estado: implementação e validação em curso em 2026-11-14. Este documento
regista evidência observada e mantém separados `clean OS`, `fresh user` e
`isolated runtime`. Nenhum resultado desta fase autoriza merge ou release.

## Taxonomia de validação

- **clean OS**: máquina/VM nova, sem ferramentas de desenvolvimento nem dados
  CyberAudit anteriores;
- **fresh user**: conta nova num sistema já utilizado para desenvolvimento;
- **isolated runtime**: diretório de dados temporário num host de
  desenvolvimento existente.

Um teste numa categoria nunca é promovido para outra. O host ARM64 disponível
é uma máquina de desenvolvimento e não possui uma VM macOS limpa ou conta de
utilizador nova preparada. Assim, os dois primeiros estados permanecem
`NOT TESTED`.

## Artefacto macOS ARM64 observado

Foi descarregado o artefacto
`cyberaudit-desktop-macos-arm64-unsigned` do run GitHub Actions
`43580939910`, produzido pelo commit
`f9e8a9b3823391cfca0decbce777baeed8ee65cf`.

| Verificação                            | Resultado observado                                                |
| -------------------------------------- | ------------------------------------------------------------------ |
| digest do artefacto GitHub             | `1eb49831681c7a797ae9ddab310126210713e45c2746b806a60ea0fc3f0ad3a9` |
| DMG                                    | `CyberAudit OS_0.1.0_aarch64.dmg`                                  |
| SHA-256 do DMG                         | `9b8a7bd4821f75cceebcf8e965836665c8ef34e1bd451a6377d0df1ca85a225b` |
| `hdiutil verify`                       | PASS                                                               |
| arquitetura do executável              | Mach-O `arm64`                                                     |
| `codesign --verify --deep --strict`    | PASS, assinatura ad-hoc                                            |
| runtime manifest v2, todos os recursos | PASS                                                               |
| `spctl --assess`                       | REJECTED                                                           |
| notarização                            | não efetuada                                                       |

A rejeição do Gatekeeper é o comportamento correto para o bundle ad-hoc não
notarizado. O Gatekeeper não foi desativado nem contornado. Este artefacto é
adequado para inspeção técnica, mas não constitui evidência de instalação limpa
suportada.

O ensaio detetou ainda que o `SHA256SUMS` publicado continha paths absolutos do
runner e a própria lista de checksums. A pipeline passa a escrever paths
relativos ao bundle, exclui `SHA256SUMS` de si próprio e executa imediatamente
`shasum -c`. A correção só será considerada provada quando um novo run produzir
um artefacto descarregável e verificável fora do runner.

## Broker Windows x64

O blocker genérico de broker foi substituído por uma integração candidata,
ainda sujeita à gate nativa Windows:

- host fixo self-contained .NET 10, sem runtime .NET externo;
- Microsoft Garnet `2.2.8` fixado por lock file e commit upstream
  `5cc8f3f50aa57ed694dfda928e4467593e073656`;
- bind explícito apenas a `127.0.0.1`;
- password de 256 bits obtida pelo supervisor do Credential Manager e entregue
  uma única vez por pipe stdin herdado;
- password ausente de argumentos, environment do broker e ficheiros de
  configuração;
- autenticação obrigatória, Lua e transações Lua para os scripts do Dramatiq;
- AOF com `WaitForCommit`, recuperação fail-closed e checkpoints periódicos;
- processo sem configuração, paths ou comandos fornecidos pelo renderer;
- licença MIT e proveniência mantidas no repositório.

Garnet não declara compatibilidade Redis total. Por isso, a pipeline Windows
executa o `RedisBroker` real do Dramatiq 1.17.1 e os seus scripts `dispatch` e
`maxstack`, incluindo `enqueue`, `fetch`, `ack`, `nack`, `requeue`, `purge`,
autenticação negativa, listener loopback e recuperação de mensagem após
término abrupto. Um executável PE x64 self-contained foi produzido localmente,
mas não pode ser executado no host macOS. Até a gate `windows-2025` passar, o
broker nativo fica `NOT TESTED` e o package Windows permanece `BLOCKED`.

Mesmo depois da gate de broker passar, o estado Windows só poderá avançar após
assembly integral de PostgreSQL, Node/Next, API, worker e Tauri, criação NSIS,
instalação limpa e exercício do percurso de utilizador. O artefacto de broker
isolado nunca é apresentado como installer.

## Backup e recuperação

O formato offline atual permanece intencionalmente ligado à instalação:
manifesta todos os ficheiros, verifica tamanho e SHA-256 antes do restore, usa
staging atómico, recusa overwrite e exclui capabilities efémeras. Os testes
Rust cobrem round-trip, corrupção, versão incompatível, runtime PostgreSQL
ativo e destino existente.

As credenciais do Keychain/Credential Manager não são copiadas para o backup.
Não existe ainda pacote cifrado de recuperação entre máquinas, derivação de
chave, AEAD ou cerimónia de recuperação. Portanto:

- restore na mesma instalação/namespace: `PASS` apenas em runtime isolado;
- restore entre máquinas: `BLOCKED`;
- desinstalar/reinstalar preservando dados: `NOT TESTED` numa instalação real;
- recovery após perda do credential store: `BLOCKED`.

Não será acrescentada exportação plaintext de credenciais para transformar
estes blockers em sucesso aparente.

## Matriz D13

| Gate                       | macOS ARM64                          | macOS x64                                                    | Windows x64                                           |
| -------------------------- | ------------------------------------ | ------------------------------------------------------------ | ----------------------------------------------------- |
| build nativo               | PASS CI anterior                     | PASS CI anterior                                             | broker compilado localmente; execução nativa pendente |
| integridade do package     | PASS; lista portátil aguarda novo CI | correção aguarda novo CI                                     | NOT TESTED                                            |
| isolated runtime           | PASS testes existentes               | PASS por CI/build, runtime integral não executado neste host | NOT TESTED                                            |
| fresh user                 | NOT TESTED                           | NOT TESTED                                                   | NOT TESTED                                            |
| clean OS                   | NOT TESTED                           | NOT TESTED                                                   | NOT TESTED                                            |
| Gatekeeper/notarização     | BLOCKED                              | BLOCKED                                                      | N/A                                                   |
| assinatura de distribuição | BLOCKED                              | BLOCKED                                                      | BLOCKED                                               |
| installer                  | DMG unsigned técnico                 | DMG unsigned técnico                                         | BLOCKED                                               |
| backup same-install        | PASS em testes Rust                  | PASS por código comum                                        | execução nativa pendente                              |
| recovery cross-machine     | BLOCKED                              | BLOCKED                                                      | BLOCKED                                               |

O estado global continua `NOT READY FOR PRODUCTION RELEASE`.

## Fontes primárias do broker

- [Garnet compatibility](https://microsoft.github.io/garnet/docs/welcome/compatibility)
- [Garnet security](https://microsoft.github.io/garnet/docs/security)
- [Garnet Lua scripting](https://microsoft.github.io/garnet/docs/commands/scripting)
- [Microsoft Garnet v2.2.8](https://github.com/microsoft/garnet/tree/v2.2.8)
- [Dramatiq v1.17.1 Redis broker](https://github.com/Bogdanp/dramatiq/blob/v1.17.1/dramatiq/brokers/redis.py)

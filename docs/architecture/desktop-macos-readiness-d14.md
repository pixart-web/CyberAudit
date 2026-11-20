# macOS native readiness — D14

Estado: validação executada entre 2026-11-14 e 2026-11-20. Esta etapa é exclusivamente macOS;
o código Windows existente foi preservado. Nenhum resultado deste documento
autoriza merge ou release.

## Ambiente e limites da evidência

O host disponível é um Mac Apple Silicon `arm64`, macOS 27.2, utilizado para
desenvolvimento. Não é uma instalação limpa. O diretório
`~/Library/Application Support/com.pixart.cyberaudit` já continha dados de
ensaios anteriores e não existia uma conta macOS nova nem uma VM limpa. Esses
dados e quaisquer credenciais existentes não foram apagados, movidos ou
substituídos.

Por consequência:

- build e inspeção do package ARM64: testados;
- cópia do `.app` do DMG para `/Applications`: testada num host existente;
- first-run e percurso GUI numa instalação limpa: `NOT TESTED`;
- x64 clean install/GUI: `NOT TESTED`, por ausência de host Intel/VM;
- assinatura Developer ID e notarização: `BLOCKED`, por ausência da identidade;
- release pública: não autorizada.

## Artefactos observados

Os dois artefactos foram descarregados do run manual GitHub Actions
`43619710513`, correspondente ao commit
`2363ba272e490f2d77ce363376be3464bcfc1163`.

| Target | Artefacto GitHub                          | DMG                               | SHA-256                                                            | Resultado                                                             |
| ------ | ----------------------------------------- | --------------------------------- | ------------------------------------------------------------------ | --------------------------------------------------------------------- |
| ARM64  | `cyberaudit-desktop-macos-arm64-unsigned` | `CyberAudit OS_0.1.0_aarch64.dmg` | `4fd07234aeaf823ef3cad5509c65fe4490a7cfcf97b5a07d99029468350799d3` | manifesto e `SHA256SUMS` PASS; `hdiutil verify` PASS; Mach-O `arm64`  |
| x64    | `cyberaudit-desktop-macos-x64-unsigned`   | `CyberAudit OS_0.1.0_x64.dmg`     | `e058debac614300f7ba221834517b0f093948b8e31155bd040947b0b29bda1e3` | manifesto e `SHA256SUMS` PASS; `hdiutil verify` PASS; Mach-O `x86_64` |

Em ambos os casos, `codesign --verify --deep --strict` passou para a assinatura
ad-hoc. Nenhum bundle declara Team ID ou notarização. O `spctl --assess` do
ARM64 não aprovou o bundle para distribuição; o Gatekeeper não foi desativado
nem contornado. Não foram encontrados symlinks dentro dos bundles e as
dependências Mach-O observadas resolvem apenas por paths internos, `@rpath`,
`/System/Library` ou `/usr/lib`.

O bundle ARM64 foi montado read-only e copiado para
`/Applications/CyberAudit OS.app` depois de confirmar que o destino não
existia. O identificador permaneceu `com.pixart.cyberaudit`, o nome apresentado
`CyberAudit OS` e o executável instalado continuou `arm64` com assinatura
válida no disco.

## Finder launch e recuperação observada

O `.app` instalado foi aberto pela interface gráfica, sem terminal. A janela
nativa apresentou nome, Dock/app identity, menus macOS e o ecrã de verificação
do runtime. Não foram iniciados processos PostgreSQL, Valkey, API, worker ou web
antes de a política de credenciais terminar.

Este ensaio revelou que o ecrã consultava o estado nativo apenas uma vez. Se a
consulta ocorresse durante `verifying_resources`, a thread nativa podia chegar
corretamente a `credential_migration_required`, mas a interface continuava a
mostrar “Verificação em curso”. A correção D14 volta a consultar apenas nos
estados transitórios `verifying_resources` e `resources_verified`; deixa de
consultar em estados terminais e antes da navegação para o frontend real.

Um bundle ARM64 local reconstruído com o runtime integral foi verificado e
aberto graficamente. Sem reload ou intervenção, avançou de “A verificar” para
“Migração segura necessária”, apresentou a ação explícita de Keychain e
preservou os dados. A migração autorizada copiou as seis credenciais para o
namespace de produção sem apagar o namespace legacy. Depois do restart, o
runtime iniciou PostgreSQL, Valkey, API, worker e Next em loopback e navegou
automaticamente para o frontend real.

O ensaio GUI autenticou uma conta sintética de validação, abriu o dashboard,
criou um cliente fictício, criou uma auditoria associada e registou um ativo
privado fictício. A validação do email rejeitou corretamente o domínio
reservado `.local`. A atividade apareceu nos audit logs e nenhum dado pessoal
real foi usado. A conta e os registos têm o prefixo `D14` e não constituem dados
de demonstração ou de produção.

O ensaio revelou ainda dois defeitos de segurança no ciclo de vida:

- o middleware Prometheus do Dramatiq herdava `0.0.0.0:9191`; o supervisor
  passa agora `dramatiq_prom_host=127.0.0.1` exclusivamente ao worker;
- `ExitRequested` enviava uma paragem assíncrona e permitia que o processo
  Tauri terminasse antes da limpeza. O callback espera agora pela confirmação
  do supervisor, com timeout limitado, antes de libertar a aplicação.

Os processos órfãos observados durante o diagnóstico foram terminados de forma
graciosa por PID. O teste integrado do runtime completo repetiu bootstrap,
login, tenant isolation, operações locais, stop e restart em diretórios
temporários, terminando sem processos próprios pendentes.

O bundle local final, assinado ad-hoc com a mesma configuração do CI, tem DMG
SHA-256
`9846ab3b9daf4fac863fcb9beb0e258bf57d5872bfb1451a2f0ff348a8cd035f`.
`hdiutil verify`, `codesign --verify --deep --strict`, Mach-O `arm64` e a
inspeção sem symlinks passaram. Este hash é evidência local, não um artefacto
publicado; os hashes finais terão de vir do novo run CI.

## Persistência, backup e restore

O binário instalado executou o fluxo de manutenção offline sobre os dados já
existentes, sem iniciar os serviços:

1. criou um backup privado `0700` com 2 296 ficheiros manifestados;
2. verificou tamanho e SHA-256 de cada ficheiro;
3. restaurou para um destino novo e privado `0700`;
4. uma comparação recursiva confirmou igualdade entre backup e restore;
5. uma cópia deliberadamente corrompida foi rejeitada com código de saída `2`;
6. o destino de restore corrompido não foi criado.

Esta evidência prova apenas backup/restore na mesma instalação. Credenciais do
Keychain não fazem parte do formato, logo recuperação entre máquinas continua
`BLOCKED`.

## Permissões locais

A inspeção do host existente revelou que os subdiretórios e ficheiros sensíveis
principais estavam privados, mas o root de dados tinha herdado `0755` e alguns
artefactos criados pelo broker tinham herdado bits de leitura/traversal do
`umask` da sessão gráfica. A implementação D14 passa a:

- criar ou corrigir explicitamente o root de dados para `0700`;
- fixar `umask 077` antes de criar threads ou processos filhos;
- manter logs e capabilities com criação privada explícita.

O teste Rust do layout verifica agora também os bits de grupo/outros do root.
O objetivo é que PostgreSQL, Valkey, API, worker e web nunca dependam do
`umask` permissivo da sessão de login.

## QA observado antes do novo CI

- Ruff: PASS;
- Black: PASS, 190 ficheiros;
- mypy: PASS, 101 source files;
- backend: 347 testes passaram no sandbox, cinco testes loopback foram
  bloqueados pelo próprio sandbox; os cinco passaram quando repetidos com
  loopback autorizado; um teste PostgreSQL foi ignorado sem a fixture; coverage
  total `75.14%`;
- frontend: 44 ficheiros/118 testes PASS; build Next de 102 rotas PASS;
- desktop: 29 testes Rust PASS e 1 integração packaged-runtime inicialmente
  ignorada; depois, o mesmo teste foi executado contra o bundle completo e
  passou em `80.26s`; 2 testes do binário PASS; 9 testes dos hosts PASS; 25
  testes Node de assembly/bridge PASS;
- Clippy desktop: PASS com warnings tratados como erro.

Os checks do PR observados antes das alterações D14 estavam todos verdes. Um
novo run é obrigatório depois do commit para provar a alteração de permissões
e reconstruir os DMGs.

## Readiness

Classificação atual: `MACOS_NATIVE_BUILD_READY`.

`MACOS_DESKTOP_EVALUATION_READY` continua proibido até uma instalação macOS
genuinamente limpa completar Finder launch, first-run, login, CRUD, workflow,
relatório, offline e persistência após restart. O target x64 necessita de
evidência separada num host Intel ou VM apropriada.

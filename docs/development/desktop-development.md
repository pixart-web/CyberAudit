# Desenvolvimento desktop

O shell desktop reutiliza `apps/web` e `apps/api`; não aponta para Hetzner. O
runtime completo falha fechado se qualquer sidecar, ferramenta, recurso ou hash
do manifesto estiver ausente ou inválido.

## Requisitos de desenvolvimento

- distribuição oficial Node.js 22.17.1 e pnpm definidos na raiz;
- Rust 1.90.0 através de rustup (fixado em `rust-toolchain.toml`);
- dependências nativas Tauri da plataforma;
- no macOS, Command Line Tools; Xcode completo será necessário para algumas
  operações de bundle/signing.

## Verificações

```bash
pnpm install --frozen-lockfile
pnpm desktop:check
pnpm desktop:test
pnpm --filter @cyberaudit/web lint
pnpm --filter @cyberaudit/web test
pnpm --filter @cyberaudit/web build
```

O helper `infrastructure/scripts/rust-cargo.sh` localiza a toolchain fixada e
evita depender de um shim global `cargo`.

## Runtime empacotado

O diretório de recursos esperado é:

```text
runtime/
  manifest.json
  runtime.json
  bin/
    cyberaudit-postgres[.exe]
    cyberaudit-valkey[.exe]
    cyberaudit-api[.exe]
    cyberaudit-worker[.exe]
    cyberaudit-web[.exe]
  tools/
    node/bin/node[.exe]
    postgresql/bin/{initdb,postgres,pg_isready,pg_ctl,createdb,psql}[.exe]
    valkey/bin/valkey-server[.exe]
  web/
    apps/web/server.js
    ...Next standalone e assets estáticos...
  licenses/
    {node,next,postgresql,valkey}-LICENSE
  provenance/
    postgresql.json
    valkey.json
```

Depois de construir/copiar exclusivamente os launchers aprovados, gerar o
manifesto:

```bash
pnpm --filter @cyberaudit/desktop runtime:manifest -- /caminho/runtime
# cross-build Windows:
pnpm --filter @cyberaudit/desktop runtime:manifest -- /caminho/runtime --windows
```

O manifesto v2 é atómico, contém SHA-256 de todos os ficheiros e rejeita
symlinks e recursos extra. Ele deteta corrupção local, mas não substitui
assinatura de código, assinatura do updater ou proveniência de build.

O assembly integral recebe apenas outputs já construídos e distribuições
redistribuíveis previamente verificadas. Nunca descarrega componentes durante o
build ou no primeiro arranque. Cada ficheiro de proveniência tem exatamente os
campos `component`, `version`, `target`, `source_url`, `archive_sha256` e
`license`; o target tem de corresponder ao artefacto em construção, PostgreSQL
tem de ser 16 e a origem tem de usar HTTPS. O output é montado num diretório
temporário, validado pelo manifesto v2 e renomeado atomicamente.

Os hosts fixos podem ser construídos e testados sem Tauri:

```bash
make desktop-runtime-hosts
make desktop-runtime-host-test
```

No macOS ARM64, as dependências nativas fixadas podem ser compiladas a partir
das fontes oficiais verificadas:

```bash
make desktop-native-dependencies-macos-arm64
```

O output fica em `.artifacts/desktop-native/macos-arm64`. O script falha se o
target não for macOS ARM64, se um checksum divergir, se um Mach-O não for ARM64
ou se depender de Homebrew/MacPorts. PostgreSQL é relinkado com `@rpath` e
validado novamente depois de mover a distribuição.

O runtime web standalone pode ser montado sem usar Node do sistema no produto:

```bash
make desktop-web-runtime
```

Depois de construir o runtime web, hosts Rust e sidecars Python, o runtime
completo é montado com distribuições fornecidas explicitamente:

```bash
make desktop-runtime-assemble \
  DESKTOP_TARGET=macos-arm64 \
  POSTGRESQL_RUNTIME_ROOT=/artefactos/postgresql-16 \
  POSTGRESQL_PROVENANCE=/artefactos/postgresql-16.json \
  VALKEY_RUNTIME_ROOT=/artefactos/valkey \
  VALKEY_PROVENANCE=/artefactos/valkey.json \
  DESKTOP_RUNTIME_FLAGS=--smoke
```

`--smoke` só pode ser usado num build nativo: executa os servidores com
`--version` e confirma que as versões correspondem à proveniência. Cross-builds
mantêm validação estrutural e dependem do job nativo do target para este gate.

O comando copia a distribuição Node completa que contém `process.execPath`,
valida-a depois da cópia e falha se a versão não for exatamente 22.17.1 ou se o
executável depender de ficheiros fora da distribuição. Instalações Homebrew não
são artefactos redistribuíveis válidos.

Esses comandos não descarregam PostgreSQL, Valkey ou Node. O assembly web copia
apenas a distribuição Node já instalada e preserva as licenças. O assembly
integral copia as distribuições PostgreSQL/Valkey completas, rejeita links que
escapem às respetivas raízes, elimina symlinks no output e inclui licenças e
proveniência no manifesto. A origem dos binários, o SBOM e a assinatura por
plataforma continuam a ser gates da pipeline de release.

## Construir o bundle Tauri

O build não aceita um runtime implícito. A variável tem de apontar para o output
completo do assembler; o pre-build faz staging atómico e volta a verificar o
manifesto antes de executar o bundler:

```bash
CYBERAUDIT_DESKTOP_RUNTIME_DIR=/caminho/runtime-completo \
  pnpm --filter @cyberaudit/desktop build
# ou
make desktop-build DESKTOP_RUNTIME_DIR=/caminho/runtime-completo
```

O diretório `apps/desktop/src-tauri/resources/runtime` é staging ignorado pelo
Git e nunca deve ser usado como fonte canónica.

## Estado honesto

Foi construído e aberto um `CyberAudit OS.app` debug em macOS ARM64 com o runtime
integral. Esta evidência valida integração local, não distribuição: o artefacto
não está assinado/notarizado, não foi testado numa máquina limpa e não prova
Windows x64 ou macOS x64. Não o distribuir como produto final.

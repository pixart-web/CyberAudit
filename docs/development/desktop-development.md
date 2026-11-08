# Desenvolvimento desktop

O shell desktop reutiliza `apps/web` e `apps/api`; não aponta para Hetzner. A
implementação atual é uma fundação D2 e falha fechado enquanto os cinco
sidecars e o respetivo manifesto não existirem.

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

Os hosts fixos podem ser construídos e testados sem Tauri:

```bash
make desktop-runtime-hosts
make desktop-runtime-host-test
```

O runtime web standalone pode ser montado sem usar Node do sistema no produto:

```bash
make desktop-web-runtime
```

O comando copia a distribuição Node completa que contém `process.execPath`,
valida-a depois da cópia e falha se a versão não for exatamente 22.17.1 ou se o
executável depender de ficheiros fora da distribuição. Instalações Homebrew não
são artefactos redistribuíveis válidos.

Esses comandos não descarregam PostgreSQL, Valkey ou Node. O assembly web copia
apenas a distribuição Node já instalada e preserva as licenças. A proveniência,
SBOM e licença dos runtimes por plataforma têm de ser verificadas pela pipeline
de release.

## Estado honesto

`cargo build --release` produz atualmente a shell e três hosts Rust em macOS
ARM64. Os hosts não constituem um runtime sem as ferramentas verificadas sob
`runtime/tools`. Ainda não existe `CyberAudit.app`; não distribuir estes
binários como produto final.

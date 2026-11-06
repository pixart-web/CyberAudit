# Desenvolvimento desktop

O shell desktop reutiliza `apps/web` e `apps/api`; não aponta para Hetzner. A
implementação atual é uma fundação D2 e falha fechado enquanto os cinco
sidecars e o respetivo manifesto não existirem.

## Requisitos de desenvolvimento

- Node.js e pnpm definidos na raiz;
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
```

Depois de construir/copiar exclusivamente os launchers aprovados, gerar o
manifesto:

```bash
pnpm --filter @cyberaudit/desktop runtime:manifest -- /caminho/runtime
# cross-build Windows:
pnpm --filter @cyberaudit/desktop runtime:manifest -- /caminho/runtime --windows
```

O manifesto é atómico e contém SHA-256. Ele deteta corrupção local, mas não
substitui assinatura de código, assinatura do updater ou proveniência de build.

## Estado honesto

`cargo build --release` produz atualmente o binário Rust do shell em macOS
ARM64. Ainda não constitui `CyberAudit.app` nem inclui serviços executáveis. Não
distribuir este binário como produto final.

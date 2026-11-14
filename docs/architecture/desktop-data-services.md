# Serviços de dados do runtime desktop

Estado: D4 parcial, validado localmente em macOS ARM64 em 2026-11-08.

## Hosts fixos

`apps/desktop/runtime-host` produz três executáveis pequenos, sem shell:

- `cyberaudit-postgres` resolve apenas seis ferramentas PostgreSQL empacotadas;
- `cyberaudit-valkey` resolve apenas `valkey-server` e envia configuração por stdin;
- `cyberaudit-web` resolve apenas Node e o `server.js` do Next standalone.

Todos calculam a raiz a partir de `runtime/bin`, rejeitam ferramentas ausentes
ou symlinks, limpam o ambiente herdado e aceitam apenas variáveis tipadas do
supervisor. No Unix, o host é substituído pelo processo final com `exec`, para
que o serviço permaneça filho direto da shell.

## PostgreSQL

No primeiro arranque o host:

1. exige diretórios absolutos e privados, porta não privilegiada e duas
   passwords hexadecimais independentes de 256 bits;
2. executa `initdb` com UTF-8, locale C, checksums e SCRAM para host/local;
3. passa a password por ficheiro temporário 0600 de nome aleatório e remove-o
   imediatamente;
4. inicia PostgreSQL apenas em `127.0.0.1` e sem Unix socket;
5. confirma readiness e cria idempotentemente a base `cyberaudit` com o owner
   de migrações `cyberaudit`;
6. cria o login de aplicação `cyberaudit_app` e o role
   `cyberaudit_runtime`, ambos `NOSUPERUSER`, `NOCREATEDB`, `NOCREATEROLE`,
   `NOINHERIT` e `NOBYPASSRLS`; só o segundo pode ser assumido pela aplicação;
7. grava um marcador de bootstrap versionado e atómico, faz shutdown `fast` e
   substitui o host pelo processo PostgreSQL final.

PostgreSQL 16.15 foi compilado do tarball oficial verificado para macOS ARM64,
sem ICU, readline, zlib, OpenSSL, LZ4 ou Zstd externos. Os Mach-O foram
relinkados com `@rpath`; o gate rejeita qualquer dependência fora de `/usr/lib`,
`/System/Library` ou da distribuição. Depois de mover o artefacto, `initdb`,
arranque loopback, consulta por `psql` e shutdown passaram. A validação anterior
de RLS aplicou migrações até `0018`, confirmou 140 tabelas e verificou que o
login de aplicação não possui `rolsuper` nem `rolbypassrls`.

## Broker

O host gera configuração fechada em memória: loopback, protected mode, AOF,
`noeviction`, limite de 512 MB, comandos debug/module/config protegidos e logs
sem dados de utilizador. A password segue num pipe anónimo; não existe ficheiro
de configuração com segredo nem argumento de processo sensível.

Valkey 8.1.10 foi compilado do tarball oficial verificado para macOS ARM64, com
`MALLOC=libc` e sem TLS externo. O binário liga apenas a `libSystem`. O host
empacotado recusou `PING` sem autenticação, respondeu `PONG` autenticado,
persistiu um valor, fez `SHUTDOWN SAVE`, reiniciou e recuperou o valor. O
tarball não inclui `.git`, pelo que o banner upstream mostra commit
`00000000, modified=1`; a proveniência é estabelecida pelo SHA-256 oficial.

## Next

O host web exige URL exata `http://127.0.0.1:<porta>/api/v1`, ficheiro regular
da capability e origem web loopback. Executa apenas o Node empacotado com o
`server.js` conhecido. A pipeline copia Next standalone, `.next/static`, assets
públicos, licenças e a distribuição Node completa, eliminando symlinks antes do
manifesto v2. O assembly executa o Node copiado com ambiente mínimo e exige
exatamente a versão 22.17.1; a instalação Homebrew local 26 foi corretamente
rejeitada por depender de bibliotecas externas. A validação do artefacto Linux
com a distribuição oficial fica a cargo do gate desktop do CI.

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

O teste real macOS usou PostgreSQL 16.14 Homebrew apenas como fixture local. A
base aplicou as migrações até `0018` com o owner, autenticou o login não
privilegiado, assumiu `cyberaudit_runtime`, leu o schema de 140 tabelas,
desligou, reiniciou e preservou os dados. O login de aplicação foi consultado
diretamente em `pg_roles` e não possui `rolsuper` nem `rolbypassrls`. Isto não
prova redistribuição: bibliotecas, licença, SBOM e rpaths ainda precisam de
assembly por target.

## Broker

O host gera configuração fechada em memória: loopback, protected mode, AOF,
`noeviction`, limite de 512 MB, comandos debug/module/config protegidos e logs
sem dados de utilizador. A password segue num pipe anónimo; não existe ficheiro
de configuração com segredo nem argumento de processo sensível.

O smoke local usou Redis 8.8 por ser o binário disponível e confirmou `PONG`
autenticado e `SHUTDOWN SAVE`. É apenas evidência de compatibilidade de protocolo
e configuração. D3 exige repetir com uma distribuição Valkey licenciada e
empacotada em Windows x64, macOS ARM64 e macOS x64.

## Next

O host web exige URL exata `http://127.0.0.1:<porta>/api/v1`, ficheiro regular
da capability e origem web loopback. Executa apenas o Node empacotado com o
`server.js` conhecido. A pipeline copia Next standalone, `.next/static`, assets
públicos, licenças e a distribuição Node completa, eliminando symlinks antes do
manifesto v2. O assembly executa o Node copiado com ambiente mínimo e exige
exatamente a versão 22.17.1; a instalação Homebrew local 26 foi corretamente
rejeitada por depender de bibliotecas externas. A validação do artefacto Linux
com a distribuição oficial fica a cargo do gate desktop do CI.

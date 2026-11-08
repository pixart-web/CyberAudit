# CyberAudit desktop reality audit

Estado da auditoria: atualizada em 2026-11-07 sobre
`codex/cyberaudit-desktop-first`. Esta página descreve a baseline observada e
os incrementos D2 e D3 parcial. Não é uma declaração de prontidão desktop.

## Resumo executivo

O produto possui um núcleo funcional extenso e uma shell Tauri 2 real em
`apps/desktop`. A shell cria diretórios OS-specific, roda uma capability por
arranque, verifica hashes dos recursos e apresenta recuperação fail-closed. A
API e o worker já podem ser empacotados sem Python de sistema. Ainda não existe
runtime completo: PostgreSQL e Valkey não estão incluídos, e o assembly Next
standalone ainda não foi integrado num installer. Os processos ainda não têm lifecycle/readiness integral e não há installer validado
em máquina limpa. Hosts nativos fixos para PostgreSQL, broker e Next já existem,
mas os runtimes redistribuíveis a que dão acesso ainda não integram o bundle.

A baseline funcional completa continua a ser Docker Compose. Nenhum `.app`,
`.dmg`, `.pkg`, `.exe` ou `.msi` de produto foi produzido.

## Auditoria do runtime atual

1. Tauri 2 (`tauri`/`tauri-build` major 2) está em `apps/desktop/src-tauri`.
2. Produção usa `apps/desktop/ui`, um estado local de recuperação, não URL remota.
3. Desenvolvimento inicia Next em `127.0.0.1:3000`; o bundle ainda não inicia Next, mas a pipeline já monta o runtime standalone com Node 22.17.1.
4. O frontend usa Next standalone para preservar SSR, rotas dinâmicas e handlers.
5. As 102 rotas compilam, mas navegação packaged completa ainda não foi provada.
6. FastAPI não era iniciado pela shell; agora possui sidecar PyInstaller validado isoladamente.
7. PostgreSQL continua externo ao bundle; o host nativo de bootstrap/persistência foi validado com PostgreSQL 16.14 local; SQLite é rejeitado.
8. Redis/Valkey continua externo ao bundle; o host usa pipe e password obrigatória; apenas compatibilidade Redis 8.8 foi exercitada localmente.
9. Dramatiq tem sidecar empacotado e plano de lançamento allowlisted, mas a shell ainda não gere o seu lifecycle.
10. Alembic está incluído no sidecar API e exposto apenas pela operação fixa `migrate`.
11. O setup real e CRUD de utilizadores/clientes existem no backend, mas não foram validados numa app instalada.
12. Evidências e modelos já usam paths configuráveis; a ligação final aos diretórios Tauri está pendente.
13. Artefactos atuais: shell Rust release sem bundle e sidecars temporários macOS ARM64.
14. CI real: Linux valida Tauri e passa a construir sidecars Python; não prova Windows/macOS.
15. Implementado parcialmente: segredos de instalação via cofre do SO, reserva loopback e launch plan fixo.
16. Simulado/incompleto: readiness/shutdown do supervisor, serviços de dados, first-run nativo, installers, offline E2E, upgrade e recovery.

## Respostas à auditoria obrigatória

### 1. Trabalho desktop já existente

Não existe Tauri, Electron, AppKit, SwiftUI, WinUI ou packaging nativo. Existe
um launcher shell para Docker Compose, binding loopback por omissão, uma página
de setup web, runtime de IA soberano, gestor de modelos, validação de pacotes de
update e documentação de instalação local. Estes elementos são reutilizáveis,
mas não constituem uma aplicação desktop.

### 2. Frontend mais reutilizável

`apps/web` é o frontend correto. Tem 102 rotas construídas com Next.js App
Router, um design system em `packages/ui`, autenticação, workspaces reais,
acessibilidade automatizada e contratos API estáveis. A build já usa
`output: "standalone"`, adequado para empacotar o servidor Next como sidecar.
Converter toda a aplicação para export estático quebraria rotas dinâmicas e
server rendering sem benefício de segurança proporcional.

### 3. Serviços locais obrigatórios

- PostgreSQL 16 para semântica SQL, migrações e RLS.
- API FastAPI empacotada, sem dependência de Python instalado.
- Servidor Next standalone empacotado, sem dependência de Node instalado.
- Worker Dramatiq para jobs persistentes, cancelamento, retry e auditoria.
- Broker Redis-compatible. Para distribuição workstation será avaliado e
  validado Valkey, preservando o protocolo e evitando uma nova implementação de
  fila.
- Tauri 2 como supervisor e fronteira nativa.

### 4. PostgreSQL embebido

É tecnicamente viável distribuir binários PostgreSQL por plataforma e gerir um
cluster privado em diretório de aplicação, desde que o produto implemente
`initdb`, credenciais por instalação, socket/loopback privado, upgrades de major
version, backup, shutdown limpo e recovery. A alternativa SQLite não é aceite:
a baseline SQLite existe para testes, mas não preserva RLS nem prova equivalência
de concorrência e isolamento.

### 5. Necessidade de Redis no workstation

Atualmente é obrigatório. O código usa Redis para Dramatiq, OIDC state
single-use, WebAuthn challenges, rate limiting, readiness e filas de SOC,
knowledge, discovery e conectores. Removê-lo agora implicaria reimplementar
durabilidade, retry, cancellation e single-use state. O desktop deve empacotar
um broker Redis-compatible em loopback, com persistência local e credencial por
instalação.

### 6. Autenticação local

O primeiro arranque cria uma organização e administrador sem credenciais
partilhadas. Passwords usam Argon2, sessões continuam sujeitas a RBAC e o
workstation não elimina isolamento por tenant. O bootstrap token deve ser
gerado pelo shell e passado ao backend fora do JavaScript. Depois do bootstrap é
invalidado. O browser interno não recebe uma chave universal de backend.

### 7. Armazenamento de segredos

Segredos de instalação e credenciais de serviços ficam no macOS Keychain ou no
Windows Credential Manager/DPAPI. Ficheiros de configuração guardam apenas
identificadores ou material não secreto. Passwords da base de dados, broker e
token de bootstrap não ficam em `localStorage`, `sessionStorage`, argumentos de
processo ou logs. A cifragem da aplicação complementa, mas não substitui,
FileVault ou BitLocker.

### 8. Modelos de IA

O `ModelRegistryService`, `HardwareCapabilityService`, `CapabilityRouter`,
retrieval local e `CyberAgentRuntime` já existem. Falta implementar importação
real de pesos, verificação de integridade/assinatura, diretório por modelo,
limites de recursos e runtime empacotado. O core continua funcional com IA
desativada e resposta determinística fundamentada.

### 9. Bloqueios de CRUD real

CRUD de utilizadores, organizações, clientes, ativos, incidentes, casos,
eventos, hunts, evidência e relatórios já foi ativado na baseline mais recente.
Os bloqueios desktop são lifecycle e bootstrap do runtime, não uma ausência
geral de endpoints. Permanecem lacunas por domínio documentadas em
`docs/operations/commercial-readiness-acceptance.md`, incluindo lifecycle de
organizações e algumas ações de edição/arquivo.

### 10. Arquitetura partilhada Windows/macOS

Tauri 2, frontend Next standalone e sidecars versionados por target. Esta opção
reutiliza a UI, reduz o custo do shell face a Electron e mantém processos locais
sob uma fronteira Rust com allowlist fixa. SwiftUI e WinUI duplicariam a UI e
Electron duplicaria o runtime Chromium sem resolver PostgreSQL, worker ou API.

### 11. Alterações para offline

- empacotar todos os runtimes e assets, incluindo fontes;
- remover a dependência normal de Docker e de endpoints Hetzner;
- usar diretórios OS-specific para dados mutáveis;
- disponibilizar licenças, knowledge packs e updates por importação offline;
- manter feeds, OIDC remoto e downloads de modelos como capacidades opcionais;
- testar o customer journey com rede externa bloqueada.

### 12. Conteúdo de cada package

Cada target inclui shell Tauri, Next standalone e Node runtime, API/worker
Python empacotados, PostgreSQL, Valkey, migrações Alembic, assets UI, catálogo
de permissões e ferramentas controladas de backup/restore. Modelos de IA e
knowledge packs não são descarregados silenciosamente nem incluídos por
omissão.

### 13. Integração futura com NODUS

O core mantém independência e expõe um contrato versionado de identidade da
aplicação, contexto, licensing, eventos, navegação e sync opcional. Não existe
endpoint NODUS hardcoded. O contrato está em
`docs/architecture/nodus-integration-contract-v1.md`.

## Evidência de validação da baseline

- Frontend lint: passou.
- Frontend Vitest baseline: 43 ficheiros e 113 testes passaram; após o proxy
  desktop, 44 ficheiros e 118 testes passaram.
- Frontend Next production build: passou, 102 rotas.
- Backend Ruff: passou.
- Backend Black check: passou, 182 ficheiros sem alterações.
- Backend mypy strict: passou, 98 ficheiros.
- Backend pytest após D2: 348 passaram, 1 foi ignorado; a suite foi executada
  fora do sandbox para permitir os testes loopback.
- Cobertura backend observada após D2: 76,43%, acima do gate de 75%.
- Runtime Python desktop: 12 testes focados passaram; dois sidecars macOS ARM64
  foram construídos e executaram smoke tests com ambiente vazio.
- Runtime Rust após D3 parcial: 11 testes passaram, incluindo estabilidade e
  rejeição de segredos inválidos, sequência fixa, sessão confinada e quatro
  portas loopback distintas. O teste de portas foi executado fora do sandbox.
- Runtime hosts Rust: 7 testes passaram. PostgreSQL 16.14 macOS ARM64 criou um
  cluster com checksums/SCRAM, a base `cyberaudit`, autenticou, fez shutdown e
  restart preservando a base. O host de broker respondeu `PONG` autenticado e
  fez `SHUTDOWN SAVE` com Redis 8.8; isto não é validação Valkey.
- Web standalone: o build de produção passou com 102 rotas; 3 testes de assembly
  passaram, incluindo dereference de symlinks e recusa de overwrite. O smoke
  rejeitou corretamente Node Homebrew 26 por não ser a distribuição portátil
  22.17.1. O CI Linux executou o Node oficial copiado e publicou com sucesso o
  runtime web (114 641 865 bytes), os hosts nativos (698 569 bytes) e os
  sidecars Python (163 098 786 bytes) no run `42461371672`.

## Bloqueadores confirmados

- toolchain Rust 1.90 disponível e fixada no repositório; `cargo check` e 11
  testes Rust passam no incremento atual;
- a matriz de sidecars de produção por target ainda não está construída;
- PostgreSQL e Valkey redistribuíveis ainda não foram incorporados com
  licenças/SBOM; Node/Next já têm assembly isolado, mas ainda não formam um
  runtime completo com os restantes serviços;
- o binário Rust release sem `custom-protocol` compilou, mas
  `tauri build --no-bundle` falhou com `E0463` ao resolver proc-macros
  (`tauri_macros` e, num `CARGO_TARGET_DIR` limpo, `phf_macros`). `cargo check` e
  os testes permanecem verdes; a toolchain/packaging precisa de diagnóstico
  antes de produzir `.app`/`.dmg`;
- inexistência de Windows limpo para validação x64;
- inexistência de macOS Intel para validação x64;
- assinatura Windows e Apple notarization sem credenciais confirmadas;
- nenhum installer desktop produzido nesta auditoria.

## QA visual do shell

O estado de recuperação foi aberto num browser integrado em 2026-11-06. A
árvore acessível continha heading, explicação sanitizada, `role=status`, lista
de componentes e botão “Verificar novamente”. A captura confirmou contraste,
hierarquia e ausência de overflow. O CLI Playwright não concluiu porque as
revisões locais de browser não correspondiam à versão exigida; esta limitação
não é contada como teste Playwright aprovado.

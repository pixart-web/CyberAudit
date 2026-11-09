# CyberAudit desktop reality audit

Estado da auditoria: atualizada em 2026-11-09 sobre
`codex/cyberaudit-desktop-first`. Esta página contém evidência executada até D6;
não é uma declaração de prontidão de release.

## Resumo executivo

O produto possui um núcleo funcional extenso e uma shell Tauri 2 real em
`apps/desktop`. Em macOS ARM64, o bundle debug contém PostgreSQL, Valkey, Node,
Next, API, worker e migrações, sem depender das instalações de sistema desses
componentes. O supervisor aplica integridade recursiva, segredos no cofre do SO,
readiness, monitorização, shutdown e restart. O first-run e o customer journey
local com persistência foram exercitados sobre o runtime empacotado.

Ainda não há release suportada: o `.app` produzido é debug, não foi
assinado/notarizado nem validado numa máquina limpa. Não existem ainda bundles
equivalentes de macOS x64 ou Windows x64, DMG/PKG/NSIS assinados ou validação de
upgrade/recovery de produção.

## Auditoria do runtime atual

1. Tauri 2 (`tauri`/`tauri-build` major 2) está em `apps/desktop/src-tauri`.
2. Produção usa `apps/desktop/ui`, um estado local de recuperação, não URL remota.
3. Desenvolvimento inicia Next em `127.0.0.1:3000`; o bundle inicia Next standalone com Node 22.17.1 empacotado.
4. O frontend usa Next standalone para preservar SSR, rotas dinâmicas e handlers.
5. As 102 rotas compilam e a shell nativa abriu a rota real `/setup` do bundle.
6. FastAPI e worker são sidecars PyInstaller ARM64 iniciados pela shell.
7. PostgreSQL 16.15 está no bundle; o host cria o cluster, roles, base, checksums e preserva dados após restart. SQLite é rejeitado.
8. Valkey 8.1.10 está no bundle; o host fornece configuração autenticada por pipe e persistência local.
9. Dramatiq tem sidecar empacotado e lifecycle gerido pelo supervisor.
10. Alembic está incluído no sidecar API e exposto apenas pela operação fixa `migrate`.
11. Setup e CRUD de organização, utilizador, cliente, auditoria, ativo e relatório foram validados no runtime local.
12. Dados mutáveis usam diretórios OS-specific sob Application Support; recursos do bundle permanecem imutáveis.
13. Artefacto atual: `.app` debug macOS ARM64 com runtime integral verificado (não distribuível).
14. CI real: Linux valida Tauri e passa a construir sidecars Python; não prova Windows/macOS.
15. Implementado: segredos via cofre do SO, loopback estrito, launch plan fixo, readiness, shutdown e lock Unix.
16. Incompleto: installers assinados, Windows Job Objects/lock equivalente, clean-machine, upgrade e recovery de release.

## Respostas à auditoria obrigatória

### 1. Trabalho desktop já existente

Existe uma shell Tauri 2, hosts Rust fixos, sidecars empacotados e um runtime
macOS ARM64 integral. O launcher Docker Compose, a página de setup web, o runtime
de IA soberano, o gestor de modelos e a validação de pacotes de update foram
reutilizados. A lacuna já não é a existência da aplicação desktop, mas a sua
industrialização multi-plataforma, assinatura e validação de instalação limpa.

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
- Runtime Rust: as suites unitárias passaram e o teste integrado D6 arrancou o
  runtime real duas vezes em 87,81 s. Validou migrações até `0019`, first-run,
  login local, CRUD representativo, shutdown e persistência após restart.
- Runtime hosts Rust: 8 testes passaram. PostgreSQL 16.15 macOS ARM64 criou um
  cluster com checksums/SCRAM, a base `cyberaudit`, roles separados de migration
  e runtime, aplicou migrations até `0019`, fez shutdown e restart preservando
  140 tabelas. O login de aplicação foi confirmado sem superuser nem bypass de
  RLS. O host de broker respondeu `PONG` autenticado e
  fez `SHUTDOWN SAVE` com Redis 8.8; isto não é validação Valkey.
- Web standalone: o build de produção passou com 102 rotas; 3 testes de assembly
  passaram, incluindo dereference de symlinks e recusa de overwrite. O smoke
  rejeitou corretamente Node Homebrew 26 por não ser a distribuição portátil
  22.17.1. O CI Linux executou o Node oficial copiado e publicou com sucesso o
  runtime web (114 641 865 bytes), os hosts nativos (698 569 bytes) e os
  sidecars Python (163 098 786 bytes) no run `42461371672`.
- Assembly integral D4: os testes passaram para composição atómica dos cinco
  sidecars, web/Node, PostgreSQL, Valkey, licenças e proveniência; também cobrem
  overwrite, target incompatível, link externo e sidecar ausente. São fixtures
  estruturais. A execução macOS ARM64 usou os redistribuíveis reais e o runtime
  dentro do `.app` voltou a passar hashes, árvore, sidecars e symlink gate.
- Bundle Tauri: `tauri build --debug --bundles app` produziu
  `CyberAudit OS.app` (484,41 MiB reportados pelo bundler). A aplicação abriu a
  página real de configuração inicial e expôs os campos de organização e
  administrador através da árvore de acessibilidade nativa.

## Bloqueadores confirmados

- toolchain Rust 1.90 disponível e fixada no repositório;
- a matriz de sidecars de produção ainda não cobre todos os targets;
- macOS ARM64 possui agora PostgreSQL 16.15, Valkey 8.1.10 e Node 22.17.1
  verificados, assembly real de 520 MB, 11 175 recursos manifestados e zero
  symlinks. A validação equivalente ainda falta em macOS x64 e Windows x64;
- o `.app` debug macOS ARM64 existe; falta repetir em release, assinar, notarizar
  e produzir DMG/PKG;
- inexistência de Windows limpo para validação x64;
- inexistência de macOS Intel para validação x64;
- assinatura Windows e Apple notarization sem credenciais confirmadas;
- nenhum installer assinado ou release candidate foi produzido nesta auditoria.

## QA visual do shell

O estado de recuperação foi aberto num browser integrado em 2026-11-06. A
árvore acessível continha heading, explicação sanitizada, `role=status`, lista
de componentes e botão “Verificar novamente”. A captura confirmou contraste,
hierarquia e ausência de overflow. O CLI Playwright não concluiu porque as
revisões locais de browser não correspondiam à versão exigida; esta limitação
não é contada como teste Playwright aprovado. Em 2026-11-09, o `.app` real foi
aberto e a árvore acessível confirmou a página `/setup`, heading, explicação e
os campos de organização, slug, administrador, email e palavra-passe.

# CyberAudit desktop reality audit

Estado da auditoria: concluída em 2026-11-06 sobre
`codex/real-product-commercial-readiness` (`548cf6c`). Esta página descreve a
baseline observada. Não é uma declaração de prontidão desktop.

## Resumo executivo

O produto já possui um núcleo funcional extenso: Next.js, FastAPI, PostgreSQL,
RLS, Redis/Dramatiq, autenticação local e OIDC, RBAC, CRUD administrativo,
relatórios PDF, runtime de IA local, agentes contextualizados, updates offline
assinados e diagnósticos sanitizados. Não existe, porém, aplicação desktop,
installer nativo, runtime embebido, supervisão de processos por Tauri ou
validação em instalações limpas.

A baseline suportada continua a ser Docker Compose. O ficheiro
`docs/architecture/local-installation.md` confirma que nenhum `.app`, `.dmg`,
`.pkg`, `.exe` ou `.msi` foi produzido.

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
- Backend pytest: 331 passaram no sandbox, 1 foi ignorado e 5 testes loopback
  falharam por proibição de bind do sandbox; os 5 passaram fora do sandbox.
- Cobertura backend observada: 71%, abaixo do objetivo de 75% do novo programa.

## Bloqueadores confirmados

- toolchain Rust 1.90 disponível e fixada no repositório; shell compilado em
  modo release e 4 testes Rust passaram;
- binários sidecar por target ainda não construídos;
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

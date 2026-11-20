# ADR-035: runtime desktop-first do CyberAudit

Estado: aceite para implementação incremental em 2026-11-06.

## Contexto

CyberAudit é hoje uma aplicação browser-oriented com Next.js, FastAPI,
PostgreSQL, Redis e Dramatiq. A baseline mais recente já contém produto real,
offline core, IA local opcional, RLS, RBAC, atualizações assinadas e relatórios.
O objetivo é distribuir uma aplicação local Windows/macOS sem exigir Docker,
Python, Node, PostgreSQL ou Redis instalados pelo utilizador.

## Decisão

Adotar Tauri 2 como shell nativo e supervisor de um runtime local fechado.

```text
Tauri 2
  -> Next standalone em loopback
  -> FastAPI empacotada em loopback privado
  -> worker Dramatiq empacotado
  -> PostgreSQL 16 privado
  -> Valkey privado e persistente
```

O shell não carrega uma URL Hetzner. Em desenvolvimento pode ligar-se aos
serviços locais iniciados pelo repositório; em bundles usa apenas recursos
empacotados e falha fechado se algum binário ou checksum estiver ausente.

## Frontend

O frontend continua a ser `apps/web`. Produção usa a build Next standalone e um
runtime Node incluído no package. Isto preserva rotas dinâmicas e evita uma
reescrita para export estático. O webview acede apenas ao servidor local
supervisionado.

## Base de dados

PostgreSQL embebido foi escolhido sobre SQLite. O cluster é por instalação,
inicializado com locale conhecido, autenticação forte e porta/socket privado.
RLS, constraints, Alembic e semântica transacional permanecem. Upgrades de major
version requerem migração explícita e backup verificado, nunca substituição do
diretório de dados.

## Broker e worker

Valkey será validado como implementação Redis-compatible por ter licença
adequada a redistribuição e por permitir reutilizar o cliente Redis e o broker
Dramatiq. O worker permanece processo separado. In-process promises não
substituem filas persistentes.

## Comunicação local

Todos os listeners usam loopback. PostgreSQL e Valkey usam credenciais por
instalação e não publicam portas na LAN. O backend aceita apenas a origem local
do runtime. Uma capability de sessão é mantida fora do JavaScript e injetada
pelo proxy local do shell/servidor. CORS wildcard, tokens universais e segredos
em `NEXT_PUBLIC_*` são proibidos.

## Segredos

O macOS usa Keychain; Windows usa Credential Manager/DPAPI. O shell gera os
segredos na primeira execução. Argumentos de processos não incluem segredos.
Os sidecars recebem-nos por handles/ambiente controlado, e os logs passam pela
redação existente.

## Layout de dados

Diretórios são resolvidos por APIs do sistema/Tauri e separados em:

- configuration;
- database;
- evidence;
- models;
- knowledge-packs;
- logs;
- backups;
- temporary.

Dados mutáveis nunca ficam dentro do `.app`, Program Files ou recursos do
bundle. Backups e evidência são preservados por omissão na desinstalação.

## Processo de arranque

1. validar manifesto e checksums de recursos;
2. criar diretórios com permissões restritivas;
3. obter segredos do keychain;
4. iniciar PostgreSQL e confirmar readiness;
5. executar Alembic sob lock de instalação;
6. iniciar Valkey;
7. iniciar API e confirmar `/ready`;
8. iniciar worker;
9. iniciar Next standalone;
10. abrir a janela principal;

Shutdown ocorre pela ordem inversa, com timeout e terminação forçada apenas dos
processos-filho conhecidos. Restart loops são limitados e auditados.

## Atualizações

O updater Tauri só aceitará bundles assinados. O formato `.caup` continua a
validar updates offline de conteúdo/runtime quando compatível, mas não substitui
a assinatura do installer. A chave privada nunca entra no repositório.

## Alternativas rejeitadas

### Electron

Reutilizaria o frontend e incluiria Node, mas adicionaria Chromium e maior
superfície/memória sem remover a necessidade de sidecars de base de dados, API e
worker.

### SwiftUI + WinUI

Oferece integração nativa máxima, mas duplica UI, acessibilidade e testes em
dois codebases, afastando-se do core partilhado.

### SQLite

Simplifica distribuição, mas perde RLS e exige provar novamente isolamento,
queries e concorrência. Não é uma troca aceitável para esta baseline.

### Docker Desktop

Continua suportado para desenvolvimento/servidor, mas é incompatível com a
experiência de instalação normal definida para o produto.

## Consequências

- bundles serão maiores devido a PostgreSQL, Valkey, Node e Python empacotados;
- builds são específicos por OS e arquitetura;
- a cadeia de supply chain passa a incluir checksums e SBOM de sidecars;
- testes limpos Windows/macOS continuam obrigatórios antes de declarar suporte;
- a baseline web/server permanece reutilizável, não é substituída.

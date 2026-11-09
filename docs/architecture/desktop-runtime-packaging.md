# Packaging do runtime Python desktop

Estado: runtime completo e bundle debug validados em macOS ARM64 em 2026-11-09.

## Decisão

FastAPI e Dramatiq são empacotados com PyInstaller 6 em executáveis `one-file`
por plataforma. O cliente não precisa de Python nem de `pip`. O package inclui
o código existente, drivers, reporting e as migrações Alembic. O build é
nativo: um binário macOS não prova compatibilidade Windows e vice-versa.

O sidecar `cyberaudit-api` aceita apenas:

- `serve`: inicia Uvicorn em IP loopback;
- `migrate`: aplica Alembic até `head`.

O sidecar `cyberaudit-worker` não aceita módulos ou filas fornecidos pelo
frontend. Usa `cyberaudit.worker`, um processo, spawn explícito e entre um e
oito threads definidos pelo supervisor.

## Configuração fail-closed

`DESKTOP_MODE=true` exige simultaneamente:

- `ENVIRONMENT=desktop`;
- PostgreSQL autenticado em loopback;
- broker Redis-compatible autenticado em loopback;
- segredos JWT e de cifragem específicos da instalação;
- API docs, debug e proxy trust desligados;
- hosts exclusivamente loopback;
- RLS ativo com o role `cyberaudit_runtime`;
- origem HTTP loopback e ficheiro de capability privado.

Configuração incompleta termina com código `78` e mensagem sanitizada. O
entrypoint não imprime o conteúdo dos segredos ou DSNs.

## Build local

```bash
.venv/bin/pip install -e "apps/api[desktop]"
make desktop-python-sidecars
make desktop-python-smoke
```

Os outputs locais ficam em `.artifacts/desktop-python/dist` e não são
versionados. O CI Linux constrói e publica sidecars de curta retenção para
detetar regressões de packaging; esses artefactos não são installers de
produto.

O manifesto v2 cobre todos os ficheiros sob `runtime`, não apenas os cinco
entrypoints. Paths absolutos, traversal, symlinks, duplicados, hashes inválidos,
ficheiros ausentes e ficheiros extra falham fechado. Isto é necessário porque
PostgreSQL e Node carregam bibliotecas e módulos adicionais depois do primeiro
processo; verificar só o executável daria uma garantia incompleta.

O assembler completo em `apps/desktop/scripts/assemble-runtime.mjs` reúne, num
staging atómico, runtime web/Node, cinco sidecars, distribuições PostgreSQL e
Valkey, licenças e proveniência. Recusa destinos existentes, versões PostgreSQL
fora da major 16, proveniência de outro target, digests inválidos, componentes
em falta e symlinks que escapem à distribuição de origem. O manifesto só é
gerado depois de confirmar que o output final não contém symlinks.

## Evidência observada

No runner local macOS ARM64:

- `cyberaudit-api`: Mach-O ARM64, aproximadamente 53 MB;
- `cyberaudit-worker`: Mach-O ARM64, aproximadamente 53 MB;
- ambos executaram `--help` com ambiente vazio;
- `cyberaudit-api serve` sem configuração terminou com código `78`;
- nenhum serviço externo foi iniciado durante o smoke test;
- assinatura Apple/notarização: não efetuadas.

O assembly completo integra PostgreSQL 16.15, Valkey 8.1.10, Node 22.17.1,
Next, API e worker. O staging pré-build verifica novamente manifesto, hashes,
árvore, ausência de symlinks e sidecars obrigatórios, e só depois copia o
runtime para os resources Tauri. Foi produzido um `.app` debug de 484,41 MiB;
o runtime dentro do bundle voltou a passar a verificação de integridade.

Os hashes desta execução local não são artefactos de release e o bundle não foi
assinado nem notarizado.

## Trabalho ainda obrigatório

- reproduzir o assembly em macOS x64 e Windows x64;
- gerar SBOM e assinar os artefactos por target;
- construir DMG/NSIS, notarizar o artefacto Apple e validar upgrades;
- validar cada instalador em máquinas limpas e sem Node, Python, PostgreSQL,
  Redis/Valkey ou acesso obrigatório à Internet.

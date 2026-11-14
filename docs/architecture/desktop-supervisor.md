# Supervisor do runtime desktop

Estado: implementado e validado em macOS ARM64, 2026-11-13. A paridade e a
validação de máquina limpa para Windows x64 e macOS x64 continuam pendentes.

## Fronteira implementada

O módulo Rust `supervisor` aceita apenas seis passos, por esta ordem:

1. `cyberaudit-postgres`;
2. `cyberaudit-api migrate`;
3. `cyberaudit-valkey`;
4. `cyberaudit-api serve`;
5. `cyberaudit-worker`;
6. `cyberaudit-web`.

Não existe API para receber comandos, executáveis, argumentos ou variáveis de
ambiente do renderer. Cada spawn usa `std::process::Command` diretamente,
limpa o ambiente herdado, aplica apenas configuração construída pelo shell e
redireciona stdout/stderr para ficheiros privados. O plano que pode ser
serializado contém apenas nomes, papéis e argumentos não secretos.

O manifesto v2 inventaria recursivamente o runtime completo. O verificador
nativo rejeita qualquer dependência não manifestada, symlink ou path inseguro,
para que bibliotecas PostgreSQL e módulos Next/Node fiquem na mesma fronteira de
integridade dos entrypoints.

Quatro portas são reservadas pelo sistema operativo exclusivamente em
`127.0.0.1`. As credenciais PostgreSQL do owner de migrações e do login de
aplicação, a password Valkey, o segredo JWT, a chave de cifragem e o token de
bootstrap são independentes e persistem no macOS Keychain ou Windows Credential
Manager através de `keyring` 4.2. Migrações usam exclusivamente o owner; API e
worker autenticam como `cyberaudit_app` e assumem o role RLS limitado
`cyberaudit_runtime`. Um valor existente malformado não é rodado
silenciosamente: o arranque falha fechado para evitar perda de dados.

A capability API continua diferente: é efémera, roda a cada arranque e fica num
ficheiro privado dentro de `configuration`. O launch plan rejeita qualquer
capability fora desse diretório ou que não seja um ficheiro regular.

Uma máquina de estados explícita impede saltos na ordem de dependências:
verificação, PostgreSQL, migrações, Valkey, API, worker e web. Falhas podem
transitar para limpeza, mas estados terminados não regressam a `ready`. Esta
máquina está ligada ao arranque Tauri. Readiness usa deadlines por serviço; o
monitor deteta a saída inesperada de filhos; o shutdown termina os serviços em
ordem inversa e aplica um limite antes de forçar a terminação. Em Unix, os filhos
usam process groups e um lock exclusivo impede duas instâncias sobre os mesmos
dados.

SIGTERM e SIGINT são convertidos por um handler mínimo num pedido de shutdown
com acknowledgement limitado a 30 segundos; o processo Tauri só termina depois
da tentativa de limpeza. O ensaio nativo confirmou que PostgreSQL, Valkey, API,
worker e Next não sobrevivem ao sinal coordenado.

## Evidência executada

O teste integrado ignorado por omissão arrancou o runtime empacotado real duas
vezes. Confirmou migrações até `0019`, API, worker e Next, criou o primeiro
administrador e dados de cliente/auditoria/ativo/utilizador/relatório, executou
um job real `cyberaudit.asset_inventory`, persistiu o raw result sanitizado e
provou que um segundo tenant recebe `404` ao consultar o job. Fez shutdown
limpo e confirmou os registos após restart. O fluxo final D7 passou em 83,98 s
dentro de um sandbox que bloqueava rede externa e permitia apenas loopback. Um
`.app` debug abriu a página `/setup` real através da shell nativa.

## Limites atuais

- o controlo de process tree e o lock têm implementação reforçada em Unix; a
  implementação Windows ainda precisa de Job Objects e lock nativo equivalente;
- faltam clean install em Windows x64 e macOS ARM64/x64 e testes de crash por
  `SIGKILL`, que não pode executar cleanup cooperativo;
- o job real valida a saúde funcional do consumidor; um heartbeat contínuo
  ainda é recomendável antes de release.

# Supervisor do runtime desktop

Estado: implementado e validado em macOS ARM64, 2026-11-09. A paridade e a
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

## Evidência executada

O teste integrado ignorado por omissão arrancou o runtime empacotado real duas
vezes. Confirmou migrações até `0019`, API, worker e Next, criou o primeiro
administrador e dados de cliente/auditoria/ativo/utilizador/relatório, fez
shutdown limpo e confirmou a persistência após restart. Um `.app` debug abriu a
página real de configuração inicial através da shell nativa.

## Limites atuais

- o controlo de process tree e o lock têm implementação reforçada em Unix; a
  implementação Windows ainda precisa de Job Objects e lock nativo equivalente;
- faltam testes de crash, processos órfãos e clean install em Windows x64 e
  macOS ARM64/x64;
- readiness do worker prova o entrypoint; a saúde funcional do consumidor deve
  evoluir para um heartbeat explícito antes de release.

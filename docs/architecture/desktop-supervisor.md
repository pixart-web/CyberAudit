# Supervisor do runtime desktop

Estado: D3 parcial, 2026-11-07. Este contrato está implementado e testado, mas
ainda não inicia o produto completo porque faltam sidecars redistribuíveis de
PostgreSQL, Valkey e Next standalone.

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

Quatro portas são reservadas pelo sistema operativo exclusivamente em
`127.0.0.1`. Passwords de PostgreSQL e Valkey, segredo JWT, chave de cifragem e
token de bootstrap são independentes e persistem no macOS Keychain ou Windows
Credential Manager através de `keyring` 4.2. Um valor existente malformado não
é rodado silenciosamente: o arranque falha fechado para evitar perda de dados.

A capability API continua diferente: é efémera, roda a cada arranque e fica num
ficheiro privado dentro de `configuration`. O launch plan rejeita qualquer
capability fora desse diretório ou que não seja um ficheiro regular.

## Próximo incremento obrigatório

- manter cada reserva até ao spawn do serviço correspondente;
- verificar readiness de PostgreSQL, Valkey, API e web com deadlines;
- aplicar migrações sob lock exclusivo;
- implementar restart budget e estados sanitizados;
- terminar filhos conhecidos pela ordem inversa, com timeout;
- ligar o supervisor à shell apenas quando todos os sidecars assinados estiverem presentes;
- testar crash, processos órfãos e clean install em Windows x64 e macOS ARM64/x64.

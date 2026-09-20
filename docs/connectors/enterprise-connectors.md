# Enterprise Connectors

Conectores possuem tipo fechado, provider, scopes, permissões pedidas e
detetadas, capacidades, retenção, cursor e health. O orquestrador cria uma
execução idempotente na fila; o worker recarrega connector e tenant antes de
processar.

Nesta entrega todos os adapters Enterprise são fixture/import-only e declaram
`requires_network=false`. Provider SDKs ficam sujeitos a revisão posterior.

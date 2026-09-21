# Enterprise Connector Security

- read-only obrigatório e verificado novamente no worker;
- allowlist de tipos, capabilities e códigos de adapter;
- sem plugins ou código carregado pelo utilizador;
- sem comandos, subprocessos, URLs arbitrários ou escrita externa;
- isolamento por `organization_id` em todas as queries;
- paginação e limites em payloads e grafos;
- sanitização recursiva antes de hashing, snapshots e logs;
- auditoria de criação, alteração, teste e sincronização.

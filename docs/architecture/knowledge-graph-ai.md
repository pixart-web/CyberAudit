# Knowledge Graph e AI Security Platform

## Contrato de resposta

Cada resposta contém obrigatoriamente:

- `facts`: dados copiados de nós autorizados;
- `inferences`: conclusões explicitamente separadas;
- `citations`: tipo, ID e referências da fonte;
- `confidence`: 0–1;
- `limitations`;
- `reproducibility_key`;
- `action_executed=false`.

`AiProvider` abstrai fornecedores. A implementação inicial,
`DeterministicGroundedProvider`, funciona offline e recusa produzir uma resposta
substantiva sem fontes. Configurações de fornecedores não armazenam segredos;
credenciais futuras pertencem a um secret manager.

O grafo usa nós tenant-bound para ativos, identidades, cloud, aplicações, APIs,
vulnerabilidades, findings, incidentes, riscos, controlos, evidências e
compliance. Arestas distinguem `inferred` e incluem confiança e fontes.

Nenhum assistente dispõe de ferramentas de execução. Recomendações não criam
jobs, alteram controlos, fecham incidentes ou aceitam riscos. Essas mutações
continuam em endpoints humanos com RBAC e audit log.

# Governação de IA

O módulo de IA é advisory-only. `action_executed` é sempre falso e não existe
interface de tool calling.

Guardrails:

1. seleção de fontes limitada a 100 IDs e filtrada pelo tenant;
2. dados desconhecidos não são inventados;
3. factos e inferências são separados;
4. fontes, confiança e limitações são obrigatórias;
5. resposta e contexto são auditados sem segredos;
6. fornecedores externos começam desativados;
7. classificação permitida, residência, retenção e revisão humana são políticas
   por organização;
8. segredos de fornecedor nunca pertencem à base de dados.

A explicabilidade é estrutural, não apenas texto no prompt. O backend constrói o
contrato e a UI mostra as quatro secções separadamente.

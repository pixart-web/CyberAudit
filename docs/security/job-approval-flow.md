# Aprovação de jobs

São criadas aprovações para perfis que as exigem, decisões `requires_approval` e intensidades elevadas ou intrusivas.

A aprovação guarda alvo normalizado, técnica, intensidade, risco, duração, configuração declarada, scope e validade. Apenas utilizadores com `approvals.review` podem aprovar ou rejeitar.

Uma aprovação:

- pertence ao mesmo tenant e engagement;
- só pode ser revista em estado `pending`;
- expira automaticamente antes da utilização;
- é novamente verificada pelo worker;
- não altera nem amplia o scope;
- gera eventos e audit logs.

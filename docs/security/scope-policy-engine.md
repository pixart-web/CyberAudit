# ScopePolicyEngine

O motor recebe organização, auditoria, operador, target, técnica, intensidade, instante e aprovação opcional. A decisão é `allowed`, `denied` ou `requires_approval`, com razões, regras correspondentes, versão e timestamp.

Valida tenant e estados, autorização e validade, scope e targets, inclusão CIDR/subdomínio, horário localizado, intensidade, técnica, emergency stop e restrições de laboratório. Intensidades `elevated` e `intrusive` exigem aprovação.

Nenhum adaptador futuro pode contornar esta avaliação. A decisão deve ser novamente validada imediatamente antes da execução para evitar alterações de âmbito entre agendamento e execução.

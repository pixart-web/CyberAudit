# Tool adapters

Adaptadores implementam a interface abstrata `ToolAdapter`: metadados, validação de configuração e alvo, estimativa, execução, cancelamento, parsing e health check.

`AdapterRegistry` é um allowlist estático. Não carrega módulos, ficheiros ou código indicado pelo utilizador. Códigos duplicados e desconhecidos são rejeitados.

O adaptador `cyberaudit.demo_assessment`:

- não abre sockets nem faz HTTP;
- não executa subprocessos ou comandos;
- não lê ficheiros nem variáveis de ambiente;
- não altera o alvo;
- aceita apenas um schema Pydantic fechado;
- gera resultados determinísticos e marcados `[SIMULADO]`.

Configuração:

```json
{
  "scenario": "clean | low_risk | mixed | critical | warning | failure | timeout",
  "duration_seconds": 10,
  "finding_count": 3
}
```

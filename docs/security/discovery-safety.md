# Discovery safety

Controlos obrigatórios:

- tenant e scope obtidos do utilizador autenticado;
- política avaliada na API e novamente no worker;
- CIDR limitado, exclusões e máximo de hosts;
- perfis de portas fechados, sem input livre;
- TCP connect apenas, sem raw packets, UDP, stealth, spoofing, flooding ou evasão;
- concorrência, taxa, timeout e cancelamento limitados;
- IPs especiais e metadata cloud bloqueados;
- laboratório permite apenas destinos privados/localhost explicitamente autorizados;
- logs estruturados não incluem tokens, passwords ou raw output.

O operador pode reduzir limites, nunca aumentá-los. O runner futuro recebe um manifest estruturado e não comandos.

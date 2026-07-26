# Proteção SSRF

Bloqueios obrigatórios:

- metadata cloud conhecida e toda a gama link-local;
- unspecified, multicast e reserved;
- loopback e privados fora de política autorizada;
- públicos em modo laboratório;
- credenciais em URL, schemes e portas não permitidos;
- IP literal fora do scope;
- mudança de resolução durante o job;
- redirect para hostname/IP fora do scope;
- expansão automática do alvo.

O hostname autorizado pode usar o seu IP resolvido apenas para a ligação a esse hostname; o IP não passa a ser um novo alvo.

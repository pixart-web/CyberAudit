# Rede de laboratório

```bash
make lab-network-up
make seed-phase4
make lab-network-down
```

O profile Docker `lab` disponibiliza HTTP/TLS e banners TCP inertes em loopback. Os banners não implementam SSH, base de dados ou cache, não aceitam comandos e não contêm vulnerabilidades reais.

Registe os destinos no scope do engagement laboratório. O worker mantém a segunda validação e não deve contactar endereços públicos. Docker é necessário para este fluxo; os testes unitários usam sockets locais efémeros.

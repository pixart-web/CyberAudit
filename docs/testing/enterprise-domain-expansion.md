# Enterprise Domain Expansion Testing

Execute:

```bash
make enterprise-domain-test
make lint
make test
```

A cobertura específica inclui schemas fechados, secret references, redaction,
change detection, scoring Zero Trust, fatores de risco, registry fechado e
contrato OpenAPI. A validação final deve ainda executar migrations desde 0001,
seed sintético, build frontend e health checks em PostgreSQL/Redis.

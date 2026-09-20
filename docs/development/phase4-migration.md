# Migração para CyberAudit OS Fase 4

1. Faça backup do PostgreSQL e do storage privado.
2. Execute `alembic upgrade head`.
3. Execute `python -m cyberaudit.seed_phase4` uma vez por ambiente de demonstração.
4. Inicie worker com `cyberaudit.worker cyberaudit.phase4_worker`.
5. Valide `/health`, `/api/v1/system-health` e os testes Phase 4.

A migration `0004_cyber_asset_graph` é reversível e preserva dados das Fases 1–3. O downgrade remove apenas estruturas Phase 4; deve ser precedido de backup.

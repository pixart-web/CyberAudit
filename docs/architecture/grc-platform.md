# Governance, Risk & Compliance

`UnifiedControl` é a unidade reutilizável. `FrameworkControlMapping` relaciona
um controlo com referências externas sem duplicar implementação ou evidência.
O catálogo suporta ISO 27001/27002, NIS2, DORA, PCI DSS, CIS Controls, NIST CSF,
NIST 800-53, SOC 2 e estado de controlos GDPR.

O seed inclui apenas mapeamentos explicitamente demonstrativos; não reproduz
texto normativo e não constitui certificação.

O risk register separa:

- probabilidade e impacto (1–5);
- risco inerente (`probabilidade × impacto`);
- efetividade dos controlos (0–1);
- risco residual (`inerente × (1 - efetividade)`);
- apetite e estratégia de tratamento.

Aceitação de risco, exceções, revisão, expiração e tratamentos requerem
permissões específicas e audit log. Evidências continuam no storage privado e
são associadas por `GrcEvidenceLink`, permitindo relações com controlos,
riscos, auditorias, findings, ativos, aplicações e incidentes.

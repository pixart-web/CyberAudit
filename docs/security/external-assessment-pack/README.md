# Independent security assessment pack

This package prepares, but does not claim, an independent assessment. The
`external_assessment` readiness check remains blocked until an authorized third
party supplies a signed report and a human reviewer validates its checksum.

## Scope

- production-like CyberAudit web/API and identity boundary;
- tenant isolation and PostgreSQL RLS;
- authorization, session, step-up and WebAuthn flows;
- Vault/MinIO provider boundaries and redaction;
- closed runner contracts and network isolation;
- evidence gate, build pipeline and release artefacts.

Excluded: real customer data, public targets, destructive testing, credential
collection, persistence, denial of service and any target not listed in the
signed rules of engagement.

## Inputs and contacts

The security owner must provide named contacts, emergency stop contact, exact
endpoints, synthetic accounts, test window and data-handling agreement. Secrets
must be delivered through an approved secret channel, never committed here.

Use [rules-of-engagement.md](rules-of-engagement.md) and
[report-template.md](report-template.md). Findings enter the normal remediation
workflow; HIGH/CRITICAL findings block candidate status unless fixed or covered
by a versioned, approved risk acceptance.

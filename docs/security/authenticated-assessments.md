# Authenticated Assessments

Phase 5 defines `AssessmentCredential` as a reference to an external secret
manager. Raw passwords, tokens and session cookies are never stored in CyberAudit
configuration or logs. Credentials are scoped to organization, engagement,
application, role and environment, expire automatically and count usage.

The bundled adapters do not authenticate to real targets. Future authenticated
adapters must resolve a reference inside an isolated runner after policy
revalidation and redact all derived material.

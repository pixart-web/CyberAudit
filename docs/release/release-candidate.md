# Release candidate procedure

1. Merge only green, reviewed changes into the protected release branch.
2. Confirm the readiness endpoint reports no evidence blockers and a formal
   candidate approval exists.
3. Create an annotated `vX.Y.Z-rc.N` tag.
4. Let the release workflow build once, generate SBOM/provenance, sign by digest
   and verify every artifact.
5. Deploy those exact digests to the production-like environment.
6. Run migrations, smoke, tenant, OIDC, WebAuthn, backup/restore and rollback
   validation.
7. Record sanitized evidence and obtain the independent promotion decision.

No release candidate was created locally for this branch.

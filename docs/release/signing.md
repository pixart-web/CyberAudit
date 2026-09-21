# Artifact signing

CI uses GitHub OIDC and Sigstore keyless signing. Container images are signed by
digest, while the release archive, checksum manifest, SBOMs and provenance are
signed as blobs. Verification pins the expected repository identity and GitHub
issuer before publication.

Private signing keys are never stored in the repository. A failed or missing
verification blocks promotion and triggers the signature-failure runbook.

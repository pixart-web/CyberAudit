# Release signature failure

1. Stop promotion and quarantine the artifact.
2. Verify digest, certificate identity, issuer, transparency entry and provenance.
3. Check the protected workflow and source commit for compromise.
4. Rebuild from reviewed source only after security approval; never bypass verify.

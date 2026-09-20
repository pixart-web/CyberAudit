# Build provenance

Container builds request maximum BuildKit provenance. The release job emits
GitHub artifact attestations for the archive and SBOM/checksum set. Provenance
must identify the source commit, workflow, dependencies and immutable artifact
digest.

Promotion consumes digests and verifies attestations; it never rebuilds from a
mutable branch or tag. Provenance is generated only by protected CI, not trusted
when supplied by an API user.

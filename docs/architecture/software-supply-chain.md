# Software Supply Chain

Repositories are metadata records, not executable working trees. Releases bind
immutable artifact hashes, optional image digests, signatures, provenance and a
validated SBOM. Components and dependency edges are imported from bounded
CycloneDX JSON.

Release gates combine AppSec score, open severity counts, confirmed secret
observations, SBOM availability and signature/provenance facts. Every evaluation
is immutable and auditable.

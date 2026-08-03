# Software bill of materials

The release workflow generates CycloneDX JSON SBOMs for the Python environment,
pnpm workspace, API image, web image and final release bundle. SBOMs are named
with the immutable release tag, checksummed, signed and attached to the release.

The job must fail if generation, vulnerability analysis or signature
verification fails. An SBOM generated only by a developer workstation is not
release evidence.

The readiness harness generated 12 component documents (CycloneDX and SPDX for
API/web sources and API/web/worker/runner images) with Syft 1.50.0. They remain
`partial`: the frozen release archive and its SBOM do not exist, and the local
documents are neither keyless-signed nor independently reviewed. Generated
documents are ignored by Git; `artifacts/readiness/sbom-results.json` contains
their sanitized paths, sizes and SHA-256 values.

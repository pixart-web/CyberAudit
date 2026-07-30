# Software bill of materials

The release workflow generates CycloneDX JSON SBOMs for the Python environment,
pnpm workspace, API image, web image and final release bundle. SBOMs are named
with the immutable release tag, checksummed, signed and attached to the release.

The job must fail if generation, vulnerability analysis or signature
verification fails. An SBOM generated only by a developer workstation is not
release evidence. No SBOM has been generated in this workspace because `syft`
and a container runtime are unavailable; the readiness check remains blocked.

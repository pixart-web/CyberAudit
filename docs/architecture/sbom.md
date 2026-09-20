# SBOM

The supported Phase 5 format is CycloneDX JSON. Imports are limited to 10 MiB,
10,000 components and 20,000 dependency records. XML and arbitrary manifest
execution are not supported.

The original document is stored privately with a SHA-256 digest. Parsed
components preserve PURL, CPE, hashes and licenses. Validation never installs,
loads or executes a component.

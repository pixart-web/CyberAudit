# Readiness toolchain

Phase 10.2 uses a pinned workstation toolchain. `scripts/readiness/tool-versions.env`
is the machine-readable source of the versions below. Operators must review an
installation plan before any package manager changes are made; the repository
never downloads and executes remote scripts.

| Tool | Tested version | Purpose | Official source and verification |
|---|---:|---|---|
| Docker Desktop | 4.44.3 | Compose, images and ephemeral runner | Docker release notes; signed macOS application/notarization |
| kubectl | 1.33.3 | Kubernetes API validation | Kubernetes release binaries and published SHA-256 |
| Kind | 0.29.0 | Disposable local Kubernetes cluster | Kubernetes SIGs GitHub release and SHA-256 |
| Helm | 3.18.4 | Chart rendering and deployment | Helm GitHub release and SHA-256 |
| Vault | 1.20.1 | Secret-reference integration | HashiCorp release and SHA256SUMS signature |
| MinIO Client | RELEASE.2025-07-21T05-28-08Z | Private object-store administration | MinIO official release and SHA-256 |
| Syft | 1.29.0 | CycloneDX/SPDX SBOM generation | Anchore GitHub release and checksums |
| Cosign | 2.5.3 | Keyless artifact and image signing | Sigstore GitHub release and checksums |
| Trivy | 0.64.1 | Dependency, image and manifest scanning | Aqua Security GitHub release and checksums |
| k6 | 1.1.0 | Controlled load validation | Grafana GitHub release and checksums |

The supported package-manager path is Homebrew on macOS and vendor repositories
or checksum-verified release packages on Linux. Run:

```bash
make readiness-environment-check
make readiness-tools-verify
```

The first command always writes the sanitized report to
`artifacts/readiness/environment-check.json`. It exits non-zero while a required
tool is absent, which is intentional and prevents an incomplete workstation from
being mistaken for release evidence.

Docker being present on `PATH` is not proof that its daemon or isolation controls
work. Service, runner and cluster checks are separate evidence items.

## Installation

The macOS installer prints the complete Homebrew plan and requires the operator
to type `INSTALL` before changing the workstation:

```bash
scripts/readiness/install-macos.sh
```

Homebrew can advance formulae beyond the validation matrix. Such a version is
not silently accepted: the environment report captures it and the reviewer must
record compatibility in the evidence manifest. The Linux helper deliberately
does not add privileged third-party repositories because distro trust policy is
an operator decision:

```bash
scripts/readiness/install-linux.sh
```

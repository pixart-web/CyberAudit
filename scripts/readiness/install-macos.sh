#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/tool-versions.env"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This installer supports macOS only." >&2
  exit 2
fi
if ! command -v brew >/dev/null 2>&1; then
  echo "Homebrew is required. Install it from https://brew.sh after reviewing its installer." >&2
  exit 2
fi

formulae=(docker docker-compose colima kubectl kind helm hashicorp/tap/vault minio-mc syft cosign trivy k6)
cat <<EOF
CyberAudit readiness toolchain installation plan

Package manager: $(command -v brew)
Formulae: ${formulae[*]}
Runtime: Colima (no Docker socket is exposed to CyberAudit workloads)
Pinned validation matrix:
  kubectl ${KUBECTL_VERSION}; kind ${KIND_VERSION}; helm ${HELM_VERSION}
  vault ${VAULT_VERSION}; mc ${MINIO_CLIENT_VERSION}; syft ${SYFT_VERSION}
  cosign ${COSIGN_VERSION}; trivy ${TRIVY_VERSION}; k6 ${K6_VERSION}

Homebrew may provide a newer security-compatible patch release. The exact
installed versions will be recorded and must be reviewed before evidence is
accepted. No installation occurs unless the operator types INSTALL.
EOF

if [[ "${READINESS_INSTALL_CONFIRM:-}" != "INSTALL" ]]; then
  read -r -p "Type INSTALL to continue: " confirmation
  if [[ "${confirmation}" != "INSTALL" ]]; then
    echo "Installation cancelled."
    exit 1
  fi
fi

brew tap hashicorp/tap
brew install "${formulae[@]}"

echo "Tool installation finished. Starting Colima remains a separate operator action:"
echo "  colima start --cpu 4 --memory 8 --disk 80 --vm-type vz"
echo "Then run: make readiness-tools-verify"

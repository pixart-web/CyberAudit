#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/tool-versions.env"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This installer supports Linux only." >&2
  exit 2
fi

cat <<EOF
CyberAudit does not add third-party package repositories or execute downloaded
scripts automatically. Install the following pinned releases from their
official vendor repositories and verify the vendor-published checksums:

  Docker Desktop/Engine ${DOCKER_DESKTOP_VERSION}
  kubectl ${KUBECTL_VERSION}
  kind ${KIND_VERSION}
  Helm ${HELM_VERSION}
  Vault ${VAULT_VERSION}
  MinIO Client ${MINIO_CLIENT_VERSION}
  Syft ${SYFT_VERSION}
  Cosign ${COSIGN_VERSION}
  Trivy ${TRIVY_VERSION}
  k6 ${K6_VERSION}

After installation run:
  make readiness-tools-verify

This script intentionally makes no system changes because Linux distribution,
package trust roots and privilege policy must be selected by the operator.
EOF

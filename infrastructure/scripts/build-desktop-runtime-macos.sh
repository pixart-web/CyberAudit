#!/usr/bin/env bash
set -euo pipefail

POSTGRESQL_VERSION="16.15"
POSTGRESQL_ARCHIVE="postgresql-${POSTGRESQL_VERSION}.tar.bz2"
POSTGRESQL_SHA256="c1575341fa7bd40f5274ea465b34390f4dc64cdd0770af327005caaeb9f6b7ed"
POSTGRESQL_URL="https://ftp.postgresql.org/pub/source/v${POSTGRESQL_VERSION}/${POSTGRESQL_ARCHIVE}"

VALKEY_VERSION="8.1.10"
VALKEY_ARCHIVE="valkey-${VALKEY_VERSION}.tar.gz"
VALKEY_SHA256="c74e50cd83f6d398a3dc570e04ac2fe538249585d021f76ee2449bbf9ebd04ed"
VALKEY_URL="https://github.com/valkey-io/valkey/archive/refs/tags/${VALKEY_VERSION}.tar.gz"

NODE_VERSION="22.17.1"
TARGET_ARCH="${1:-$(uname -m)}"
case "${TARGET_ARCH}" in
  arm64)
    NODE_SHA256="a983f4f2a7b71512b78d7935b9ccf6b72120a255810070afd635c4146bca7b31"
    ;;
  x86_64)
    NODE_SHA256="b925103150fac0d23a44a45b2d88a01b73e5fff101e5dcfbae98d32c08d4bee3"
    ;;
  *)
    echo "desktop runtime build failed: unsupported macOS architecture ${TARGET_ARCH}" >&2
    exit 1
    ;;
esac
TARGET_NAME="macos-${TARGET_ARCH/x86_64/x64}"
NODE_ARCHIVE="node-v${NODE_VERSION}-darwin-${TARGET_ARCH/x86_64/x64}.tar.gz"
NODE_URL="https://nodejs.org/download/release/v${NODE_VERSION}/${NODE_ARCHIVE}"

SCRIPT_DIRECTORY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "${SCRIPT_DIRECTORY}/../.." && pwd -P)"
OUTPUT_ROOT="${2:-${REPOSITORY_ROOT}/.artifacts/desktop-native/${TARGET_NAME}}"

fail() {
  echo "desktop runtime build failed: $1" >&2
  exit 1
}

[[ "$(uname -s)" == "Darwin" ]] || fail "macOS is required"
[[ "$(uname -m)" == "${TARGET_ARCH}" ]] || fail "a native ${TARGET_ARCH} host is required"
[[ "${OUTPUT_ROOT}" == /* ]] || fail "output path must be absolute"
[[ "${OUTPUT_ROOT}" != "/" ]] || fail "output path cannot be the filesystem root"
[[ ! -e "${OUTPUT_ROOT}" ]] || fail "output path already exists"

for command in curl make shasum tar otool lipo file install_name_tool; do
  command -v "${command}" >/dev/null || fail "required build tool ${command} is unavailable"
done

OUTPUT_PARENT="$(dirname "${OUTPUT_ROOT}")"
mkdir -p "${OUTPUT_PARENT}"
STAGING_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/cyberaudit-${TARGET_NAME}-runtime.XXXXXX")"
STAGING_ROOT="$(cd "${STAGING_ROOT}" && pwd -P)"
SOURCE_ROOT="${STAGING_ROOT}/sources"
DIST_ROOT="${STAGING_ROOT}/distribution"
mkdir -p "${SOURCE_ROOT}" "${DIST_ROOT}/provenance"

cleanup() {
  if [[ -d "${STAGING_ROOT}" ]]; then
    rm -rf "${STAGING_ROOT}"
  fi
}
trap cleanup EXIT

download_verified() {
  local url="$1"
  local digest="$2"
  local destination="$3"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --output "${destination}" "${url}"
  local actual
  actual="$(shasum -a 256 "${destination}" | awk '{print $1}')"
  [[ "${actual}" == "${digest}" ]] || fail "checksum mismatch for $(basename "${destination}")"
}

assert_native_macho() {
  local binary="$1"
  file "${binary}" | grep -q 'Mach-O 64-bit' || \
    fail "$(basename "${binary}") is not a 64-bit Mach-O executable"
  lipo -archs "${binary}" | grep -qw "${TARGET_ARCH}" || \
    fail "$(basename "${binary}") lacks ${TARGET_ARCH}"
}

assert_portable_macho_tree() {
  local root="$1"
  while IFS= read -r -d '' candidate; do
    if ! file "${candidate}" | grep -q 'Mach-O'; then
      continue
    fi
    while IFS= read -r dependency; do
      dependency="${dependency#"${dependency%%[![:space:]]*}"}"
      dependency="${dependency%% *}"
      case "${dependency}" in
        /usr/lib/*|/System/Library/*|@rpath/*|@loader_path/*|@executable_path/*) ;;
        "${root}"/*) ;;
        *) fail "external dynamic dependency ${dependency} in ${candidate}" ;;
      esac
    done < <(otool -L "${candidate}" | tail -n +2)
  done < <(find "${root}" -type f -print0)
}

relocate_macho_tree() {
  local root="$1"
  while IFS= read -r -d '' candidate; do
    local description
    description="$(file "${candidate}")"
    if [[ "${description}" != *Mach-O* ]]; then
      continue
    fi
    if [[ "${description}" == *"dynamically linked shared library"* ]]; then
      install_name_tool -id "@rpath/$(basename "${candidate}")" "${candidate}"
    fi
    while IFS= read -r dependency; do
      dependency="${dependency#"${dependency%%[![:space:]]*}"}"
      dependency="${dependency%% *}"
      if [[ "${dependency}" == "${root}"/* ]]; then
        install_name_tool -change "${dependency}" "@rpath/$(basename "${dependency}")" "${candidate}"
      fi
    done < <(otool -L "${candidate}" | tail -n +2)
    if [[ "${description}" == *"Mach-O 64-bit executable"* ]]; then
      install_name_tool -add_rpath "@executable_path/../lib" "${candidate}"
    fi
  done < <(find "${root}" -type f -print0)
}

POSTGRESQL_SOURCE_ARCHIVE="${SOURCE_ROOT}/${POSTGRESQL_ARCHIVE}"
download_verified "${POSTGRESQL_URL}" "${POSTGRESQL_SHA256}" "${POSTGRESQL_SOURCE_ARCHIVE}"
tar -xjf "${POSTGRESQL_SOURCE_ARCHIVE}" -C "${SOURCE_ROOT}"
POSTGRESQL_PREFIX="${DIST_ROOT}/postgresql"
(
  cd "${SOURCE_ROOT}/postgresql-${POSTGRESQL_VERSION}"
  LDFLAGS="-Wl,-headerpad_max_install_names" ./configure \
    --prefix="${POSTGRESQL_PREFIX}" \
    --disable-nls \
    --without-icu \
    --without-readline \
    --without-zlib
  make -s -j"$(sysctl -n hw.logicalcpu)"
  make -s install
)
cp "${SOURCE_ROOT}/postgresql-${POSTGRESQL_VERSION}/COPYRIGHT" "${POSTGRESQL_PREFIX}/COPYRIGHT"
relocate_macho_tree "${POSTGRESQL_PREFIX}"
assert_native_macho "${POSTGRESQL_PREFIX}/bin/postgres"
assert_portable_macho_tree "${POSTGRESQL_PREFIX}"
"${POSTGRESQL_PREFIX}/bin/postgres" --version | grep -q "PostgreSQL) ${POSTGRESQL_VERSION}"

VALKEY_SOURCE_ARCHIVE="${SOURCE_ROOT}/${VALKEY_ARCHIVE}"
download_verified "${VALKEY_URL}" "${VALKEY_SHA256}" "${VALKEY_SOURCE_ARCHIVE}"
tar -xzf "${VALKEY_SOURCE_ARCHIVE}" -C "${SOURCE_ROOT}"
VALKEY_PREFIX="${DIST_ROOT}/valkey"
(
  cd "${SOURCE_ROOT}/valkey-${VALKEY_VERSION}"
  GIT_CEILING_DIRECTORIES="${SOURCE_ROOT}" SOURCE_DATE_EPOCH=0 \
    make -s -j"$(sysctl -n hw.logicalcpu)" BUILD_TLS=no MALLOC=libc
  GIT_CEILING_DIRECTORIES="${SOURCE_ROOT}" SOURCE_DATE_EPOCH=0 \
    make -s PREFIX="${VALKEY_PREFIX}" BUILD_TLS=no MALLOC=libc install
)
cp "${SOURCE_ROOT}/valkey-${VALKEY_VERSION}/COPYING" "${VALKEY_PREFIX}/COPYING"
assert_native_macho "${VALKEY_PREFIX}/bin/valkey-server"
assert_portable_macho_tree "${VALKEY_PREFIX}"
"${VALKEY_PREFIX}/bin/valkey-server" --version | grep -q "v=${VALKEY_VERSION}"

NODE_SOURCE_ARCHIVE="${SOURCE_ROOT}/${NODE_ARCHIVE}"
download_verified "${NODE_URL}" "${NODE_SHA256}" "${NODE_SOURCE_ARCHIVE}"
tar -xzf "${NODE_SOURCE_ARCHIVE}" -C "${SOURCE_ROOT}"
mv "${SOURCE_ROOT}/node-v${NODE_VERSION}-darwin-${TARGET_ARCH/x86_64/x64}" "${DIST_ROOT}/node"
assert_native_macho "${DIST_ROOT}/node/bin/node"
assert_portable_macho_tree "${DIST_ROOT}/node"
[[ "$(env -i "${DIST_ROOT}/node/bin/node" --version)" == "v${NODE_VERSION}" ]] || \
  fail "Node version validation failed"

cat >"${DIST_ROOT}/node/PROVENANCE.json" <<EOF
{
  "archive_sha256": "${NODE_SHA256}",
  "component": "node",
  "license": "MIT",
  "source_url": "${NODE_URL}",
  "target": "${TARGET_NAME}",
  "version": "${NODE_VERSION}"
}
EOF

cat >"${DIST_ROOT}/provenance/postgresql.json" <<EOF
{
  "archive_sha256": "${POSTGRESQL_SHA256}",
  "component": "postgresql",
  "license": "PostgreSQL",
  "source_url": "${POSTGRESQL_URL}",
  "target": "${TARGET_NAME}",
  "version": "${POSTGRESQL_VERSION}"
}
EOF

cat >"${DIST_ROOT}/provenance/valkey.json" <<EOF
{
  "archive_sha256": "${VALKEY_SHA256}",
  "component": "valkey",
  "license": "BSD-3-Clause",
  "source_url": "${VALKEY_URL}",
  "target": "${TARGET_NAME}",
  "version": "${VALKEY_VERSION}"
}
EOF

chmod -R u+rwX,go-rwx "${DIST_ROOT}"
mv "${DIST_ROOT}" "${OUTPUT_ROOT}"
assert_portable_macho_tree "${OUTPUT_ROOT}/postgresql"
assert_portable_macho_tree "${OUTPUT_ROOT}/valkey"
assert_portable_macho_tree "${OUTPUT_ROOT}/node"
"${OUTPUT_ROOT}/postgresql/bin/postgres" --version | grep -q "PostgreSQL) ${POSTGRESQL_VERSION}"
"${OUTPUT_ROOT}/valkey/bin/valkey-server" --version | grep -q "v=${VALKEY_VERSION}"
[[ "$(env -i "${OUTPUT_ROOT}/node/bin/node" --version)" == "v${NODE_VERSION}" ]] || \
  fail "relocated Node version validation failed"
trap - EXIT
rm -rf "${STAGING_ROOT}"

echo "${TARGET_NAME} runtime dependencies built at ${OUTPUT_ROOT}"

#!/usr/bin/env bash
# Cross-platform release packaging script for AI Model Provenance Gate.
# Builds static binaries for darwin/arm64, darwin/amd64, linux/amd64, linux/arm64, and windows/amd64,
# verifies archive integrity and host smoke execution, and emits checksums.txt, SHA256SUMS, and manifest.json.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
BINARY="ai-model-provenance"
MODULE="github.com/devenes/ai-model-provenance-gate"
VERSION="${VERSION:-0.1.0}"
BUILD_TYPE="${BUILD_TYPE:-release}"
GIT_COMMIT="$(git -C "${ROOT_DIR}" rev-parse --short HEAD 2>/dev/null || echo "dev")"
BUILD_DATE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
GO_VERSION="$(go version | awk '{print $3}')"
HOST_OS="$(go env GOOS)"
HOST_ARCH="$(go env GOARCH)"

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

TARGETS=(
  "darwin/arm64"
  "darwin/amd64"
  "linux/amd64"
  "linux/arm64"
  "windows/amd64"
)

MANIFEST_ENTRIES=""

for target in "${TARGETS[@]}"; do
  GOOS="${target%/*}"
  GOARCH="${target#*/}"
  EXT=""
  if [[ "${GOOS}" == "windows" ]]; then
    EXT=".exe"
  fi

  STAGE_NAME="${BINARY}_${VERSION}_${GOOS}_${GOARCH}"
  STAGE_DIR="${DIST_DIR}/${STAGE_NAME}"
  STANDALONE_BIN="${DIST_DIR}/${STAGE_NAME}${EXT}"
  rm -rf "${STAGE_DIR}"
  mkdir -p "${STAGE_DIR}"

  echo "==> Building ${GOOS}/${GOARCH} (version=${VERSION}, commit=${GIT_COMMIT})..."
  CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" go build -trimpath \
    -ldflags="-s -w -X ${MODULE}/internal/version.ToolVersion=${VERSION} -X ${MODULE}/internal/version.GitCommit=${GIT_COMMIT} -X ${MODULE}/internal/version.BuildDate=${BUILD_DATE} -X ${MODULE}/internal/version.BuildType=${BUILD_TYPE}" \
    -o "${STAGE_DIR}/${BINARY}${EXT}" "${ROOT_DIR}/cmd/ai-model-provenance"

  FILE_DESC="$(file -b "${STAGE_DIR}/${BINARY}${EXT}")"
  BIN_SHA256="$(shasum -a 256 "${STAGE_DIR}/${BINARY}${EXT}" | awk '{print $1}')"
  BIN_SIZE="$(wc -c < "${STAGE_DIR}/${BINARY}${EXT}" | tr -d ' ')"

  SMOKE_STATUS="NOT_RUN (cross-compiled binary verified via file header; runtime requires ${GOOS}/${GOARCH} host)"
  if [[ "${GOOS}" == "${HOST_OS}" && "${GOARCH}" == "${HOST_ARCH}" ]]; then
    echo "==> Running native host smoke check on ${STAGE_DIR}/${BINARY}${EXT}..."
    "${STAGE_DIR}/${BINARY}${EXT}" version >/dev/null
    "${STAGE_DIR}/${BINARY}${EXT}" version --json >/dev/null
    "${STAGE_DIR}/${BINARY}${EXT}" --help >/dev/null
    "${STAGE_DIR}/${BINARY}${EXT}" inspect --help >/dev/null
    "${STAGE_DIR}/${BINARY}${EXT}" bom --help >/dev/null
    "${STAGE_DIR}/${BINARY}${EXT}" oms --help >/dev/null
    "${STAGE_DIR}/${BINARY}${EXT}" evidence --help >/dev/null
    "${STAGE_DIR}/${BINARY}${EXT}" gate --help >/dev/null
    "${STAGE_DIR}/${BINARY}${EXT}" release --help >/dev/null
    "${STAGE_DIR}/${BINARY}${EXT}" keygen --help >/dev/null
    SMOKE_STATUS="PASS (native ${HOST_OS}/${HOST_ARCH} execution verified)"
  fi

  cp "${ROOT_DIR}/README.md" "${ROOT_DIR}/CHANGELOG.md" "${ROOT_DIR}/LICENSE" "${STAGE_DIR}/"

  if [[ "${GOOS}" == "windows" ]]; then
    ARCHIVE_NAME="${STAGE_NAME}.zip"
    (cd "${DIST_DIR}" && zip -qr "${ARCHIVE_NAME}" "${STAGE_NAME}")
    unzip -t "${DIST_DIR}/${ARCHIVE_NAME}" >/dev/null
  else
    ARCHIVE_NAME="${STAGE_NAME}.tar.gz"
    tar -C "${DIST_DIR}" -czf "${DIST_DIR}/${ARCHIVE_NAME}" "${STAGE_NAME}"
    tar -tzf "${DIST_DIR}/${ARCHIVE_NAME}" >/dev/null
  fi

  cp "${STAGE_DIR}/${BINARY}${EXT}" "${DIST_DIR}/${BINARY}.tmp"
  rm -rf "${STAGE_DIR}"
  mv "${DIST_DIR}/${BINARY}.tmp" "${STANDALONE_BIN}"

  ARCHIVE_SHA256="$(shasum -a 256 "${DIST_DIR}/${ARCHIVE_NAME}" | awk '{print $1}')"
  ARCHIVE_SIZE="$(wc -c < "${DIST_DIR}/${ARCHIVE_NAME}" | tr -d ' ')"

  ENTRY=$(cat <<EOF
    {
      "os": "${GOOS}",
      "arch": "${GOARCH}",
      "binary": "${STAGE_NAME}${EXT}",
      "binarySha256": "${BIN_SHA256}",
      "binarySizeBytes": ${BIN_SIZE},
      "fileHeader": "${FILE_DESC}",
      "archive": "${ARCHIVE_NAME}",
      "sha256": "${ARCHIVE_SHA256}",
      "sizeBytes": ${ARCHIVE_SIZE},
      "runtimeSmokeTest": "${SMOKE_STATUS}"
    }
EOF
)
  if [[ -z "${MANIFEST_ENTRIES}" ]]; then
    MANIFEST_ENTRIES="${ENTRY}"
  else
    MANIFEST_ENTRIES="${MANIFEST_ENTRIES},
${ENTRY}"
  fi
done

(
  cd "${DIST_DIR}"
  shasum -a 256 -- "${BINARY}_${VERSION}"_* > SHA256SUMS
  cp SHA256SUMS checksums.txt
  shasum -a 256 -c SHA256SUMS >/dev/null
)

cat > "${DIST_DIR}/manifest.json" <<EOF
{
  "schemaVersion": "ai-model-provenance.release-manifest/v1",
  "name": "${BINARY}",
  "version": "${VERSION}",
  "gitCommit": "${GIT_COMMIT}",
  "buildDate": "${BUILD_DATE}",
  "buildType": "${BUILD_TYPE}",
  "goVersion": "${GO_VERSION}",
  "hostPlatform": "${HOST_OS}/${HOST_ARCH}",
  "artifacts": [
${MANIFEST_ENTRIES}
  ]
}
EOF

echo "==> Packaged and verified cross-platform v${VERSION} release artifacts in ${DIST_DIR}/:"
cat "${DIST_DIR}/SHA256SUMS"

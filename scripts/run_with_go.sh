#!/usr/bin/env bash
set -euo pipefail

ENV_FLAVOR="${CBMPC_ENV_FLAVOR:-host}"
DEFAULT_GOCACHE="${PWD}/build/.cache/go-build-${ENV_FLAVOR}"
DEFAULT_GOMODCACHE="${PWD}/build/.cache/go-mod-${ENV_FLAVOR}"
GOCACHE_DIR="${CBMPC_GOCACHE:-${DEFAULT_GOCACHE}}"
GOMODCACHE_DIR="${CBMPC_GOMODCACHE:-${DEFAULT_GOMODCACHE}}"
mkdir -p "${GOCACHE_DIR}" "${GOMODCACHE_DIR}"
export GOCACHE="${GOCACHE_DIR}"
export GOMODCACHE="${GOMODCACHE_DIR}"

# Set CGO flags for OpenSSL based on build flavor
OPENSSL_ROOT="${PWD}/build/openssl-${ENV_FLAVOR}"
export CGO_CFLAGS="${CGO_CFLAGS:+${CGO_CFLAGS} }-I${OPENSSL_ROOT}/include"
export CGO_CXXFLAGS="${CGO_CXXFLAGS:+${CGO_CXXFLAGS} }-I${OPENSSL_ROOT}/include"

# Add library paths that exist
LDFLAGS_OPENSSL=""
[[ -d "${OPENSSL_ROOT}/lib" ]] && LDFLAGS_OPENSSL="${LDFLAGS_OPENSSL} -L${OPENSSL_ROOT}/lib"
[[ -d "${OPENSSL_ROOT}/lib64" ]] && LDFLAGS_OPENSSL="${LDFLAGS_OPENSSL} -L${OPENSSL_ROOT}/lib64"
export CGO_LDFLAGS="${CGO_LDFLAGS:+${CGO_LDFLAGS} }${LDFLAGS_OPENSSL}"

# Enforce Go module immutability unless the caller opts out by specifying their own -mod flag.
CURRENT_GOFLAGS="${GOFLAGS:-}"
if [[ "${CURRENT_GOFLAGS}" != *"-mod="* ]]; then
  if [[ -z "${CURRENT_GOFLAGS}" ]]; then
    export GOFLAGS="-mod=readonly"
  else
    export GOFLAGS="${CURRENT_GOFLAGS} -mod=readonly"
  fi
fi

if [[ "${CBMPC_USE_DOCKER:-0}" == "1" ]]; then
  CBMPC_ENV_FLAVOR=docker GOFLAGS="${GOFLAGS}" scripts/docker_exec.sh go "$@"
  exit 0
fi

# Establish required Go version early for subsequent comparisons
GO_VERSION="${GO_VERSION:-1.25.3}"

if command -v go >/dev/null 2>&1; then
  # Prefer system Go only if it is recent enough; otherwise fall back to the pinned toolchain.
  SYS_GO_VER_RAW="$(go version | awk '{print $3}')"  # e.g. go1.24.2
  REQ_GO_VER_RAW="go${GO_VERSION}"                  # e.g. go1.25.3
  SYS_GO_VER_NUM="${SYS_GO_VER_RAW#go}"
  REQ_GO_VER_NUM="${REQ_GO_VER_RAW#go}"
  # Compare using sort -V: the lesser version will be first; if it's the system version, it's older.
  SMALLEST_VER="$(printf "%s\n%s\n" "${SYS_GO_VER_NUM}" "${REQ_GO_VER_NUM}" | sort -V | head -n1)"
  if [[ "${SMALLEST_VER}" == "${REQ_GO_VER_NUM}" ]]; then
    # System Go is older than required; use pinned toolchain below.
    :
  else
    exec go "$@"
  fi
fi

GO_ROOT="${CBMPC_GO_ROOT:-${PWD}/build/go-${ENV_FLAVOR}}"
LOCAL_GO="${GO_ROOT}/go/bin/go"

if [[ ! -x "${LOCAL_GO}" ]]; then
  scripts/install_go.sh "${GO_ROOT}" "${GO_VERSION}"
fi

PATH="${GO_ROOT}/go/bin:${PATH}" exec "${LOCAL_GO}" "$@"

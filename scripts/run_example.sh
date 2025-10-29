#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <go run arguments...>" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
GO_CACHE_DIR="${REPO_ROOT}/build/go-example-cache"
mkdir -p "${GO_CACHE_DIR}"

# Ensure module downloads are allowed for examples unless caller overrides.
GOFLAGS_WITH_MOD="${GOFLAGS:-}"
if [[ "${GOFLAGS_WITH_MOD}" != *"-mod="* ]]; then
  GOFLAGS_WITH_MOD="${GOFLAGS_WITH_MOD:+${GOFLAGS_WITH_MOD} }-mod=mod"
fi

# Inject version ldflags unless the caller already provided their own.
CMD="$1"
shift || true

HAVE_LDFLAGS=0
for arg in "$@"; do
  if [[ "$arg" == "-ldflags" ]]; then
    HAVE_LDFLAGS=1
    break
  fi
done

if [[ "$CMD" == "run" || "$CMD" == "build" || "$CMD" == "test" ]]; then
  if [[ "$HAVE_LDFLAGS" == "0" ]]; then
    LDFLAGS_STR="$(make -sC "${REPO_ROOT}" print-ldflags)"
    set -- "$CMD" -ldflags "${LDFLAGS_STR}" "$@"
  else
    set -- "$CMD" "$@"
  fi
else
  set -- "$CMD" "$@"
fi

GOCACHE="${GO_CACHE_DIR}" GOFLAGS="${GOFLAGS_WITH_MOD}" scripts/run_with_go.sh "$@"

#!/bin/bash

set -euo pipefail

SCRIPT_PATH="$(
  cd -- "$(dirname "$0")" >/dev/null 2>&1
  pwd -P
)"
ROOT_PATH="${SCRIPT_PATH}/.."

cd "${ROOT_PATH}"

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <ref_name>"
  echo "  ref_name: The release tag name (e.g. v0.1.0-beta)"
  exit 1
fi

REF_NAME=$1

git submodule update --init --recursive

rm -rf \
  "cb-mpc-go-${REF_NAME}.tar.gz" \
  bin \
  demos/tmp \
  demos/ecdsa_mp_ac_web/tmp \
  cb-mpc/build \
  cb-mpc/lib

COPYFILE_DISABLE=1 tar -czf "cb-mpc-go-${REF_NAME}.tar.gz" \
  --exclude='.git' \
  --exclude='.github' \
  --exclude='.buildkite' \
  --exclude='.DS_Store' \
  --exclude='*/.DS_Store' \
  --exclude='cb-mpc/.git' \
  --exclude='cb-mpc/.github' \
  --exclude='cb-mpc/.buildkite' \
  --exclude='*.tar.gz' \
  *

#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${1:-"$ROOT_DIR/demos/tmp/certs/ecdsa2pc_mtls"}"
LISTEN_ADDR="${2:-127.0.0.1:9440}"

PARTY0_LOG="$(mktemp)"
PARTY1_LOG="$(mktemp)"
PARTY0_PID=""
PARTY1_PID=""

cleanup() {
  if [[ -n "$PARTY0_PID" ]]; then
    kill "$PARTY0_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "$PARTY1_PID" ]]; then
    kill "$PARTY1_PID" >/dev/null 2>&1 || true
  fi
  rm -f "$PARTY0_LOG" "$PARTY1_LOG"
}
trap cleanup EXIT

bash "$ROOT_DIR/scripts/go_with_cpp.sh" go run ./demos/ecdsa2pc_mtls/main.go \
  --self 0 \
  --listen "$LISTEN_ADDR" \
  --ca "$CERT_DIR/ca.pem" \
  --cert "$CERT_DIR/party-0/cert.pem" \
  --key "$CERT_DIR/party-0/key.pem" \
  >"$PARTY0_LOG" 2>&1 &
PARTY0_PID=$!

sleep 1

bash "$ROOT_DIR/scripts/go_with_cpp.sh" go run ./demos/ecdsa2pc_mtls/main.go \
  --self 1 \
  --peer "$LISTEN_ADDR" \
  --ca "$CERT_DIR/ca.pem" \
  --cert "$CERT_DIR/party-1/cert.pem" \
  --key "$CERT_DIR/party-1/key.pem" \
  >"$PARTY1_LOG" 2>&1 &
PARTY1_PID=$!

party0_status=0
party1_status=0
wait "$PARTY0_PID" || party0_status=$?
wait "$PARTY1_PID" || party1_status=$?

echo "--- party 0 ---"
cat "$PARTY0_LOG"
echo "--- party 1 ---"
cat "$PARTY1_LOG"

if [[ $party0_status -ne 0 || $party1_status -ne 0 ]]; then
  exit 1
fi

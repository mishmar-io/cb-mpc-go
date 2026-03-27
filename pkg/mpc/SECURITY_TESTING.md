# Security Testing Coverage

This document describes the current security-relevant automated coverage for the
`cb-mpc-go` wrapper itself.

It is intentionally scoped to the Go API, the CGO boundary, and test/demo
helpers in this repository. It does not claim deep cryptographic validation of
the upstream `cb-mpc` implementation.

## Active Test Suites

### `pkg/mpc/api_test.go`

Integration-style happy-path coverage for the shipped wrapper APIs:

- ECDSA 2PC and MP additive flows
- EdDSA 2PC and MP additive flows
- Schnorr 2PC and MP additive flows
- TDH2 DKG, encrypt, verify, partial decrypt, and combine
- PVE single-recipient, batch, and access-structure flows

Security-relevant assertions in these tests include:

- all parties derive the same public key material for a shared protocol run
- designated signature receivers are the only parties that receive MP outputs
- Ed25519 signatures verify against the derived public key
- ECDSA signatures are well-formed DER with positive `r`/`s` values
- TDH2 and PVE encrypt/verify/decrypt paths round-trip the expected plaintext

### `pkg/mpc/malicious_session_test.go`

Active negative coverage for shipped test helpers and selected failure modes:

- `mpctest.MaliciousSession` behavior isolation and error messages
- dropped-message behavior for interactive protocols with explicit timeouts
- garbage-message injection causing at least one protocol participant to fail

These tests intentionally focus on wrapper-visible behavior rather than making
claims about Byzantine fault tolerance or upstream protocol proofs.

### `internal/cgo/binding_hardening_test.go`

Boundary and hardening coverage for the CGO layer:

- `cmem_t` / `cmems_t` round-trip conversions
- rejection of embedded NUL bytes in C strings
- access-structure validation (cycles, unreachable nodes, invalid thresholds)
- panic recovery in exported transport and PVE callback bridges
- oversized callback-output rejection before `C.int` truncation
- fast-fail validation for MP signature receivers and AC quorum inputs
- TDH2 AC parallel-slice contract validation

## How To Run

Run the full wrapper test suite with the repository CGO environment:

```bash
bash scripts/go_with_cpp.sh go test ./...
```

Run only the Go wrapper integration tests:

```bash
bash scripts/go_with_cpp.sh go test ./pkg/mpc
```

Run only the CGO hardening tests:

```bash
bash scripts/go_with_cpp.sh go test ./internal/cgo
```

## Important Limits

The current automated coverage does not claim:

- deep cryptographic review of upstream `cb-mpc`
- proof of constant-time behavior or side-channel resistance
- authenticated or confidential transport from `mpctest.NewMockNetwork`
- general Byzantine fault tolerance, collusion resistance, or replay resistance
- production readiness of example code or dev certificate scripts

## Production Assumptions

The wrapper assumes that production callers provide their own `Session`
implementation with:

- authenticated transport
- confidential transport
- reasonable message-size limits
- timeout/cancellation handling for stalled or malicious peers

`mpctest.NewMockNetwork`, `mpctest.MaliciousSession`, and the example
transports exist to test or demonstrate integration behavior. They are not
drop-in production transports.

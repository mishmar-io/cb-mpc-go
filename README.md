# cb-mpc-go

[![Go Reference](https://pkg.go.dev/badge/github.com/coinbase/cb-mpc-go.svg)](https://pkg.go.dev/github.com/coinbase/cb-mpc-go)
[![CI](https://github.com/coinbase/cb-mpc-go/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/coinbase/cb-mpc-go/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Go bindings for Coinbase MPC, implemented strictly on top of the public C API (`include/cbmpc/c_api/*`).

## Status

`cb-mpc-go` is beta software. Its primary goal is to make the public `cb-mpc` C API easier to use from Go while the wrapper surface continues to mature.

Project policies:

- [License](LICENSE)
- [Security Policy](SECURITY.md)
- [Bug Bounty Scope](BUG_BOUNTY.md)
- [Security Testing Notes](pkg/mpc/SECURITY_TESTING.md)
- [Contributing](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

## Scope

- Uses only the **public install** of `cb-mpc` (`include/` + `lib/`)
- Does **not** depend on `include-internal/` or any internal C++ headers
- Wraps the public C API surface in `pkg/mpc`

## Supported Protocols

- ECDSA 2PC: DKG, refresh, sign, key/public-share helpers
- ECDSA MP: additive + access-structure variants
- EdDSA 2PC/MP: additive + access-structure variants
- Schnorr 2PC/MP: additive + access-structure variants, x-only pubkey extract
- TDH2: DKG, encrypt/verify, partial decrypt, combine (additive + AC)
- PVE / PVE Batch / PVE AC: encrypt/verify/decrypt + helper constructors for
  built-in RSA/ECIES keys and external RSA modulus / ECIES public-key import +
  optional callback bridges (base PKE / KEM / HSM)

## Requirements

- Go 1.25+
- CMake + C++17 toolchain
- `cb-mpc` submodule checked out at upstream tag `v0.2.0` (this repo vendors it as a submodule)
- OpenSSL/toolchain setup required by the pinned `cb-mpc` revision (see `cb-mpc/README.md`; `v0.2.0` uses the OpenSSL 3.6.1 flow)

## Build and Test

```bash
# Initialize the pinned cb-mpc v0.2.0 submodule
make deps

# Build cb-mpc + public install, then Go code
make build

# Run tests
make test

# Run the same golangci-lint version as CI
make lint

# Run the same govulncheck version as CI
make vulncheck

# Run protocol examples
make examples

# Show production-like demo workflows
make demos-help
```

The runnable interactive examples use `mpctest.NewMockNetwork` for local demos
and tests. That transport is not authenticated or confidential. Production
deployments should provide their own `Session`.

This repository keeps zero-setup examples and production-like demos separate:

- `examples/` are self-contained local runs meant for `make examples`
- `demos/` are networked reference workflows that may require setup such as PEM cert generation
- the reference demo mTLS transport in `demos/common/mtls.go` is intentionally local/demo-oriented, not a production-ready networking layer

## Dependency Setup

This module is published as:

```bash
go get github.com/coinbase/cb-mpc-go
```

`cb-mpc-go` is a CGO wrapper, not a pure-Go package. Consumers must make the
`cb-mpc` public install artifacts available at build time:

- public headers under `cbmpc/c_api/*`
- `libcbmpc`
- OpenSSL libraries compatible with the pinned `cb-mpc` revision

When working from this repository, `bash scripts/go_with_cpp.sh ...` sets the
required CGO include/library paths automatically.

If you are building outside this repository wrapper script, set the equivalent
environment yourself, for example:

```bash
export CBMPC_PREFIX="/path/to/cb-mpc/build/install/public"
export CGO_CFLAGS="-I${CBMPC_PREFIX}/include"
export CGO_CXXFLAGS="-I${CBMPC_PREFIX}/include"
export CGO_LDFLAGS="-L${CBMPC_PREFIX}/lib -L/path/to/openssl/lib"
```

The helper script also supports overriding the install locations with:

- `CBMPC_PREFIX`
- `CBMPC_OPENSSL_ROOT`

### Linux / OpenSSL Notes

The default `CBMPC_OPENSSL_ROOT` in `scripts/go_with_cpp.sh` points at a
Homebrew-style macOS location. On Linux or other layouts, set
`CBMPC_OPENSSL_ROOT` explicitly before invoking the script, or mirror the
OpenSSL setup used in CI under `.github/workflows/ci.yml` and `scripts/openssl/`.

This repository intentionally pins the underlying `cb-mpc` submodule to the
tested upstream `v0.2.0` release instead of following a floating branch.

All Go commands should run through `scripts/go_with_cpp.sh` (the Makefile already does this) so `CGO_CFLAGS` and `CGO_LDFLAGS` point at:

- `cb-mpc/build/install/public/include`
- `cb-mpc/build/install/public/lib`

## Quick Example (ECDSA-2PC)

```go
import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/coinbase/cb-mpc-go/pkg/mpc"
	"github.com/coinbase/cb-mpc-go/pkg/mpctest"
)

ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

// mpctest.NewMockNetwork is for local demos/tests only.
sessions := mpctest.NewMockNetwork(2)
defer sessions[0].Close()
defer sessions[1].Close()

var (
	keyBlobs [2][]byte
	wg       sync.WaitGroup
	errCh    = make(chan error, 2)
)

for i := 0; i < 2; i++ {
	wg.Add(1)
	go func(idx int) {
		defer wg.Done()
		blob, err := mpc.ECDSA2PDKG(ctx, sessions[idx], mpc.CurveSecp256k1)
		if err != nil {
			errCh <- err
			return
		}
		keyBlobs[idx] = blob
	}(i)
}
wg.Wait()
close(errCh)

for err := range errCh {
	if err != nil {
		log.Fatalf("ecdsa 2pc dkg failed: %v", err)
	}
}
```

See full runnable examples in:

- `examples/ecdsa2pc`
- `examples/schnorr2pc`
- `examples/eddsa2pc`
- `examples/eddsa_mp_backup` for multi-key EdDSA-MP share backup and restore via PVE-AC
- `examples/pve_showcase` for custom base-PKE callbacks and simulated ECIES HSM-backed PVE flows
- `examples/tdh2`
- `examples/pve_batch`

Production-like demos live under:

- `demos/ecdsa2pc_mtls` for a two-process ECDSA-2PC flow over a reference mTLS transport
- `demos/ecdsa_mp_ac_mtls` for a three-process ECDSA-MP access-structure DKG/sign/refresh/sign workflow over mTLS
- `demos/eddsa_mp_backup_mtls` for a three-process EdDSA-MP backup and restore showcase over mTLS
- `demos/tdh2_mtls` for a three-process TDH2 encrypt/partial-decrypt/combine workflow over mTLS

See `demos/README.md` for certificate generation and multi-terminal launch
commands.

## Architecture

```text
pkg/mpc (public Go API)
  -> internal/cgo (only package importing "C")
    -> cb-mpc public C API (cbmpc/c_api/*) + libcbmpc
```

## Notes

- The underlying `cb-mpc` implementation is not thread-safe; do not share mutable protocol state across goroutines without synchronization.
- Interactive protocols require all parties to run concurrently and exchange messages through a `Session`.
- `mpctest.NewMockNetwork` and the example transports are for demos and tests; production code should use a hardened authenticated/confidential transport with appropriate peer-identity binding and deadlines/timeouts.
- Many returned blobs (key blobs, private shares, decryption keys) contain sensitive material. They are returned as Go `[]byte` and may remain in memory until garbage collected; zeroize buffers when you are done with them if you need stricter in-memory handling (see `mpc.Zeroize` / `mpc.ZeroizeSlices` or `mpc.Sensitive` / `mpc.SensitiveSlices`).
- Production `Session` implementations should provide authenticated + confidential transport and enforce reasonable message size limits to avoid memory-exhaustion attacks from untrusted peers.

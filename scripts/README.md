## Scripts guide

This directory contains small utilities that standardize local and Docker-based development for cb-mpc-go. They pin toolchain versions, configure CGO to link against the locally-built OpenSSL, and keep caches isolated per environment flavor (host vs docker).

### Common environment variables

- **CBMPC_USE_DOCKER**: Set to `1` to route commands through a dev Docker image; default `0` (host). Used by wrappers to dispatch via Docker.
- **CBMPC_ENV_FLAVOR**: "host" or "docker". Defaults based on context (`host` unless routed via Docker). Controls cache directories and `build/openssl-<flavor>` pathing.
- **CBMPC_OPENSSL_ROOT**: Override the OpenSSL install prefix used by builds and CGO. Defaults to `build/openssl-<flavor>`.
- **CBMPC_GOCACHE**, **CBMPC_GOMODCACHE**, **CBMPC_GOLANGCI_CACHE**: Optional cache overrides. Defaults live under `build/.cache/*-<flavor>`.
- **CBMPC_GO_ROOT**: Directory where a pinned Go toolchain is installed if the system Go is too old. Default `build/go-<flavor>`.
- **GO_VERSION**: Required Go version used by wrappers when pinning. Default `1.25.3`.
- **CBMPC_TOOLS_BIN**: Location to install local dev tools (e.g., `golangci-lint`). Default `build/bin-<flavor>`.
- **CBMPC_USE_SYSTEM_GOLANGCI**: Set to `1` to prefer the system `golangci-lint` if present; default uses the pinned binary.
- Docker-related (when CBMPC_USE_DOCKER=1):
  - **CBMPC_DOCKER_BIN**: Docker CLI to use (default `docker`).
  - **CBMPC_DOCKER_IMAGE**: Dev image name (default `cb-mpc-go/dev`).
  - **CBMPC_DOCKERFILE**: Dockerfile path (default `Dockerfile`).
  - **CBMPC_DOCKER_PLATFORM**: Optional platform (e.g., `linux/amd64`).
- CGO flags are set automatically by wrappers to include the selected OpenSSL: `CGO_CFLAGS`, `CGO_CXXFLAGS`, `CGO_LDFLAGS`.
- **GOFLAGS**: `run_with_go.sh` will enforce `-mod=readonly` by default if not set. `run_example.sh` defaults to `-mod=mod` so examples can fetch modules.

### Script overview

- **bootstrap.sh**: One-step local setup: install Git LFS, sync submodules, verify submodule state, build OpenSSL and cb-mpc (unless `CBMPC_SKIP_BUILD=1`), warm up Go and `golangci-lint`.
- **build_openssl.sh [install-root]**: Download and build a minimal static OpenSSL into `install-root` (default `build/openssl-<flavor>`). Verifies checksum and configures per host OS/arch.
- **build_cbmpc.sh [build-type]**: Configure and build the `cb-mpc` static library (`cbmpc`) using CMake; `build-type` default `Release`. Cleans stale CMake caches if the source dir changes.
- **check_submodule.sh**: Guardrails for the `cb-mpc` submodule: initialized, clean (no local changes), and pinned in the index.
- **run_host_or_docker.sh <cmd> [args...]**: Dispatch helper that runs `<cmd>` locally or via Docker based on `CBMPC_USE_DOCKER`.
- **docker_exec.sh <cmd> [args...]**: Ensure/build the dev image and run `<cmd>` inside it with caches mounted and user mapping preserved.
- **run_with_go.sh <go args...>**: Wrapper for `go` that sets caches, links OpenSSL via CGO flags, and selects a recent system Go or installs a pinned toolchain (`GO_VERSION`). Respects Docker if enabled.
- **run_golangci.sh <args...>**: Wrapper for `golangci-lint` mirroring the environment setup in `run_with_go.sh`; installs a pinned linter if not present.
- **install_go.sh [dest-root] [version]**: Fetch and unpack a Go toolchain under `dest-root` (default `build/go`), removing testdata to avoid spurious module scans.
- **install_golangci.sh <dest> [version]**: Install `golangci-lint` to `<dest>` using the pinned Go toolchain.
- **run_example.sh <go run args...>**: Convenience wrapper for running examples with isolated cache; routes through `run_with_go.sh` and defaults to `GOFLAGS=-mod=mod`.

### Examples

- Run unit tests on host:
  ```bash
  make test
  # or
  scripts/run_with_go.sh test ./pkg/...
  ```

- Run unit tests in Docker:
  ```bash
  CBMPC_USE_DOCKER=1 make test
  ```

- Lint and auto-fix:
  ```bash
  scripts/run_golangci.sh run --fix ./pkg/...
  ```

- Build OpenSSL and cb-mpc:
  ```bash
  make openssl
  make build-cbmpc
  ```

- Run an example:
  ```bash
  scripts/run_example.sh run ./examples/kem-pve-roundtrip/main.go
  ```



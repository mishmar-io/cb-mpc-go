# Contributing to cb-mpc-go

Thanks for your interest in `cb-mpc-go`.

`cb-mpc-go` is beta software and is intentionally focused on demonstrating and exposing the public `cb-mpc` C API through an idiomatic Go package. Please keep that scope in mind when proposing changes.

## Before Opening a Change

- For non-security bugs, API feedback, wrapper usability issues, and documentation improvements, please open an issue first when practical.
- For security-sensitive reports, do not open a public issue. Follow `SECURITY.md`.
- If the issue appears to belong to the underlying `cb-mpc` library rather than this Go wrapper, please use the upstream guidance in `cb-mpc/SECURITY.md`.

## Pull Requests

We welcome focused contributions that improve the wrapper, tests, examples, or documentation. Because the project is beta and still evolving, not every proposed API addition or architectural change will be accepted.

Please keep pull requests aligned with the repository's design constraints:

- Depend only on the public `cb-mpc` install artifacts.
- Keep all `import "C"` usage inside `internal/cgo`.
- Do not add dependencies on `include-internal/` or non-public `cbmpc` headers.
- Prefer small, reviewable changes with tests or runnable examples when practical.

## Development Workflow

Use the repository scripts and Makefile so CGO points at the public install prefix:

```bash
make deps
make build
make test
make sanitize-go
make lint
make vulncheck
make examples
make demos-help
```

If you run Go commands directly, use:

```bash
bash scripts/go_with_cpp.sh go test ./...
bash scripts/go_with_cpp.sh go -C demos/ecdsa_mp_ac_web test ./...
```

The root `go test ./...` and `go build ./...` patterns do not cross nested
module boundaries, so `make build`, `make test`, and `make lint` are the
safest full-repository entry points now that `demos/ecdsa_mp_ac_web` is an
isolated demo module.

The repository keeps:

- `examples/` for zero-setup local runs
- `demos/` for multi-process/networked demo workflows with extra setup such as PEM cert generation

## Releases

`cb-mpc-go` follows the same tag-driven release process as `cb-mpc`, adapted to
this repository:

- release tags remain beta/prerelease tags until the public Go API stabilizes; the first published tag is `v0.1.0-beta`
- merge the release-related changes to `master` first, then push the version tag
- pushing a version tag runs `.github/workflows/ci.yml`
- the same tag also triggers `.github/workflows/make-release.yml`, which creates `cb-mpc-go-<tag>.tar.gz`, generates a provenance attestation, and opens a draft GitHub Release

## Licensing

By submitting a contribution, you agree that your contributions will be licensed under the MIT License for this repository.

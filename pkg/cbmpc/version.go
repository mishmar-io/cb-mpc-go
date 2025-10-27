package cbmpc

import "github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"

var (
	// Version is the wrapper version populated at build time via -ldflags.
	Version = "v0.0.0-in-progress"
	// UpstreamSHA is the pinned upstream cb-mpc commit used for builds.
	UpstreamSHA = "unknown"
	// UpstreamDir is the submodule directory name for the upstream tree.
	UpstreamDir = "cb-mpc"
)

// WrapperVersion returns the semantic version populated at build time via
// ldflags. In development it defaults to v0.0.0-in-progress.
func WrapperVersion() string {
	return Version
}

// UpstreamVersion returns the version string reported by the native bindings if
// available; otherwise it falls back to the pinned upstream commit SHA.
func UpstreamVersion() string {
	if v := backend.Version(); v != "" {
		return v
	}
	return UpstreamSHA
}

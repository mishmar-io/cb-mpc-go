//go:build cgo && !windows

package cbmpc_test

import (
	"fmt"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
)

// ExampleWrapperVersion demonstrates how to retrieve the wrapper version.
func ExampleWrapperVersion() {
	// WrapperVersion returns the version of the Go wrapper library.
	// In production builds with proper ldflags, this will be a semantic version like "v0.1.0".
	// In development builds without ldflags, it may be "unknown" or a git describe output.
	version := cbmpc.WrapperVersion()

	// For testing purposes, we just check that it returns a non-empty string
	if version != "" && version != "unspecified" {
		fmt.Println("Wrapper version available")
	}
	// Output:
	// Wrapper version available
}

// ExampleUpstreamVersion demonstrates how to retrieve the upstream cb-mpc version.
func ExampleUpstreamVersion() {
	// UpstreamVersion returns the commit SHA of the cb-mpc C++ library.
	// In production builds with proper ldflags, this will be a full commit hash.
	// In development builds without ldflags, it may be "unknown".
	version := cbmpc.UpstreamVersion()

	// For testing purposes, we just check that it returns a non-empty string
	if version != "" && version != "unknown" {
		fmt.Println("Upstream version available")
	}
	// Output:
	// Upstream version available
}

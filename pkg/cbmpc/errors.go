//go:build cgo && !windows

package cbmpc

import (
	"errors"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// ErrNotBuilt indicates the native MPC bindings are not available in the
// current build (e.g., built without CGO or on an unsupported platform).
//
// Functions that require the native library will return this error when called
// in such environments.
var ErrNotBuilt = errors.New("cbmpc: native bindings not built")

// ErrMustLock indicates a signature verification failure in global abort mode,
// which may leak a single bit of information about the private key.
// This error requires special handling: the key should be treated as compromised and not used further.
// Do not use it further; halt any ongoing or parallel signing processes and begin
// an incident investigation, with particular focus on the counterparty.
var ErrMustLock = errors.New("potential bit leak of private key detected in signature verification")

// RemapError converts bindings layer errors to public API errors.
// This is exported for use by protocol subpackages.
func RemapError(err error) error {
	if err == nil {
		return nil
	}
	// Map backend.ErrNotBuilt to the public sentinel error.
	if errors.Is(err, backend.ErrNotBuilt) {
		return ErrNotBuilt
	}
	// Map bindings.ErrMustLock to public ErrMustLock using errors.Is to avoid
	// string comparison fragility.
	if errors.Is(err, backend.ErrMustLock) {
		return ErrMustLock
	}
	return err
}

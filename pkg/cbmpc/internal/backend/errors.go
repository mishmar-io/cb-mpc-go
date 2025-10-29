//go:build !windows

package backend

import "errors"

// ErrNotBuilt reports that the native bindings were not linked into the
// current binary.
var ErrNotBuilt = errors.New("cbmpc/internal/bindings: native bindings not built")

// ErrMustLock indicates potential leakage of a single bit of the key.
// The caller must halt all other parallel operations and should not
// initiate another operation until the error is investigated.
var ErrMustLock = errors.New("potential bit leak of private key detected")

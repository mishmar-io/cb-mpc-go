// Package mpc provides Go wrappers over cb-mpc's public C API.
//
// The API surface mirrors protocol families in cbmpc/c_api/*:
// ECDSA (2PC + MP), EdDSA, Schnorr, TDH2, PVE, PVE batch, and PVE AC.
//
// Interactive protocols require all parties to execute concurrently while
// exchanging messages over the Session interface.
//
// Security notes:
//   - Many functions return opaque blobs that contain sensitive key material.
//     These are returned as Go byte slices and may remain in memory until garbage
//     collected. Zeroize buffers when you are done with them if you need stricter
//     in-memory handling (see Zeroize / ZeroizeSlices or Sensitive / SensitiveSlices).
//   - Test/demo transports live in `pkg/mpctest`. Production code should
//     provide its own Session implementation.
//   - Production Session implementations should provide authenticated +
//     confidential transport and enforce reasonable message size limits to avoid
//     memory-exhaustion attacks from untrusted peers.
//
// The underlying cb-mpc implementation is not thread-safe. Treat protocol state
// as single-threaded unless you provide your own synchronization.
package mpc

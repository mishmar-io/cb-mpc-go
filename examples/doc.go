// Package examples provides helper code for runnable protocol examples.
//
// Example binaries live under:
//   - examples/ecdsa2pc
//   - examples/schnorr2pc
//   - examples/eddsa2pc
//   - examples/tdh2
//   - examples/pve_batch
//
// The mTLS session implementation in this package is a reference starting
// point for real network deployments. It demonstrates one way to implement the
// Session contract over a network, but it is not a hardened drop-in production
// transport.
package examples

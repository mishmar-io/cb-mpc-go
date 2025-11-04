// Package mtls provides an implementation of transport.Transport
// built on mutual TLS (mTLS). It enforces TLS 1.3 as the minimum version, mutual
// authentication, and peer identity binding to certificate SANs (CN is ignored).
// The package is designed to be the recommended default transport for MPC while
// keeping the core library transport-agnostic.
//
// For usage examples, see example_test.go in this package.
//
// In development, use the certificate generator under
// examples/certutil/cmd/gen-certs to produce demo certificates. In production,
// integrate with your PKI; ensure each Party.Name is present as a DNS SAN in its
// certificate. All Party.Name values and Addresses must be unique and non-empty.
// Identity is derived from certificate SANs, not network addresses.
//
// Operational notes:
//
//   - Timeouts: Handshake and Connect timeouts have safe defaults. Per-frame
//     Read/Write deadlines are disabled by default (zero values). Set non-zero
//     Read/Write deadlines in production or untrusted networks to ensure IO
//     operations do not block indefinitely. Choose values appropriate for your
//     message sizes and network latency.
//
//   - Message ownership: Send() makes a defensive copy of the provided payload
//     before enqueueing to avoid data races if the caller mutates the slice after
//     calling Send. This improves safety at the cost of an allocation/copy per
//     message. For high-throughput scenarios, consider tuning Buffers and
//     reusing caller-side buffers to reduce allocation pressure.
//
//   - Connection model: Exactly one long-lived TLS connection is maintained per
//     peer. Duplicate connections are rejected. If a per-peer connection fails
//     after establishment, the transport marks that peer as failed and does not
//     attempt reconnection automatically; callers should treat this as a fatal
//     condition for that peer and recreate the transport if necessary.
//
//   - Limits and safety: MaxMessage bounds payload sizes on both read and write.
//     TLS 1.3 is enforced as a minimum (or higher if configured). SAN-based peer
//     identity verification is performed, with optional SPKI pinning and
//     user-provided VerifyPeer for additional checks.
package mtls

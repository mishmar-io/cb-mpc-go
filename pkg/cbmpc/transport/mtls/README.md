# mtls transport

This package implements `cbmpc.Transport` over mutual TLS (mTLS) with secure defaults:

- TLS 1.3 minimum (enforced), mutual authentication required
- Peer identity binding to certificate SANs (client sets SNI for server verification)
- Bounded frame sizes, buffered channels, and per-op deadlines
- Simple reconnect loop with exponential backoff

See `pkg/cbmpc/transport/mtls/example_test.go` for working examples of setting up and using the mTLS transport.

Certificates

- For development, use `examples/certutil/cmd/gen-certs` to generate a demo CA and per-party certs.
- In production, integrate with your PKI; ensure each party's `Party.Name` is present as a DNS SAN in its certificate.

Security notes

- SAN-only identity binding; CN is ignored. Party identity is derived from the peer's certificate SANs, not network addresses.
- TLS 1.3 minimum is enforced; values below TLS 1.3 in `TLS.MinVersion` are upgraded to TLS 1.3.
- TLS 1.3 ciphers are safe by default; `TLS.CipherSuites` is optional.
- Consider setting `TLS.SPKIPin` for certificate pinning (optional).
- All `Party.Name` values must be unique across the cluster and non-empty. Addresses must also be unique and non-empty.
- `RemoteAddr()` is not used for identity; NAT and ephemeral ports make address-based identity unreliable.

Troubleshooting

- Connection timeouts: ensure parties start close in time and addresses are reachable.
- Certificate errors: verify CA pool, SANs, and SNI (`Party.Name`).

# mtls transport

This package implements `cbmpc.Transport` over mutual TLS (mTLS) with secure defaults:

- TLS 1.3 minimum (enforced), mutual authentication required
- Peer identity binding to certificate SANs (SNI enforced)
- Bounded frame sizes, buffered channels, and per-op deadlines
- Simple reconnect loop with exponential backoff

See `pkg/cbmpc/transport/mtls/example_test.go` for working examples of setting up and using the mTLS transport.

Certificates

- For development, use `examples/certutil/cmd/gen-certs` to generate a demo CA and per-party certs.
- In production, integrate with your PKI or SPIFFE/SVID; ensure party names are present as DNS SANs.

Security notes

- SAN-only identity binding; CN is ignored.
- TLS 1.3 minimum is enforced; values below TLS 1.3 in `TLS.MinVersion` are upgraded to TLS 1.3.
- TLS 1.3 ciphers are safe by default; `TLS.CipherSuites` is optional.
- Consider setting `TLS.SPKIPin` for certificate pinning (optional).

Troubleshooting

- Connection timeouts: ensure parties start close in time and addresses are reachable.
- Certificate errors: verify CA pool, SANs, and SNI (`Party.Name`).

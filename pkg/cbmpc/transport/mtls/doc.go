// Package mtls provides an implementation of transport.Transport
// built on mutual TLS (mTLS). It enforces TLS 1.3 as the minimum version, mutual
// authentication, and peer identity binding to certificate SANs. The package is
// designed to be the recommended default transport for MPC while keeping the
// core library transport-agnostic.
//
// Quick start:
//
//	// Build Parties and TLS config (certs and CA pool)
//	t, err := mtls.New(mtls.Config{
//		SelfIndex:  self,
//		Parties:    parties,
//		TLS:        mtls.TLSConfig{Certificate: cert, RootCAs: caPool},
//		MaxMessage: 32 << 20, // 32 MiB cap
//	})
//	if err != nil { /* handle */ }
//	defer t.Close()
//
// In development, use the certificate generator under
// examples/certutil/cmd/gen-certs to produce demo certificates. In production,
// integrate with your PKI or SPIFFE/SVID issuance.
package mtls

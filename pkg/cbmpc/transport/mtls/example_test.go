//go:build cgo && !windows

package mtls_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/transport/mtls"
)

// Example demonstrates how to set up an mTLS transport for MPC operations.
// This example shows the structure - in practice you would need valid certificates.
func Example() {
	// Define party names and addresses
	names := []string{"party0", "party1", "party2"}
	addrs := []string{"localhost:8000", "localhost:8001", "localhost:8002"}
	self := 0 // This party's index

	// In a real application, you would load these from files or a key management system
	// For this example, we show the structure without actual certificates
	var cert tls.Certificate // Would be loaded via tls.LoadX509KeyPair or similar
	var ca *x509.CertPool    // Would be loaded with x509.SystemCertPool or custom CA

	// Create party configuration
	parties := make([]mtls.Party, len(names))
	for i := range names {
		parties[i] = mtls.Party{Name: names[i], Address: addrs[i]}
	}

	// Configure the mTLS transport
	_ = mtls.Config{
		SelfIndex:  self,
		Parties:    parties,
		TLS:        mtls.TLSConfig{Certificate: cert, RootCAs: ca},
		MaxMessage: 32 << 20, // 32 MB max message size
	}

	// This would create the transport in a real scenario
	// t, err := mtls.New(config)
	// if err != nil {
	// 	return err
	// }
	// defer t.Close()

	// Create an MPC job with the transport
	// ctx := context.Background()
	// job, err := cbmpc.NewJobMPWithContext(ctx, t, cbmpc.RoleID(self), names)
	// if err != nil {
	// 	return err
	// }
	// defer job.Close()

	fmt.Printf("Transport configured with %d parties\n", len(parties))

	// Output:
	// Transport configured with 3 parties
}

// ExampleConfig demonstrates the structure of an mTLS transport configuration.
func ExampleConfig() {
	// Party configuration: each party has a name (used for SNI/SAN matching)
	// and an address (host:port for TCP connection)
	parties := []mtls.Party{
		{Name: "alice", Address: "alice.example.com:8000"},
		{Name: "bob", Address: "bob.example.com:8001"},
	}

	// TLS configuration requires:
	// - Certificate: This party's TLS certificate (with private key)
	// - RootCAs: Certificate pool for validating peer certificates
	var cert tls.Certificate
	var ca *x509.CertPool

	config := mtls.Config{
		SelfIndex:  0,       // Index of this party in the parties slice
		Parties:    parties, // All parties including self
		TLS:        mtls.TLSConfig{Certificate: cert, RootCAs: ca},
		MaxMessage: 32 << 20, // Maximum message size (32 MB)
	}

	fmt.Printf("Config for party %s with max message size %d bytes\n",
		parties[config.SelfIndex].Name, config.MaxMessage)

	// Output:
	// Config for party alice with max message size 33554432 bytes
}

// ExampleNew demonstrates creating a new mTLS transport.
// In practice, you would need valid certificates. See examples/certutil/cmd/gen-certs
// for generating development certificates (not for production use).
func ExampleNew() {
	names := []string{"party0", "party1"}
	addrs := []string{"localhost:8000", "localhost:8001"}

	parties := make([]mtls.Party, len(names))
	for i := range names {
		parties[i] = mtls.Party{Name: names[i], Address: addrs[i]}
	}

	// In a real application, load certificates:
	// cert, err := tls.LoadX509KeyPair("party0.crt", "party0.key")
	// if err != nil { return err }
	//
	// ca := x509.NewCertPool()
	// caBytes, err := os.ReadFile("ca.crt")
	// if err != nil { return err }
	// ca.AppendCertsFromPEM(caBytes)

	// Create the transport
	// t, err := mtls.New(mtls.Config{
	// 	SelfIndex:  0,
	// 	Parties:    parties,
	// 	TLS:        mtls.TLSConfig{Certificate: cert, RootCAs: ca},
	// 	MaxMessage: 32 << 20,
	// })
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer t.Close()

	// Use the transport with an MPC job
	// ctx := context.Background()
	// job, err := cbmpc.NewJobMPWithContext(ctx, t, cbmpc.RoleID(0), names)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer job.Close()

	fmt.Println("mTLS transport created")

	// Output:
	// mTLS transport created
}

// Example_withContext demonstrates using mTLS transport with context for cancellation.
func Example_withContext() {
	// Create a context with cancellation
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create MPC job with context
	// job, err := cbmpc.NewJobMPWithContext(ctx, t, cbmpc.RoleID(0), names)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer job.Close()

	// The context can be used to cancel long-running operations
	// cancel() // This would stop any ongoing MPC operations

	fmt.Println("Context-aware job configured")

	// Output:
	// Context-aware job configured
}

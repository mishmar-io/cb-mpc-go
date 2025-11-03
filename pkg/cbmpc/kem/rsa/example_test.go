//go:build cgo && !windows

package rsa_test

import (
	"bytes"
	"fmt"
	"log"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/kem/rsa"
)

// Example_determinism demonstrates that the RSA-OAEP KEM is deterministic.
// Same (public_key, rho) produces identical ciphertext every time.
// This is a required property for deterministic encryption protocols.
func Example_determinism() {
	// Create a KEM with 2048-bit RSA keys
	kem, err := rsa.New(2048)
	if err != nil {
		log.Fatal(err)
	}

	// Generate key pair
	_, ek, err := kem.Generate()
	if err != nil {
		log.Fatal(err)
	}

	// Fixed rho (seed) - in real usage, this comes from protocol-specific derivation
	var rho [32]byte
	copy(rho[:], []byte("deterministic-seed-1234567890123"))

	// Encrypt twice with same (ek, rho)
	ct1, _, err := kem.Encapsulate(ek, rho)
	if err != nil {
		log.Fatal(err)
	}

	ct2, _, err := kem.Encapsulate(ek, rho)
	if err != nil {
		log.Fatal(err)
	}

	// Ciphertexts are IDENTICAL (byte-for-byte)
	if bytes.Equal(ct1, ct2) {
		fmt.Println("Determinism verified: same (ek, rho) produces identical ciphertext")
	} else {
		fmt.Println("FAIL: Ciphertexts differ!")
	}

	// Output:
	// Determinism verified: same (ek, rho) produces identical ciphertext
}

// Example_keySizes demonstrates the different RSA key size options.
func Example_keySizes() {
	// 2048 bits: Minimum for current use
	// Suitable for most applications today
	kem2048, _ := rsa.New(2048)
	_ = kem2048
	fmt.Println("2048-bit: Minimum for current use")

	// 3072 bits: Recommended for long-term security (post-2030)
	// Provides protection against advances in computing power
	kem3072, _ := rsa.New(3072)
	_ = kem3072
	fmt.Println("3072-bit: Recommended for long-term security")

	// 4096 bits: High-security applications
	// Maximum security at the cost of performance
	kem4096, _ := rsa.New(4096)
	_ = kem4096
	fmt.Println("4096-bit: High-security applications")

	// Output:
	// 2048-bit: Minimum for current use
	// 3072-bit: Recommended for long-term security
	// 4096-bit: High-security applications
}

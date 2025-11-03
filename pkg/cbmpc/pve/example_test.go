//go:build cgo && !windows

package pve_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/kem/rsa"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/pve"
)

// Example_pveRoundTrip demonstrates a complete PVE encrypt-verify-decrypt cycle.
// This shows how Publicly Verifiable Encryption works with deterministic KEM.
func Example_pveRoundTrip() {
	if err := runPVERoundTrip(); err != nil {
		log.Fatal(err)
	}
	// Output:
	// Ciphertext verified
	// PVE round-trip successful
}

func runPVERoundTrip() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Create KEM
	kem, err := rsa.New(2048)
	if err != nil {
		return err
	}

	// 2. Generate key pair
	skRef, ek, err := kem.Generate()
	if err != nil {
		return err
	}

	// 3. Create private key handle
	dkHandle, err := kem.NewPrivateKeyHandle(skRef)
	if err != nil {
		return err
	}
	defer func() {
		if err := kem.FreePrivateKeyHandle(dkHandle); err != nil {
			log.Printf("failed to free private key handle: %v", err)
		}
	}()

	// 4. Create PVE instance
	pveInstance, err := pve.New(kem)
	if err != nil {
		return err
	}

	// 5. Encrypt a scalar value
	secretValue := "123456789012345678901234567890"
	x, err := curve.NewScalarFromString(secretValue)
	if err != nil {
		return err
	}
	defer x.Free()

	label := []byte("my-label")
	encryptResult, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
		EK:    ek,
		Label: label,
		Curve: cbmpc.CurveP256,
		X:     x,
	})
	if err != nil {
		return err
	}

	// 6. Extract Q for verification
	Q, err := encryptResult.Ciphertext.Q()
	if err != nil {
		return err
	}
	defer Q.Free()

	// 7. Verify ciphertext (publicly verifiable proof)
	err = pveInstance.Verify(ctx, &pve.VerifyParams{
		EK:         ek,
		Ciphertext: encryptResult.Ciphertext,
		Q:          Q,
		Label:      label,
	})
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}
	fmt.Println("Ciphertext verified")

	// 8. Decrypt
	decryptResult, err := pveInstance.Decrypt(ctx, &pve.DecryptParams{
		DK:         dkHandle,
		EK:         ek,
		Ciphertext: encryptResult.Ciphertext,
		Label:      label,
		Curve:      cbmpc.CurveP256,
	})
	if err != nil {
		return err
	}
	defer decryptResult.X.Free()

	if secretValue == decryptResult.X.String() {
		fmt.Println("PVE round-trip successful")
	} else {
		return fmt.Errorf("decrypted value doesn't match")
	}

	return nil
}

//go:build cgo && !windows

package zk_test

import (
	"crypto/rand"
	"fmt"
	"log"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/zk"
)

// Example demonstrates basic usage of UC_DL proofs.
func Example() {
	if err := runExample(); err != nil {
		log.Fatalf("example failed: %v", err)
	}
	// Output:
	// Generated proof
	// Proof verified successfully!
}

func runExample() error {
	// Generate a random discrete logarithm (exponent) using C++ library
	exponent, err := curve.RandomScalar(curve.P256)
	if err != nil {
		return fmt.Errorf("failed to generate exponent: %w", err)
	}
	defer exponent.Free()

	// Compute point Q = exponent*G using C++ library
	point, err := curve.MulGenerator(curve.P256, exponent)
	if err != nil {
		return fmt.Errorf("failed to compute point: %w", err)
	}
	defer point.Free()

	// Generate session ID for proof security
	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		return fmt.Errorf("failed to generate session ID: %w", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	// Create proof that proves knowledge of exponent such that Q = exponent*G
	// Proof is just []byte - no Close() needed, safe to copy and serialize
	proof, err := zk.ProveDL(&zk.DLProveParams{
		Point:     point,
		Exponent:  exponent,
		SessionID: sessionID,
		Aux:       1,
	})
	if err != nil {
		return fmt.Errorf("failed to generate proof: %w", err)
	}

	fmt.Println("Generated proof")

	// Proof can be used directly - it's already serialized bytes
	// Can pass across goroutines, store in database, send over network, etc.

	// Verify proof
	err = zk.VerifyDL(&zk.DLVerifyParams{
		Proof:     proof,
		Point:     point,
		SessionID: sessionID,
		Aux:       1,
	})
	if err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}

	fmt.Println("Proof verified successfully!")
	return nil
}

// ExampleProveDL demonstrates UC_DL - Universally Composable Discrete Logarithm Proof.
// This proves knowledge of a discrete logarithm w such that Q = w*G without revealing w.
func ExampleProveDL() {
	if err := runProveDL(); err != nil {
		log.Fatal(err)
	}
	// Output:
	// UC_DL proof verified
}

func runProveDL() error {
	// Generate random exponent w
	exponent, err := curve.RandomScalar(curve.P256)
	if err != nil {
		return err
	}
	defer exponent.Free()

	// Compute point Q = w*G
	point, err := curve.MulGenerator(curve.P256, exponent)
	if err != nil {
		return err
	}
	defer point.Free()

	// Generate session ID
	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		return err
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	// Generate proof - returns []byte, no Close() needed
	proof, err := zk.ProveDL(&zk.DLProveParams{
		Point:     point,
		Exponent:  exponent,
		SessionID: sessionID,
		Aux:       1, // Party ID or auxiliary data
	})
	if err != nil {
		return err
	}

	// Verify proof
	err = zk.VerifyDL(&zk.DLVerifyParams{
		Proof:     proof,
		Point:     point,
		SessionID: sessionID,
		Aux:       1,
	})
	if err != nil {
		return err
	}

	fmt.Println("UC_DL proof verified")
	return nil
}

// ExampleProveBatchDL demonstrates UC_Batch_DL - Batch Discrete Logarithm Proof.
// This proves knowledge of multiple discrete logarithms efficiently in a single proof.
func ExampleProveBatchDL() {
	if err := runProveBatchDL(); err != nil {
		log.Fatal(err)
	}
	// Output:
	// Batch DL proof verified for multiple points
}

func runProveBatchDL() error {
	// Generate multiple points and their exponents
	numPoints := 3
	points := make([]*curve.Point, numPoints)
	exponents := make([]*curve.Scalar, numPoints)

	for i := 0; i < numPoints; i++ {
		exp, err := curve.RandomScalar(curve.P256)
		if err != nil {
			return err
		}
		defer exp.Free()
		exponents[i] = exp

		pt, err := curve.MulGenerator(curve.P256, exp)
		if err != nil {
			return err
		}
		defer pt.Free()
		points[i] = pt
	}

	// Generate session ID
	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		return err
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	// Generate batch proof
	proof, err := zk.ProveBatchDL(&zk.BatchDLProveParams{
		Points:    points,
		Exponents: exponents,
		SessionID: sessionID,
		Aux:       1,
	})
	if err != nil {
		return err
	}

	// Verify batch proof
	err = zk.VerifyBatchDL(&zk.BatchDLVerifyParams{
		Proof:     proof,
		Points:    points,
		SessionID: sessionID,
		Aux:       1,
	})
	if err != nil {
		return err
	}

	fmt.Println("Batch DL proof verified for multiple points")
	return nil
}

// ExampleProveElGamalCom demonstrates UC_ElGamal_Com proof.
// This proves knowledge of the opening (x, r) of an ElGamal commitment UV = (r*G, x*Q + r*G).
func ExampleProveElGamalCom() {
	if err := runProveElGamalCom(); err != nil {
		log.Fatal(err)
	}
	// Output:
	// ElGamal commitment proof verified
}

func runProveElGamalCom() error {
	// Generate base point Q
	qScalar, err := curve.RandomScalar(curve.P256)
	if err != nil {
		return err
	}
	defer qScalar.Free()

	qPoint, err := curve.MulGenerator(curve.P256, qScalar)
	if err != nil {
		return err
	}
	defer qPoint.Free()

	// Secret value x and randomness r
	x, err := curve.RandomScalar(curve.P256)
	if err != nil {
		return err
	}
	defer x.Free()

	r, err := curve.RandomScalar(curve.P256)
	if err != nil {
		return err
	}
	defer r.Free()

	// Create ElGamal commitment UV = (r*G, x*Q + r*G)
	commitment, err := curve.MakeElGamalCom(qPoint, x, r)
	if err != nil {
		return err
	}
	defer commitment.Free()

	// Generate session ID
	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		return err
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	// Generate proof of knowledge of x and r
	proof, err := zk.ProveElGamalCom(&zk.ElGamalComProveParams{
		BasePoint:  qPoint,
		Commitment: commitment,
		X:          x,
		R:          r,
		SessionID:  sessionID,
		Aux:        1,
	})
	if err != nil {
		return err
	}

	// Verify the proof
	err = zk.VerifyElGamalCom(&zk.ElGamalComVerifyParams{
		Proof:      proof,
		BasePoint:  qPoint,
		Commitment: commitment,
		SessionID:  sessionID,
		Aux:        1,
	})
	if err != nil {
		return err
	}

	fmt.Println("ElGamal commitment proof verified")
	return nil
}

// ExampleMakeElGamalComWithProof demonstrates the convenience function
// that creates a commitment and proof in one step.
func ExampleMakeElGamalComWithProof() {
	if err := runMakeElGamalComWithProof(); err != nil {
		log.Fatal(err)
	}
	// Output:
	// ElGamal commitment with proof verified
}

func runMakeElGamalComWithProof() error {
	// Generate base point Q
	qScalar, err := curve.RandomScalar(curve.P256)
	if err != nil {
		return err
	}
	defer qScalar.Free()

	qPoint, err := curve.MulGenerator(curve.P256, qScalar)
	if err != nil {
		return err
	}
	defer qPoint.Free()

	// Secret value x and randomness r
	x, err := curve.RandomScalar(curve.P256)
	if err != nil {
		return err
	}
	defer x.Free()

	r, err := curve.RandomScalar(curve.P256)
	if err != nil {
		return err
	}
	defer r.Free()

	// Generate session ID
	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		return err
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	// Create commitment + proof in one call
	result, err := zk.MakeElGamalComWithProof(qPoint, x, r, sessionID, 1)
	if err != nil {
		return err
	}
	defer result.Commitment.Free()

	// Verify as usual
	err = zk.VerifyElGamalCom(&zk.ElGamalComVerifyParams{
		Proof:      result.Proof,
		BasePoint:  qPoint,
		Commitment: result.Commitment,
		SessionID:  sessionID,
		Aux:        1,
	})
	if err != nil {
		return err
	}

	fmt.Println("ElGamal commitment with proof verified")
	return nil
}

// ExampleProveDH demonstrates DH - Diffie-Hellman Proof.
// This proves that B = w*A where the prover knows w.
func ExampleProveDH() {
	if err := runProveDH(); err != nil {
		log.Fatal(err)
	}
	// Output:
	// Diffie-Hellman proof verified
}

func runProveDH() error {
	// Generate random scalar for Q (public key base)
	qScalar, err := curve.RandomScalar(curve.P256)
	if err != nil {
		return err
	}
	defer qScalar.Free()

	// Compute Q = qScalar*G
	Q, err := curve.MulGenerator(curve.P256, qScalar)
	if err != nil {
		return err
	}
	defer Q.Free()

	// Generate secret exponent w
	w, err := curve.RandomScalar(curve.P256)
	if err != nil {
		return err
	}
	defer w.Free()

	// Compute A = w*G
	A, err := curve.MulGenerator(curve.P256, w)
	if err != nil {
		return err
	}
	defer A.Free()

	// Compute B = w*Q (proves knowledge of w)
	B, err := Q.Mul(w)
	if err != nil {
		return err
	}
	defer B.Free()

	// Generate session ID
	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		return err
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	// Generate DH proof
	proof, err := zk.ProveDH(&zk.DHProveParams{
		Q:         Q,
		A:         A,
		B:         B,
		Exponent:  w,
		SessionID: sessionID,
		Aux:       1,
	})
	if err != nil {
		return err
	}

	// Verify DH proof
	err = zk.VerifyDH(&zk.DHVerifyParams{
		Proof:     proof,
		Q:         Q,
		A:         A,
		B:         B,
		SessionID: sessionID,
		Aux:       1,
	})
	if err != nil {
		return err
	}

	fmt.Println("Diffie-Hellman proof verified")
	return nil
}

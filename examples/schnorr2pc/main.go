package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/coinbase/cb-mpc-go/pkg/mpc"
	"github.com/coinbase/cb-mpc-go/pkg/mpctest"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// mpctest.NewMockNetwork is for local demos/tests only.
	sessions := mpctest.NewMockNetwork(2)
	closeSessions := sync.OnceFunc(func() {
		for _, session := range sessions {
			_ = session.Close()
		}
	})
	defer closeSessions()
	fatal := func(args ...any) {
		closeSessions()
		log.Fatal(args...)
	}

	keyBlobs := make([][]byte, 2)
	errCh := make(chan error, 2)
	var wg sync.WaitGroup

	for i := range sessions {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			keyBlob, err := mpc.Schnorr2PDKG(ctx, sessions[idx], mpc.CurveSecp256k1)
			if err != nil {
				errCh <- fmt.Errorf("party %d dkg: %w", idx, err)
				return
			}
			keyBlobs[idx] = keyBlob
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		fatal(err)
	}

	msgHash := sha256.Sum256([]byte("cb-mpc-go schnorr2pc example"))
	sigs := make([][]byte, 2)
	errCh = make(chan error, 2)

	for i := range sessions {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sig, err := mpc.Schnorr2PSign(ctx, sessions[idx], keyBlobs[idx], msgHash[:])
			if err != nil {
				errCh <- fmt.Errorf("party %d sign: %w", idx, err)
				return
			}
			sigs[idx] = sig
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		fatal(err)
	}

	xOnly, err := mpc.Schnorr2PExtractPublicKeyXOnly(keyBlobs[0])
	if err != nil {
		fatal(err)
	}

	fmt.Printf("Schnorr-2PC sign complete\n")
	fmt.Printf("x-only pubkey bytes: %d\n", len(xOnly))
	fmt.Printf("signature sizes: party0=%d party1=%d\n", len(sigs[0]), len(sigs[1]))
}

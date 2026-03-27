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
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	for i := range sessions {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			keyBlob, err := mpc.ECDSA2PDKG(ctx, sessions[idx], mpc.CurveSecp256k1)
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

	hash := sha256.Sum256([]byte("cb-mpc-go ecdsa2pc example"))
	sidOuts := make([][]byte, 2)
	signatures := make([][]byte, 2)
	errCh = make(chan error, 2)

	for i := range sessions {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sidOut, sigDER, err := mpc.ECDSA2PSign(ctx, sessions[idx], keyBlobs[idx], hash[:], nil)
			if err != nil {
				errCh <- fmt.Errorf("party %d sign: %w", idx, err)
				return
			}
			sidOuts[idx] = sidOut
			signatures[idx] = sigDER
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		fatal(err)
	}

	refreshed := make([][]byte, 2)
	errCh = make(chan error, 2)
	for i := range sessions {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			keyBlob, err := mpc.ECDSA2PRefresh(ctx, sessions[idx], keyBlobs[idx])
			if err != nil {
				errCh <- fmt.Errorf("party %d refresh: %w", idx, err)
				return
			}
			refreshed[idx] = keyBlob
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		fatal(err)
	}

	pubKey, err := mpc.ECDSA2PGetPublicKeyCompressed(refreshed[0])
	if err != nil {
		fatal(err)
	}

	fmt.Printf("ECDSA-2PC keygen/sign/refresh complete\n")
	fmt.Printf("public key bytes: %d\n", len(pubKey))
	fmt.Printf("sid sizes: party0=%d party1=%d\n", len(sidOuts[0]), len(sidOuts[1]))
	fmt.Printf("signature sizes: party0=%d party1=%d\n", len(signatures[0]), len(signatures[1]))
}

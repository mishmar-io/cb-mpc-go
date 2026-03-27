package main

import (
	"context"
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
			keyBlob, err := mpc.EdDSA2PDKG(ctx, sessions[idx], mpc.CurveEd25519)
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

	msg := []byte("cb-mpc-go eddsa2pc example")
	sigs := make([][]byte, 2)
	errCh = make(chan error, 2)

	for i := range sessions {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sig, err := mpc.EdDSA2PSign(ctx, sessions[idx], keyBlobs[idx], msg)
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

	pubKey, err := mpc.EdDSA2PGetPublicKeyCompressed(keyBlobs[0])
	if err != nil {
		fatal(err)
	}

	fmt.Printf("EdDSA-2PC sign complete\n")
	fmt.Printf("public key bytes: %d\n", len(pubKey))
	fmt.Printf("signature sizes: party0=%d party1=%d\n", len(sigs[0]), len(sigs[1]))
}

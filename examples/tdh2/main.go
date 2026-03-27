package main

import (
	"bytes"
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
	const parties = 3
	sessions := mpctest.NewMockNetwork(parties)
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
	fatalf := func(format string, args ...any) {
		closeSessions()
		log.Fatalf(format, args...)
	}

	publicKeys := make([][]byte, parties)
	publicShares := make([][][]byte, parties)
	privateShares := make([][]byte, parties)
	errCh := make(chan error, parties)
	var wg sync.WaitGroup

	for i := range sessions {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			publicKey, shares, privateShare, _, err := mpc.TDH2DKGAdditive(ctx, sessions[idx], mpc.CurveP256)
			if err != nil {
				errCh <- fmt.Errorf("party %d dkg: %w", idx, err)
				return
			}
			publicKeys[idx] = publicKey
			publicShares[idx] = shares
			privateShares[idx] = privateShare
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		fatal(err)
	}

	plaintext := []byte("tdh2 example payload")
	label := []byte("tdh2-label")
	ciphertext, err := mpc.TDH2Encrypt(publicKeys[0], plaintext, label)
	if err != nil {
		fatal(err)
	}
	if err := mpc.TDH2Verify(publicKeys[0], ciphertext, label); err != nil {
		fatal(err)
	}

	partials := make([][]byte, parties)
	errCh = make(chan error, parties)
	for i := range sessions {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			partial, err := mpc.TDH2PartialDecrypt(privateShares[idx], ciphertext, label)
			if err != nil {
				errCh <- fmt.Errorf("party %d partial decrypt: %w", idx, err)
				return
			}
			partials[idx] = partial
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		fatal(err)
	}

	recovered, err := mpc.TDH2CombineAdditive(publicKeys[0], publicShares[0], label, partials, ciphertext)
	if err != nil {
		fatal(err)
	}
	if !bytes.Equal(recovered, plaintext) {
		fatalf("recovered plaintext mismatch: got=%q want=%q", recovered, plaintext)
	}

	fmt.Printf("TDH2 DKG/encrypt/decrypt complete\n")
	fmt.Printf("ciphertext bytes: %d\n", len(ciphertext))
	fmt.Printf("recovered: %q\n", recovered)
}

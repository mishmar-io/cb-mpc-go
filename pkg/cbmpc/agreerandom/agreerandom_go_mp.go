package agreerandom

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
)

// GoMultiAgreeRandom is a pure-Go, n-party commit-reveal protocol that produces
// a shared uniformly random bitstring of the requested length.
// All parties commit, then reveal, then verify and XOR.
func GoMultiAgreeRandom(ctx context.Context, j *cbmpc.JobMP, bitlen int) ([]byte, error) {
	if j == nil {
		return nil, errors.New("nil job")
	}
	if bitlen < 8 || bitlen%8 != 0 {
		return nil, cbmpc.ErrInvalidBits
	}
	if j.Transport() == nil {
		return nil, cbmpc.ErrNilTransport
	}

	// Merge contexts: cancel I/O if either is done.
	opCtx, cancel := context.WithCancel(j.Context())
	defer cancel()
	if ctx != nil {
		go func() {
			select {
			case <-ctx.Done():
				cancel()
			case <-opCtx.Done():
			}
		}()
	}

	// List peers (all except self).
	peers := j.Peers()
	rlen := bitlen / 8

	// Local randomness and commitment
	localR := make([]byte, rlen)
	localSalt := make([]byte, 32)
	if _, err := rand.Read(localR); err != nil {
		return nil, err
	}
	if _, err := rand.Read(localSalt); err != nil {
		return nil, err
	}
	const tag = "cbmpc:agreerandom:mp:v1"
	h := sha256.New()
	_, _ = h.Write([]byte(tag))
	_, _ = h.Write(localSalt)
	_, _ = h.Write(localR)
	localCommit := h.Sum(nil)

	// Broadcast commit to all peers.
	commitMsg := make([]byte, 1+len(localCommit))
	commitMsg[0] = 0x01
	copy(commitMsg[1:], localCommit)
	for _, peer := range peers {
		if err := j.Send(opCtx, peer, commitMsg); err != nil {
			return nil, err
		}
	}

	// Receive commits from all peers.
	commitBatch, err := j.ReceiveAll(opCtx, peers)
	if err != nil {
		return nil, err
	}
	peerCommits := make(map[int][]byte, len(peers))
	for _, peer := range peers {
		msg, ok := commitBatch[peer]
		if !ok || len(msg) != 1+sha256.Size || msg[0] != 0x01 {
			return nil, errors.New("agreerandom: invalid commit message")
		}
		c := make([]byte, sha256.Size)
		copy(c, msg[1:])
		peerCommits[peer] = c
	}

	// Broadcast reveal to all peers.
	revealMsg := make([]byte, 1+rlen+len(localSalt))
	revealMsg[0] = 0x02
	copy(revealMsg[1:], localR)
	copy(revealMsg[1+rlen:], localSalt)
	for _, peer := range peers {
		if err := j.Send(opCtx, peer, revealMsg); err != nil {
			return nil, err
		}
	}

	// Receive reveals from all peers and verify.
	revealBatch, err := j.ReceiveAll(opCtx, peers)
	if err != nil {
		return nil, err
	}
	out := make([]byte, rlen)
	copy(out, localR)
	for _, peer := range peers {
		msg, ok := revealBatch[peer]
		if !ok || len(msg) != 1+rlen+32 || msg[0] != 0x02 {
			return nil, errors.New("agreerandom: invalid reveal message")
		}
		peerR := msg[1 : 1+rlen]
		peerSalt := msg[1+rlen:]
		h2 := sha256.New()
		_, _ = h2.Write([]byte(tag))
		_, _ = h2.Write(peerSalt)
		_, _ = h2.Write(peerR)
		if !equalBytes(peerCommits[peer], h2.Sum(nil)) {
			return nil, errors.New("agreerandom: commitment mismatch")
		}
		for i := 0; i < rlen; i++ {
			out[i] ^= peerR[i]
		}
	}
	return out, nil
}

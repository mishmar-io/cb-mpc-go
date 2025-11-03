package agreerandom

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
)

// GoAgreeRandom is a pure-Go, two-party commit-reveal protocol that produces
// a shared uniformly random bitstring of the requested length. It mirrors the
// AgreeRandom interface but does not rely on the native backend.
//
// Protocol (both parties execute symmetrically):
// 1) Sample local random R and salt S; send commitment C = H(tag || S || R).
// 2) Receive peer commitment C'.
// 3) Send reveal message (R, S); receive peer reveal (R', S').
// 4) Verify H(tag || S' || R') == C'; output R XOR R'.
func GoAgreeRandom(ctx context.Context, j *cbmpc.Job2P, bitlen int) ([]byte, error) {
	if j == nil {
		return nil, errors.New("nil job")
	}
	if bitlen < 8 || bitlen%8 != 0 {
		return nil, cbmpc.ErrInvalidBits
	}

	// Merge external ctx with the job's lifetime ctx so either can cancel IO.
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

	// Transport is accessed via job helpers; protocols stay transport-agnostic.
	if j.Transport() == nil {
		return nil, cbmpc.ErrNilTransport
	}

	// Local randomness and commitment.
	rlen := bitlen / 8
	localR := make([]byte, rlen)
	localSalt := make([]byte, 32)
	if _, err := rand.Read(localR); err != nil {
		return nil, err
	}
	if _, err := rand.Read(localSalt); err != nil {
		return nil, err
	}
	// Domain-separated commitment tag.
	const tag = "cbmpc:agreerandom:v1"
	h := sha256.New()
	_, _ = h.Write([]byte(tag))
	_, _ = h.Write(localSalt)
	_, _ = h.Write(localR)
	localCommit := h.Sum(nil)

	// 1) Send commit
	commitMsg := make([]byte, 1+len(localCommit))
	commitMsg[0] = 0x01
	copy(commitMsg[1:], localCommit)
	if err := j.SendToPeer(opCtx, commitMsg); err != nil {
		return nil, err
	}
	// 2) Receive peer commit
	peerCommitMsg, err := j.ReceiveFromPeer(opCtx)
	if err != nil {
		return nil, err
	}
	if len(peerCommitMsg) != 1+sha256.Size || peerCommitMsg[0] != 0x01 {
		return nil, errors.New("agreerandom: invalid commit message")
	}
	peerCommit := make([]byte, sha256.Size)
	copy(peerCommit, peerCommitMsg[1:])

	// 3) Send reveal (R || S)
	revealMsg := make([]byte, 1+rlen+len(localSalt))
	revealMsg[0] = 0x02
	copy(revealMsg[1:], localR)
	copy(revealMsg[1+rlen:], localSalt)
	if err := j.SendToPeer(opCtx, revealMsg); err != nil {
		return nil, err
	}
	// Receive peer reveal
	peerRevealMsg, err := j.ReceiveFromPeer(opCtx)
	if err != nil {
		return nil, err
	}
	if len(peerRevealMsg) != 1+rlen+32 || peerRevealMsg[0] != 0x02 {
		return nil, errors.New("agreerandom: invalid reveal message")
	}
	peerR := make([]byte, rlen)
	copy(peerR, peerRevealMsg[1:1+rlen])
	peerSalt := make([]byte, 32)
	copy(peerSalt, peerRevealMsg[1+rlen:])

	// 4) Verify commitment
	h2 := sha256.New()
	_, _ = h2.Write([]byte(tag))
	_, _ = h2.Write(peerSalt)
	_, _ = h2.Write(peerR)
	if !equalBytes(peerCommit, h2.Sum(nil)) {
		return nil, errors.New("agreerandom: commitment mismatch")
	}

	// XOR to derive shared random bytes.
	out := make([]byte, rlen)
	for i := 0; i < rlen; i++ {
		out[i] = localR[i] ^ peerR[i]
	}
	return out, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

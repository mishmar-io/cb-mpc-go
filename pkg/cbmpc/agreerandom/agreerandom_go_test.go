package agreerandom

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/transport/mocknet"
)

func TestGoAgreeRandom2P(t *testing.T) {
	t.Parallel()
	const bitlen = 256
	net := mocknet.New()
	t0 := net.Ep2P(cbmpc.RoleID(cbmpc.RoleP1), cbmpc.RoleID(cbmpc.RoleP2))
	t1 := net.Ep2P(cbmpc.RoleID(cbmpc.RoleP2), cbmpc.RoleID(cbmpc.RoleP1))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	names := [2]string{"A", "B"}
	j0, err := cbmpc.NewGoJob2PWithContext(ctx, t0, cbmpc.RoleP1, names)
	if err != nil {
		t.Fatalf("NewGoJob2PWithContext: %v", err)
	}
	defer func() { _ = j0.Close() }()
	j1, err := cbmpc.NewGoJob2PWithContext(ctx, t1, cbmpc.RoleP2, names)
	if err != nil {
		t.Fatalf("NewGoJob2PWithContext: %v", err)
	}
	defer func() { _ = j1.Close() }()

	var wg sync.WaitGroup
	wg.Add(2)
	var out0, out1 []byte
	var err0, err1 error
	go func() { defer wg.Done(); out0, err0 = GoAgreeRandom(ctx, j0, bitlen) }()
	go func() { defer wg.Done(); out1, err1 = GoAgreeRandom(ctx, j1, bitlen) }()
	wg.Wait()

	if err0 != nil || err1 != nil {
		t.Fatalf("errors: %v, %v", err0, err1)
	}
	if len(out0) != bitlen/8 || len(out1) != bitlen/8 {
		t.Fatalf("unexpected lengths: %d, %d", len(out0), len(out1))
	}
	if string(out0) != string(out1) {
		t.Fatalf("mismatch: %x != %x", out0, out1)
	}
}

func TestGoMultiAgreeRandom3P(t *testing.T) {
	t.Parallel()
	const (
		n      = 3
		bitlen = 256
	)
	net := mocknet.New()
	names := []string{"A", "B", "C"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	jobs := make([]*cbmpc.JobMP, n)
	outs := make([][]byte, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		// peers are all others
		peers := make([]cbmpc.RoleID, 0, n-1)
		for p := 0; p < n; p++ {
			if p == i {
				continue
			}
			peers = append(peers, cbmpc.RoleID(p))
		}
		ti := net.EpMP(cbmpc.RoleID(i), peers)
		j, err := cbmpc.NewGoJobMPWithContext(ctx, ti, cbmpc.RoleID(i), names)
		if err != nil {
			t.Fatalf("NewGoJobMPWithContext[%d]: %v", i, err)
		}
		jobs[i] = j
		defer func() { _ = j.Close() }()
	}

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() { defer wg.Done(); outs[i], errs[i] = GoMultiAgreeRandom(ctx, jobs[i], bitlen) }()
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("party %d error: %v", i, errs[i])
		}
		if len(outs[i]) != bitlen/8 {
			t.Fatalf("party %d unexpected length: %d", i, len(outs[i]))
		}
		if string(outs[i]) != string(outs[0]) {
			t.Fatalf("party %d mismatch with party 0: %x != %x", i, outs[i], outs[0])
		}
	}
}

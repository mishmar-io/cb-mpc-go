package mpc

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coinbase/cb-mpc-go/pkg/mpctest"
)

func TestMaliciousSession_BehaviorIsolation(t *testing.T) {
	sessions := mpctest.NewMaliciousNetwork(3, 0, mpctest.MaliciousBehavior{
		DropAllSends: true,
	})
	t.Cleanup(func() {
		for _, session := range sessions {
			_ = session.Close()
		}
	})

	if _, ok := sessions[0].(*mpctest.MaliciousSession); !ok {
		t.Fatal("party 0 should be a MaliciousSession")
	}

	if err := sessions[0].Send(context.Background(), 1, []byte("msg")); err != nil {
		t.Fatalf("malicious send returned error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := sessions[1].Receive(ctx, 0); err == nil {
		t.Fatal("party 1 unexpectedly received a dropped message")
	}

	for i := 1; i < len(sessions); i++ {
		if _, ok := sessions[i].(*mpctest.MaliciousSession); ok {
			t.Fatalf("party %d should not be malicious", i)
		}
	}
}

func TestMaliciousSession_ErrorMessages(t *testing.T) {
	testCases := []struct {
		name            string
		behavior        mpctest.MaliciousBehavior
		operation       func(Session) error
		expectedErrText string
	}{
		{
			name:     "fail after N sends",
			behavior: mpctest.MaliciousBehavior{FailAfterNSends: 1},
			operation: func(s Session) error {
				ctx := context.Background()
				_ = s.Send(ctx, 1, []byte("msg1"))
				return s.Send(ctx, 1, []byte("msg2"))
			},
			expectedErrText: "failing after N sends",
		},
		{
			name:     "fail after N receives",
			behavior: mpctest.MaliciousBehavior{FailAfterNReceives: 1},
			operation: func(s Session) error {
				_, err := s.ReceiveAll(context.Background(), []int{1, 1})
				return err
			},
			expectedErrText: "failing after N receives",
		},
		{
			name:     "drop all receives",
			behavior: mpctest.MaliciousBehavior{DropAllReceives: true},
			operation: func(s Session) error {
				_, err := s.Receive(context.Background(), 1)
				return err
			},
			expectedErrText: "dropping all receives",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			network := mpctest.NewMockNetwork(2)
			t.Cleanup(func() {
				for _, session := range network {
					_ = session.Close()
				}
			})

			malicious := mpctest.NewMaliciousSession(network[0], tc.behavior)
			err := tc.operation(malicious)
			if err == nil {
				t.Fatal("expected error but got nil")
			}
			if !strings.Contains(err.Error(), tc.expectedErrText) {
				t.Fatalf("expected error containing %q, got %v", tc.expectedErrText, err)
			}
		})
	}
}

func TestECDSA2PDKG_DropAllSendsHonorsTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	sessions := mpctest.NewMaliciousNetwork(2, 0, mpctest.MaliciousBehavior{
		DropAllSends: true,
	})
	t.Cleanup(func() {
		for _, session := range sessions {
			_ = session.Close()
		}
	})

	errs := runPerSession(t, sessions, func(session Session) error {
		_, err := ECDSA2PDKG(ctx, session, CurveSecp256k1)
		return err
	})
	for i, err := range errs {
		if err == nil {
			t.Fatalf("party %d unexpectedly succeeded under dropped messages", i)
		}
	}
}

func TestECDSA2PDKG_SendGarbageDoesNotFullySucceed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	sessions := mpctest.NewMaliciousNetwork(2, 0, mpctest.MaliciousBehavior{
		SendGarbage: true,
	})
	t.Cleanup(func() {
		for _, session := range sessions {
			_ = session.Close()
		}
	})

	errs := runPerSession(t, sessions, func(session Session) error {
		_, err := ECDSA2PDKG(ctx, session, CurveSecp256k1)
		return err
	})

	successCount := 0
	for _, err := range errs {
		if err == nil {
			successCount++
		}
	}
	if successCount == len(sessions) {
		t.Fatal("expected at least one party to fail under garbage messages")
	}
}

func runPerSession(t *testing.T, sessions []mpctest.Session, fn func(Session) error) []error {
	t.Helper()

	errs := make([]error, len(sessions))
	var wg sync.WaitGroup
	for i, session := range sessions {
		wg.Add(1)
		go func(idx int, s Session) {
			defer wg.Done()
			errs[idx] = fn(s)
		}(i, session)
	}
	wg.Wait()
	return errs
}

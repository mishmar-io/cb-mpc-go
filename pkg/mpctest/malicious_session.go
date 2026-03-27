package mpctest

import (
	"context"
	"errors"
	"sync"
)

// MaliciousSession wraps a normal session with adversarial behavior for tests.
type MaliciousSession struct {
	inner    Session
	behavior MaliciousBehavior
	mutex    sync.Mutex

	// State tracking.
	sendCount    int
	receiveCount int
}

// MaliciousBehavior defines what kind of malicious action to perform.
type MaliciousBehavior struct {
	// DropAllSends drops all outgoing messages (simulates a network partition).
	DropAllSends bool

	// DropAllReceives fails all receive operations.
	DropAllReceives bool

	// CorruptMessages modifies message contents before sending.
	CorruptMessages bool

	// SendWrongSize sends messages with incorrect size.
	SendWrongSize bool

	// FailAfterNSends fails after N send operations.
	FailAfterNSends int

	// FailAfterNReceives fails after N receive operations.
	FailAfterNReceives int

	// SendEmptyMessages sends empty messages instead of real data.
	SendEmptyMessages bool

	// SendGarbage sends all-0xFF garbage instead of protocol messages.
	SendGarbage bool

	// ReplayFirstMessage replays the first sent message repeatedly.
	ReplayFirstMessage bool
	firstMessage       []byte

	// FlipRandomBits flips a bit in the middle of the message.
	FlipRandomBits bool
}

// NewMaliciousSession wraps a session with malicious behavior.
func NewMaliciousSession(inner Session, behavior MaliciousBehavior) *MaliciousSession {
	return &MaliciousSession{
		inner:    inner,
		behavior: behavior,
	}
}

// Send implements Session.Send with malicious behavior.
func (m *MaliciousSession) Send(ctx context.Context, toParty int, msg []byte) error {
	if m.inner == nil {
		return errors.New("malicious: inner session is nil")
	}

	m.mutex.Lock()
	m.sendCount++
	count := m.sendCount
	behavior := m.behavior
	if behavior.ReplayFirstMessage {
		if m.behavior.firstMessage == nil {
			m.behavior.firstMessage = append([]byte(nil), msg...)
		}
		behavior.firstMessage = m.behavior.firstMessage
	}
	m.mutex.Unlock()

	// Check if we should fail after N sends.
	if behavior.FailAfterNSends > 0 && count > behavior.FailAfterNSends {
		return errors.New("malicious: failing after N sends")
	}

	// Drop all sends.
	if behavior.DropAllSends {
		// Pretend success but don't actually send.
		return nil
	}

	// Send empty messages.
	if behavior.SendEmptyMessages {
		return m.inner.Send(ctx, toParty, []byte{})
	}

	// Send garbage.
	if behavior.SendGarbage {
		garbage := make([]byte, len(msg))
		for i := range garbage {
			garbage[i] = 0xFF
		}
		return m.inner.Send(ctx, toParty, garbage)
	}

	// Replay first message.
	if behavior.ReplayFirstMessage {
		return m.inner.Send(ctx, toParty, behavior.firstMessage)
	}

	// Corrupt messages.
	if behavior.CorruptMessages {
		corrupted := make([]byte, len(msg))
		copy(corrupted, msg)
		if len(corrupted) > 0 {
			corrupted[0] ^= 0xFF
		}
		return m.inner.Send(ctx, toParty, corrupted)
	}

	// Send wrong size.
	if behavior.SendWrongSize && len(msg) > 0 {
		return m.inner.Send(ctx, toParty, msg[:len(msg)/2])
	}

	// Flip random bits.
	if behavior.FlipRandomBits {
		corrupted := make([]byte, len(msg))
		copy(corrupted, msg)
		if len(corrupted) > 4 {
			corrupted[len(corrupted)/2] ^= 0x01
		}
		return m.inner.Send(ctx, toParty, corrupted)
	}

	// Normal send.
	return m.inner.Send(ctx, toParty, msg)
}

// Receive implements Session.Receive with malicious behavior.
func (m *MaliciousSession) Receive(ctx context.Context, fromParty int) ([]byte, error) {
	if m.inner == nil {
		return nil, errors.New("malicious: inner session is nil")
	}

	m.mutex.Lock()
	m.receiveCount++
	count := m.receiveCount
	behavior := m.behavior
	m.mutex.Unlock()

	// Check if we should fail after N receives.
	if behavior.FailAfterNReceives > 0 && count > behavior.FailAfterNReceives {
		return nil, errors.New("malicious: failing after N receives")
	}

	// Drop all receives.
	if behavior.DropAllReceives {
		return nil, errors.New("malicious: dropping all receives")
	}

	// Normal receive.
	return m.inner.Receive(ctx, fromParty)
}

// ReceiveAll implements Session.ReceiveAll with malicious behavior.
func (m *MaliciousSession) ReceiveAll(ctx context.Context, fromParties []int) ([][]byte, error) {
	if m.inner == nil {
		return nil, errors.New("malicious: inner session is nil")
	}

	m.mutex.Lock()
	m.receiveCount += len(fromParties)
	count := m.receiveCount
	behavior := m.behavior
	m.mutex.Unlock()

	// Check if we should fail after N receives.
	if behavior.FailAfterNReceives > 0 && count > behavior.FailAfterNReceives {
		return nil, errors.New("malicious: failing after N receives")
	}

	// Drop all receives.
	if behavior.DropAllReceives {
		return nil, errors.New("malicious: dropping all receives")
	}

	// Normal receive.
	return m.inner.ReceiveAll(ctx, fromParties)
}

// MyIndex implements Session.MyIndex.
func (m *MaliciousSession) MyIndex() int {
	return m.inner.MyIndex()
}

// PartyCount implements Session.PartyCount.
func (m *MaliciousSession) PartyCount() int {
	return m.inner.PartyCount()
}

// Close implements Session.Close.
func (m *MaliciousSession) Close() error {
	return m.inner.Close()
}

// NewMaliciousNetwork creates a mock network where one party is malicious.
func NewMaliciousNetwork(nParties int, maliciousParty int, behavior MaliciousBehavior) []Session {
	mockSessions := NewMockNetwork(nParties)

	sessions := make([]Session, nParties)
	for i := 0; i < nParties; i++ {
		if i == maliciousParty {
			sessions[i] = NewMaliciousSession(mockSessions[i], behavior)
		} else {
			sessions[i] = mockSessions[i]
		}
	}

	return sessions
}

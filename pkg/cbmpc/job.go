//go:build cgo && !windows

package cbmpc

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/jobptr"
)

var (
	// ErrInvalidBits is returned when a requested bit length is invalid.
	ErrInvalidBits = errors.New("bitlen must be >= 8 and a multiple of 8")
	// ErrBadPeers indicates a malformed topology or self role for a job.
	ErrBadPeers = errors.New("invalid peers/self configuration")
	// ErrNilTransport signals that a required Transport was nil.
	ErrNilTransport = errors.New("transport must not be nil")
	// ErrJobClosed indicates that the job has already been closed.
	ErrJobClosed = errors.New("job has been closed")
)

// Job2P is a two-party MPC job handle tied to a native session.
type Job2P struct {
	cptr      unsafe.Pointer
	hptr      uintptr
	cancel    context.CancelFunc
	closeOnce sync.Once
}

// JobMP is an n-party MPC job handle tied to a native session.
type JobMP struct {
	cptr      unsafe.Pointer
	hptr      uintptr
	cancel    context.CancelFunc
	closeOnce sync.Once
}

// transportAdapter bridges the public RoleID-based Transport interface with
// the uint32 identifiers required by the cgo bindings layer. The adapter keeps
// the exported API idiomatic while avoiding a dependency cycle between pkg and
// internal/bindings.
type transportAdapter struct {
	transport Transport
	ctx       context.Context
}

func (a transportAdapter) Send(_ context.Context, to uint32, msg []byte) error {
	return a.transport.Send(a.ctx, RoleID(to), msg)
}

func (a transportAdapter) Receive(_ context.Context, from uint32) ([]byte, error) {
	return a.transport.Receive(a.ctx, RoleID(from))
}

func (a transportAdapter) ReceiveAll(_ context.Context, from []uint32) (map[uint32][]byte, error) {
	roles := make([]RoleID, len(from))
	for i, r := range from {
		roles[i] = RoleID(r)
	}
	batch, err := a.transport.ReceiveAll(a.ctx, roles)
	if err != nil {
		return nil, err
	}
	out := make(map[uint32][]byte, len(batch))
	for role, data := range batch {
		out[uint32(role)] = data
	}
	return out, nil
}

// NewJob2P constructs a 2-party job using the provided transport, role, and
// party names. Names must be stable, unique identifiers for each participant.
// This variant uses a background context; see NewJob2PWithContext to provide
// a cancellable context for transport operations.
func NewJob2P(t Transport, self Role, names [2]string) (*Job2P, error) {
	return NewJob2PWithContext(context.Background(), t, self, names)
}

// NewJob2PWithContext constructs a 2-party job with a parent context. A child
// context derived from ctx is used for all transport operations and will be
// canceled during Close() to promptly unblock pending receives.
func NewJob2PWithContext(ctx context.Context, t Transport, self Role, names [2]string) (*Job2P, error) {
	if t == nil {
		return nil, ErrNilTransport
	}
	if !self.valid() {
		return nil, fmt.Errorf("%w: role %d is not valid", ErrBadPeers, self)
	}
	if names[0] == "" || names[1] == "" {
		return nil, fmt.Errorf("%w: party names must not be empty", ErrBadPeers)
	}
	if names[0] == names[1] {
		return nil, fmt.Errorf("%w: party names must be unique (got %q)", ErrBadPeers, names[0])
	}

	jobCtx, cancel := context.WithCancel(ctx)
	adapter := transportAdapter{transport: t, ctx: jobCtx}
	cjob, h, err := backend.NewJob2P(adapter, uint32(self.roleID()), []string{names[0], names[1]})
	if err != nil {
		cancel()
		return nil, RemapError(err)
	}

	job := &Job2P{cptr: cjob, hptr: h, cancel: cancel}
	runtime.SetFinalizer(job, func(job *Job2P) { _ = job.Close() })
	return job, nil
}

// Close releases native resources associated with the 2-party job.
func (job *Job2P) Close() error {
	if job == nil {
		return nil
	}
	job.closeOnce.Do(func() {
		runtime.SetFinalizer(job, nil)
		if job.cancel != nil {
			job.cancel()
		}
		backend.FreeJob2P(job.cptr, job.hptr)
		job.cptr = nil
		job.hptr = 0
		job.cancel = nil
	})
	return nil
}

// NewJobMP constructs an n-party job. Each entry in names identifies a party in
// the session; self is the caller's index within that slice.
// This variant uses a background context; see NewJobMPWithContext to provide
// a cancellable context for transport operations.
func NewJobMP(t Transport, self RoleID, names []string) (*JobMP, error) {
	return NewJobMPWithContext(context.Background(), t, self, names)
}

// NewJobMPWithContext constructs an n-party job with a parent context. A child
// context derived from ctx is used for all transport operations and will be
// canceled during Close() to promptly unblock pending receives.
func NewJobMPWithContext(ctx context.Context, t Transport, self RoleID, names []string) (*JobMP, error) {
	if t == nil {
		return nil, ErrNilTransport
	}
	n := len(names)
	if n < 2 {
		return nil, fmt.Errorf("%w: need at least 2 parties (got %d)", ErrBadPeers, n)
	}
	if int(self) < 0 || int(self) >= n {
		return nil, fmt.Errorf("%w: self role %d out of range [0,%d)", ErrBadPeers, self, n)
	}

	seen := make(map[string]struct{}, n)
	for i, name := range names {
		if name == "" {
			return nil, fmt.Errorf("%w: party name at index %d is empty", ErrBadPeers, i)
		}
		if _, dup := seen[name]; dup {
			return nil, fmt.Errorf("%w: duplicate party name %q", ErrBadPeers, name)
		}
		seen[name] = struct{}{}
	}

	jobCtx, cancel := context.WithCancel(ctx)
	adapter := transportAdapter{transport: t, ctx: jobCtx}
	cjob, h, err := backend.NewJobMP(adapter, uint32(self), names)
	if err != nil {
		cancel()
		return nil, RemapError(err)
	}

	job := &JobMP{cptr: cjob, hptr: h, cancel: cancel}
	runtime.SetFinalizer(job, func(job *JobMP) { _ = job.Close() })
	return job, nil
}

// Close releases native resources associated with the n-party job.
func (job *JobMP) Close() error {
	if job == nil {
		return nil
	}
	job.closeOnce.Do(func() {
		runtime.SetFinalizer(job, nil)
		if job.cancel != nil {
			job.cancel()
		}
		backend.FreeJobMP(job.cptr, job.hptr)
		job.cptr = nil
		job.hptr = 0
		job.cancel = nil
	})
	return nil
}

func init() {
	jobptr.Get = func(v any) (unsafe.Pointer, error) {
		if j, ok := v.(interface {
			ptr() (unsafe.Pointer, error)
		}); ok {
			return j.ptr()
		}
		return nil, fmt.Errorf("invalid job handle type %T", v)
	}
}

// ptr returns the unsafe pointer to the underlying C job.
// For internal use by protocol subpackages via internal/jobptr.
func (job *Job2P) ptr() (unsafe.Pointer, error) {
	if job == nil || job.cptr == nil {
		return nil, ErrJobClosed
	}
	return job.cptr, nil
}

// ptr returns the unsafe pointer to the underlying C job.
// For internal use by protocol subpackages via internal/jobptr.
func (job *JobMP) ptr() (unsafe.Pointer, error) {
	if job == nil || job.cptr == nil {
		return nil, ErrJobClosed
	}
	return job.cptr, nil
}

// SessionID represents an immutable session identifier for MPC protocols.
// Session IDs are cryptographically important protocol state and must not be
// mutated after creation. All methods return defensive copies to ensure immutability.
//
// An empty (zero-value) SessionID indicates a fresh session should be created.
type SessionID struct {
	data []byte
}

// NewSessionID creates a SessionID from bytes, making a defensive copy.
// If data is nil or empty, returns an empty SessionID (fresh session).
func NewSessionID(data []byte) SessionID {
	if len(data) == 0 {
		return SessionID{}
	}
	clone := make([]byte, len(data))
	copy(clone, data)
	return SessionID{data: clone}
}

// Bytes returns a defensive copy of the session ID data.
// External mutations of the returned slice do not affect the SessionID.
// Returns nil for an empty SessionID (fresh session).
func (s SessionID) Bytes() []byte {
	if len(s.data) == 0 {
		return nil
	}
	clone := make([]byte, len(s.data))
	copy(clone, s.data)
	return clone
}

// IsEmpty returns true if the SessionID is empty (nil or zero-length).
// An empty SessionID indicates a fresh session should be created.
func (s SessionID) IsEmpty() bool {
	return len(s.data) == 0
}

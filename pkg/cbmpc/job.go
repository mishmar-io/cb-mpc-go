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

// RoleID identifies this process's role within a multi-party session. Values
// start at 0 and increase monotonically for additional parties.
type RoleID uint32

// Role enumerates the fixed two-party positions supported by a 2-party job.
type Role uint8

const (
	// RoleP1 is the first party in 2-party protocols.
	RoleP1 Role = iota
	// RoleP2 is the second party in 2-party protocols.
	RoleP2
)

// Transport captures the messaging contract for MPC jobs.
//
// Concurrency: Implementations MUST be safe for concurrent use by multiple
// goroutines. Callers may invoke Send and Receive concurrently, and native
// code may invoke callbacks from different OS threads via CGO.
//
// Cancellation: The native code currently drives the protocol and callbacks do
// not carry a caller-provided context. Implementations may treat ctx as a best-
// effort cancellation signal (e.g., per-session context) if available. Future
// versions may add explicit cancellation plumbing per job.
//
// Semantics: Transport must support both Receive and batched ReceiveAll, even
// for two-party jobs. ReceiveAll MUST return exactly one entry per requested
// role; missing entries are an error.
type Transport interface {
	Send(ctx context.Context, to RoleID, msg []byte) error
	Receive(ctx context.Context, from RoleID) ([]byte, error)
	ReceiveAll(ctx context.Context, from []RoleID) (map[RoleID][]byte, error)
}

// Job2P is a two-party MPC job handle. It carries per-session context, party
// names, and the underlying Transport. When constructed with NewJob2P it is
// backed by a native session; when constructed with NewGoJob2P it is Go-only.
type Job2P struct {
	cptr   unsafe.Pointer
	hptr   uintptr
	cancel context.CancelFunc
	// Fields below enable pure-Go protocols to use the same job handle.
	// They are populated at construction and remain immutable thereafter.
	ctx       context.Context
	t         Transport
	role      Role
	names     [2]string
	closeOnce sync.Once
}

// JobMP is an n-party MPC job handle. It carries per-session context, party
// names, and the underlying Transport. When constructed with NewJobMP it is
// backed by a native session; when constructed with NewGoJobMP it is Go-only.
type JobMP struct {
	cptr   unsafe.Pointer
	hptr   uintptr
	cancel context.CancelFunc
	// Fields below enable pure-Go protocols to use the same job handle.
	// They are populated at construction and remain immutable thereafter.
	ctx       context.Context
	t         Transport
	self      RoleID
	names     []string
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
	if self != RoleP1 && self != RoleP2 {
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
	cjob, h, err := backend.NewJob2P(adapter, uint32(self), []string{names[0], names[1]})
	if err != nil {
		cancel()
		return nil, RemapError(err)
	}

	job := &Job2P{
		cptr:   cjob,
		hptr:   h,
		cancel: cancel,
		ctx:    jobCtx,
		t:      t,
		role:   self,
		names:  names,
	}
	runtime.SetFinalizer(job, func(job *Job2P) { _ = job.Close() })
	return job, nil
}

// NewGoJob2P constructs a 2-party job for pure-Go protocols without creating a
// native backend session. It validates inputs and wires transport metadata.
func NewGoJob2P(t Transport, self Role, names [2]string) (*Job2P, error) {
	return NewGoJob2PWithContext(context.Background(), t, self, names)
}

// NewGoJob2PWithContext is like NewGoJob2P but allows a parent context.
func NewGoJob2PWithContext(ctx context.Context, t Transport, self Role, names [2]string) (*Job2P, error) {
	if t == nil {
		return nil, ErrNilTransport
	}
	if self != RoleP1 && self != RoleP2 {
		return nil, fmt.Errorf("%w: role %d is not valid", ErrBadPeers, self)
	}
	if names[0] == "" || names[1] == "" {
		return nil, fmt.Errorf("%w: party names must not be empty", ErrBadPeers)
	}
	if names[0] == names[1] {
		return nil, fmt.Errorf("%w: party names must be unique (got %q)", ErrBadPeers, names[0])
	}
	jobCtx, cancel := context.WithCancel(ctx)
	job := &Job2P{
		cptr:   nil,
		hptr:   0,
		cancel: cancel,
		ctx:    jobCtx,
		t:      t,
		role:   self,
		names:  names,
	}
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
		job.t = nil
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

	job := &JobMP{
		cptr:   cjob,
		hptr:   h,
		cancel: cancel,
		ctx:    jobCtx,
		t:      t,
		self:   self,
		names:  append([]string(nil), names...),
	}
	runtime.SetFinalizer(job, func(job *JobMP) { _ = job.Close() })
	return job, nil
}

// NewGoJobMP constructs an n-party job for pure-Go protocols without creating a
// native backend session. It validates inputs and wires transport metadata.
func NewGoJobMP(t Transport, self RoleID, names []string) (*JobMP, error) {
	return NewGoJobMPWithContext(context.Background(), t, self, names)
}

// NewGoJobMPWithContext is like NewGoJobMP but allows a parent context.
func NewGoJobMPWithContext(ctx context.Context, t Transport, self RoleID, names []string) (*JobMP, error) {
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
	job := &JobMP{
		cptr:   nil,
		hptr:   0,
		cancel: cancel,
		ctx:    jobCtx,
		t:      t,
		self:   self,
		names:  append([]string(nil), names...),
	}
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
		job.t = nil
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

// Context returns the per-job context used for transport operations.
// It is canceled when Close is called, unblocking pending transport calls.
func (job *Job2P) Context() context.Context { return job.ctx }

// Transport exposes the underlying transport used by this job.
// It is intended for pure-Go protocols that orchestrate messaging directly.
func (job *Job2P) Transport() Transport { return job.t }

// Role returns the caller's fixed role in a 2-party session.
func (job *Job2P) Role() Role { return job.role }

// Names returns the immutable party names for a 2-party session.
func (job *Job2P) Names() [2]string { return job.names }

// Context returns the per-job context used for transport operations.
// It is canceled when Close is called, unblocking pending transport calls.
func (job *JobMP) Context() context.Context { return job.ctx }

// Transport exposes the underlying transport used by this job.
// It is intended for pure-Go protocols that orchestrate messaging directly.
func (job *JobMP) Transport() Transport { return job.t }

// Self returns the caller's role identifier in an n-party session.
func (job *JobMP) Self() RoleID { return job.self }

// Names returns a defensive copy of the immutable party names for the session.
func (job *JobMP) Names() []string { return append([]string(nil), job.names...) }

// ---- Job-level helpers for pure-Go protocols (transport-agnostic API) ----

// PeerIndex returns the integer index of the other party in a 2-party session.
// Panics if the role is invalid; construction prevents this in practice.
func (job *Job2P) PeerIndex() int {
	switch job.role {
	case RoleP1:
		return 1
	case RoleP2:
		return 0
	default:
		// Should never happen due to validation in constructors
		panic("cbmpc: invalid 2P role")
	}
}

// roleIDFromInt safely converts an int index to a RoleID, ensuring it fits
// within the 32-bit range used by RoleID.
func roleIDFromInt(idx int) (RoleID, error) {
	const maxUint32 = 1<<32 - 1
	if idx < 0 || idx > maxUint32 {
		return 0, fmt.Errorf("cbmpc: index %d out of range for RoleID", idx)
	}
	return RoleID(uint32(idx)), nil
}

// SendToPeer sends a message to the other party in a 2-party session.
func (job *Job2P) SendToPeer(ctx context.Context, msg []byte) error {
	if job == nil || job.t == nil {
		return ErrNilTransport
	}
	peer := job.PeerIndex()
	rid, err := roleIDFromInt(peer)
	if err != nil {
		return err
	}
	return job.t.Send(ctx, rid, msg)
}

// ReceiveFromPeer receives a message from the other party in a 2-party session.
func (job *Job2P) ReceiveFromPeer(ctx context.Context) ([]byte, error) {
	if job == nil || job.t == nil {
		return nil, ErrNilTransport
	}
	peer := job.PeerIndex()
	rid, err := roleIDFromInt(peer)
	if err != nil {
		return nil, err
	}
	return job.t.Receive(ctx, rid)
}

// Peers returns the indices of all other parties in an n-party session.
func (job *JobMP) Peers() []int {
	if job == nil {
		return nil
	}
	out := make([]int, 0, len(job.names)-1)
	for i := range job.names {
		if int(job.self) == i {
			continue
		}
		out = append(out, i)
	}
	return out
}

// Send sends a message to the specified party index in an n-party session.
func (job *JobMP) Send(ctx context.Context, to int, msg []byte) error {
	if job == nil || job.t == nil {
		return ErrNilTransport
	}
	if to < 0 || to >= len(job.names) {
		return fmt.Errorf("%w: destination %d out of range", ErrBadPeers, to)
	}
	if to == int(job.self) {
		return fmt.Errorf("%w: send to self", ErrBadPeers)
	}
	rid, err := roleIDFromInt(to)
	if err != nil {
		return err
	}
	return job.t.Send(ctx, rid, msg)
}

// Receive receives a message from the specified party index in an n-party session.
func (job *JobMP) Receive(ctx context.Context, from int) ([]byte, error) {
	if job == nil || job.t == nil {
		return nil, ErrNilTransport
	}
	if from < 0 || from >= len(job.names) {
		return nil, fmt.Errorf("%w: source %d out of range", ErrBadPeers, from)
	}
	if from == int(job.self) {
		return nil, fmt.Errorf("%w: receive from self", ErrBadPeers)
	}
	rid, err := roleIDFromInt(from)
	if err != nil {
		return nil, err
	}
	return job.t.Receive(ctx, rid)
}

// ReceiveAll receives a message from each of the specified party indices.
func (job *JobMP) ReceiveAll(ctx context.Context, from []int) (map[int][]byte, error) {
	if job == nil || job.t == nil {
		return nil, ErrNilTransport
	}
	if len(from) == 0 {
		return map[int][]byte{}, nil
	}
	roles := make([]RoleID, len(from))
	seen := make(map[int]struct{}, len(from))
	for i, idx := range from {
		if idx < 0 || idx >= len(job.names) {
			return nil, fmt.Errorf("%w: source %d out of range", ErrBadPeers, idx)
		}
		if idx == int(job.self) {
			return nil, fmt.Errorf("%w: receive from self", ErrBadPeers)
		}
		if _, dup := seen[idx]; dup {
			return nil, fmt.Errorf("%w: duplicate source %d", ErrBadPeers, idx)
		}
		seen[idx] = struct{}{}
		rid, err := roleIDFromInt(idx)
		if err != nil {
			return nil, err
		}
		roles[i] = rid
	}
	batch, err := job.t.ReceiveAll(ctx, roles)
	if err != nil {
		return nil, err
	}
	out := make(map[int][]byte, len(batch))
	for role, data := range batch {
		out[int(role)] = data
	}
	return out, nil
}

package mtls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
)

// Transport implements cbmpc.Transport using long-lived mTLS connections between parties.
type Transport struct {
	self  cbmpc.RoleID
	names []string

	ctx    context.Context
	cancel context.CancelFunc

	mu    sync.RWMutex
	peers map[cbmpc.RoleID]*peerConn

	listener  net.Listener
	closeOnce sync.Once

	cfg Config
}

type peerConn struct {
	id   cbmpc.RoleID
	conn net.Conn

	send chan []byte
	recv chan []byte

	errOnce       sync.Once
	err           error
	closeRecvOnce sync.Once

	cfg Config
}

// New establishes mTLS connections with every other party and returns a ready-to-use transport.
func New(cfg Config) (*Transport, error) {
	if cfg.TLS.RootCAs == nil {
		return nil, errors.New("mtls: root CA pool required")
	}
	// Ensure a non-empty certificate with a private key is provided
	if len(cfg.TLS.Certificate.Certificate) == 0 || cfg.TLS.Certificate.PrivateKey == nil {
		return nil, errors.New("mtls: certificate (with private key) required")
	}
	if cfg.SelfIndex < 0 || cfg.SelfIndex >= len(cfg.Parties) {
		return nil, fmt.Errorf("mtls: invalid self index %d", cfg.SelfIndex)
	}
	if len(cfg.Parties) < 2 {
		return nil, errors.New("mtls: at least two parties required")
	}
	if len(cfg.Parties) > math.MaxUint32 {
		return nil, fmt.Errorf("mtls: too many parties (%d) for 32-bit role IDs", len(cfg.Parties))
	}
	cfg.defaults()

	// Validate parties: non-empty unique names and unique addresses
	nameSeen := make(map[string]struct{}, len(cfg.Parties))
	addrSeen := make(map[string]struct{}, len(cfg.Parties))
	for i, p := range cfg.Parties {
		if p.Name == "" {
			return nil, fmt.Errorf("mtls: party %d has empty Name", i)
		}
		if p.Address == "" {
			return nil, fmt.Errorf("mtls: party %d has empty Address", i)
		}
		if _, ok := nameSeen[p.Name]; ok {
			return nil, fmt.Errorf("mtls: duplicate party Name %q", p.Name)
		}
		nameSeen[p.Name] = struct{}{}
		if _, ok := addrSeen[p.Address]; ok {
			return nil, fmt.Errorf("mtls: duplicate party Address %q", p.Address)
		}
		addrSeen[p.Address] = struct{}{}
	}

	names := make([]string, len(cfg.Parties))
	addrs := make([]string, len(cfg.Parties))
	for i, p := range cfg.Parties {
		names[i] = p.Name
		addrs[i] = p.Address
	}

	selfRole, err := roleIDFromIndex(cfg.SelfIndex)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	t := &Transport{
		self:   selfRole,
		names:  names,
		ctx:    ctx,
		cancel: cancel,
		peers:  make(map[cbmpc.RoleID]*peerConn),
		cfg:    cfg,
	}

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{cfg.TLS.Certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    cfg.TLS.RootCAs,
		MinVersion:   tls.VersionTLS13,
		CipherSuites: cfg.TLS.CipherSuites,
	}
	// Allow user to configure a higher TLS version if desired
	if cfg.TLS.MinVersion > tls.VersionTLS13 {
		serverTLS.MinVersion = cfg.TLS.MinVersion
	}

	ln, err := tls.Listen("tcp", addrs[cfg.SelfIndex], serverTLS)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("mtls: listen: %w", err)
	}
	t.listener = ln

	expectedPeers := len(cfg.Parties) - 1
	var ready sync.WaitGroup
	ready.Add(expectedPeers)
	errCh := make(chan error, expectedPeers)

	register := func(id cbmpc.RoleID, conn *tls.Conn) error {
		t.mu.Lock()
		if _, exists := t.peers[id]; exists {
			t.mu.Unlock()
			return fmt.Errorf("mtls: duplicate connection from peer %d", id)
		}
		pc := newPeerConn(t.ctx, id, conn, cfg)
		t.peers[id] = pc
		t.mu.Unlock()
		ready.Done()
		return nil
	}

	// Accept loop
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-t.ctx.Done():
					return
				default:
					errCh <- fmt.Errorf("mtls: accept: %w", err)
					return
				}
			}
			tlsConn, ok := conn.(*tls.Conn)
			if !ok {
				_ = conn.Close()
				errCh <- errors.New("mtls: non-TLS connection accepted")
				return
			}
			// Handshake with deadline
			if cfg.Timeouts.Handshake > 0 {
				_ = tlsConn.SetDeadline(time.Now().Add(cfg.Timeouts.Handshake))
			}
			if err := tlsConn.Handshake(); err != nil {
				_ = closeWithContextErr(tlsConn, fmt.Errorf("mtls: handshake: %w", err))
				errCh <- err
				return
			}
			if cfg.Timeouts.Handshake > 0 {
				_ = tlsConn.SetDeadline(time.Time{})
			}
			state := tlsConn.ConnectionState()
			if len(state.PeerCertificates) == 0 {
				errCh <- closeWithContextErr(tlsConn, errors.New("mtls: missing peer certificate"))
				return
			}
			leaf := state.PeerCertificates[0]
			// Derive peer index from certificate SAN names (no framing needed)
			var (
				peerIdx      = -1
				matchedCount = 0
			)
			for i, p := range cfg.Parties {
				if i == cfg.SelfIndex {
					continue
				}
				if certHasSANName(leaf, p.Name) {
					peerIdx = i
					matchedCount++
				}
			}
			if matchedCount == 0 || peerIdx < 0 {
				errCh <- closeWithContextErr(tlsConn, fmt.Errorf("mtls: unrecognized peer certificate (no SAN name matches configured parties)"))
				return
			}
			if matchedCount > 1 {
				errCh <- closeWithContextErr(tlsConn, fmt.Errorf("mtls: ambiguous peer certificate (matches multiple configured parties)"))
				return
			}
			expectedName := names[peerIdx]
			if err := verifyPeerIdentity(leaf, expectedName, cfg.TLS.SPKIPin, cfg.TLS.VerifyPeer); err != nil {
				errCh <- closeWithContextErr(tlsConn, err)
				return
			}
			roleID, err := roleIDFromIndex(peerIdx)
			if err != nil {
				errCh <- closeWithContextErr(tlsConn, err)
				return
			}
			if err := register(roleID, tlsConn); err != nil {
				errCh <- closeWithContextErr(tlsConn, err)
				return
			}
			// accepted
		}
	}()

	clientTLSBase := &tls.Config{
		Certificates: []tls.Certificate{cfg.TLS.Certificate},
		RootCAs:      cfg.TLS.RootCAs,
		MinVersion:   tls.VersionTLS13,
		CipherSuites: cfg.TLS.CipherSuites,
	}
	// Allow user to configure a higher TLS version if desired
	if cfg.TLS.MinVersion > tls.VersionTLS13 {
		clientTLSBase.MinVersion = cfg.TLS.MinVersion
	}

	// Dial peers with higher index to avoid duplicate dials
	for peer := range names {
		if peer == cfg.SelfIndex {
			continue
		}
		if peer < cfg.SelfIndex {
			continue
		}
		peerIdx := peer
		go func() {
			addr := addrs[peerIdx]
			tlsCfg := clientTLSBase.Clone()
			serverName := names[peerIdx]
			if cfg.TLS.ServerNamePolicy != nil {
				serverName = cfg.TLS.ServerNamePolicy(cfg.Parties[peerIdx])
			}
			tlsCfg.ServerName = serverName

			d := &net.Dialer{Timeout: cfg.Timeouts.Connect}
			backoff := cfg.Backoff.Min
			for {
				select {
				case <-t.ctx.Done():
					return
				default:
				}
				rawConn, err := d.DialContext(t.ctx, "tcp", addr)
				if err != nil {
					backoff = nextBackoff(backoff, cfg)
					time.Sleep(backoff)
					continue
				}
				conn := tls.Client(rawConn, tlsCfg)
				if cfg.Timeouts.Handshake > 0 {
					_ = conn.SetDeadline(time.Now().Add(cfg.Timeouts.Handshake))
				}
				if err := conn.Handshake(); err != nil {
					_ = closeWithContextErr(conn, fmt.Errorf("mtls: client handshake: %v", err))
					backoff = nextBackoff(backoff, cfg)
					time.Sleep(backoff)
					continue
				}
				if cfg.Timeouts.Handshake > 0 {
					_ = conn.SetDeadline(time.Time{})
				}
				roleID, err := roleIDFromIndex(peerIdx)
				if err != nil {
					errCh <- closeWithContextErr(conn, err)
					return
				}
				if err := register(roleID, conn); err != nil {
					errCh <- closeWithContextErr(conn, err)
					return
				}
				// connected
				return
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		ready.Wait()
		close(done)
	}()

	select {
	case <-done:
		return t, nil
	case err := <-errCh:
		cancel()
		return nil, err
	case <-time.After(cfg.Timeouts.Handshake):
		cancel()
		return nil, errors.New("mtls: timeout waiting for peer connections")
	}
}

func nextBackoff(current time.Duration, cfg Config) time.Duration {
	// simple exponential backoff with cap and jitter
	if current <= 0 {
		current = cfg.Backoff.Min
	}
	next := time.Duration(float64(current) * cfg.Backoff.Factor)
	if next > cfg.Backoff.Max {
		next = cfg.Backoff.Max
	}
	if cfg.Backoff.Jitter > 0 {
		// naive jitter: +/- Jitter * next using time.Now().UnixNano()
		n := time.Now().UnixNano()
		sign := int64(1)
		if n&1 == 1 {
			sign = -1
		}
		delta := time.Duration(cfg.Backoff.Jitter * float64(next))
		next += time.Duration(sign) * (delta / 2)
		if next < cfg.Backoff.Min {
			next = cfg.Backoff.Min
		}
	}
	return next
}

// Send delivers msg to the specified peer or returns an error if the
// transport is closed, the context is done, or the peer is unknown.
func (t *Transport) Send(ctx context.Context, to cbmpc.RoleID, msg []byte) error {
	if to == t.self {
		return errors.New("mtls: send to self")
	}
	pc, err := t.getPeer(to)
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.ctx.Done():
		return errors.New("mtls: transport closed")
	case pc.send <- append([]byte(nil), msg...):
		return nil
	}
}

// Receive blocks until a message is received from the specified peer,
// or returns an error if the transport is closed or the context is done.
func (t *Transport) Receive(ctx context.Context, from cbmpc.RoleID) ([]byte, error) {
	if from == t.self {
		return nil, errors.New("mtls: receive from self")
	}
	pc, err := t.getPeer(from)
	if err != nil {
		return nil, err
	}
	return pc.recvOne(ctx, t.ctx)
}

// ReceiveAll receives one message from each peer in from and returns them
// as a map keyed by role. It fails if any peer is unknown, duplicated, or
// if the transport is closed or context is done.
func (t *Transport) ReceiveAll(ctx context.Context, from []cbmpc.RoleID) (map[cbmpc.RoleID][]byte, error) {
	uniq := make(map[cbmpc.RoleID]struct{}, len(from))
	for _, role := range from {
		if role == t.self {
			return nil, errors.New("mtls: receive_all includes self")
		}
		if _, err := t.getPeer(role); err != nil {
			return nil, err
		}
		if _, exists := uniq[role]; exists {
			return nil, errors.New("mtls: duplicate role in receive_all")
		}
		uniq[role] = struct{}{}
	}

	// Receive from all peers concurrently to avoid head-of-line blocking
	out := make(map[cbmpc.RoleID][]byte, len(from))
	var mu sync.Mutex

	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 1)
	var wg sync.WaitGroup

	for _, role := range from {
		pc, _ := t.getPeer(role)
		wg.Add(1)
		go func(r cbmpc.RoleID, pc *peerConn) {
			defer wg.Done()
			msg, err := pc.recvOne(childCtx, t.ctx)
			if err != nil {
				select {
				case errCh <- fmt.Errorf("mtls: receive from %d: %w", r, err):
					cancel()
				default:
				}
				return
			}
			mu.Lock()
			out[r] = msg
			mu.Unlock()
		}(role, pc)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return out, nil
	case err := <-errCh:
		<-done
		return nil, err
	case <-childCtx.Done():
		<-done
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("mtls: receive_all cancelled")
	case <-t.ctx.Done():
		cancel()
		<-done
		return nil, errors.New("mtls: transport closed")
	}
}

// Close terminates the transport and underlying connections.
func (t *Transport) Close() error {
	t.closeOnce.Do(func() {
		t.cancel()
		if t.listener != nil {
			_ = t.listener.Close()
		}
		t.mu.Lock()
		for _, pc := range t.peers {
			pc.close()
		}
		t.mu.Unlock()
		// transport closed
	})
	return nil
}

func (t *Transport) getPeer(id cbmpc.RoleID) (*peerConn, error) {
	t.mu.RLock()
	pc, ok := t.peers[id]
	t.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("mtls: unknown peer %d", id)
	}
	return pc, nil
}

func newPeerConn(ctx context.Context, id cbmpc.RoleID, conn net.Conn, cfg Config) *peerConn {
	pc := &peerConn{
		id:   id,
		conn: conn,
		send: make(chan []byte, cfg.Buffers.Send),
		recv: make(chan []byte, cfg.Buffers.Recv),
		cfg:  cfg,
	}
	go pc.writer(ctx)
	go pc.reader(ctx)
	return pc
}

func (pc *peerConn) writer(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			pc.setErr(ctx.Err())
			return
		case msg, ok := <-pc.send:
			if !ok {
				return
			}
			if err := writeFrame(pc.conn, pc.cfg.Timeouts.Write, msg, pc.cfg.MaxMessage); err != nil {
				pc.setErr(err)
				return
			}
		}
	}
}

func (pc *peerConn) reader(ctx context.Context) {
	for {
		msg, err := readFrame(pc.conn, pc.cfg.Timeouts.Read, pc.cfg.MaxMessage)
		if err != nil {
			pc.setErr(err)
			pc.closeRecv()
			return
		}
		select {
		case pc.recv <- msg:
		case <-ctx.Done():
			pc.setErr(ctx.Err())
			pc.closeRecv()
			return
		}
	}
}

func (pc *peerConn) recvOne(ctx, transportCtx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-transportCtx.Done():
		return nil, errors.New("mtls: transport closed")
	case msg, ok := <-pc.recv:
		if !ok {
			return nil, pc.errOr(io.EOF)
		}
		return msg, nil
	}
}

func (pc *peerConn) close() {
	pc.setErr(io.EOF)
	pc.closeRecv()
}

func (pc *peerConn) setErr(err error) {
	pc.errOnce.Do(func() {
		if err == nil {
			err = io.EOF
		}
		pc.err = err
		_ = pc.conn.Close()
		close(pc.send)
	})
}

func (pc *peerConn) closeRecv() {
	pc.closeRecvOnce.Do(func() {
		close(pc.recv)
	})
}

func (pc *peerConn) errOr(fallback error) error {
	if pc.err != nil {
		return pc.err
	}
	return fallback
}

func roleIDFromIndex(idx int) (cbmpc.RoleID, error) {
	if idx < 0 {
		return 0, fmt.Errorf("mtls: negative role index %d", idx)
	}
	if idx > math.MaxUint32 {
		return 0, fmt.Errorf("mtls: role index %d exceeds 32-bit capacity", idx)
	}
	return cbmpc.RoleID(idx), nil
}

func closeWithContextErr(c io.Closer, base error) error {
	if base == nil {
		return c.Close()
	}
	if closeErr := c.Close(); closeErr != nil {
		return fmt.Errorf("%w; close error: %v", base, closeErr)
	}
	return base
}

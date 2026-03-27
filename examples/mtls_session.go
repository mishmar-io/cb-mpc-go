package examples

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// maxMessageSize is the maximum allowed message size (64 MB).
// This prevents a malicious peer from causing OOM via a large length prefix.
const maxMessageSize = 64 * 1024 * 1024

// MTLSSession is a reference mTLS-backed Session implementation.
// It is intended as an example starting point, not a hardened drop-in
// production transport.
type MTLSSession struct {
	myIndex    int
	partyCount int

	// Network connections
	listener  net.Listener
	clients   []net.Conn
	clientsMu sync.RWMutex
	writeMu   []sync.Mutex // per-connection write lock to prevent interleaved framing

	// Message queues for each party
	messageQueues []chan []byte

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	closed bool
	mu     sync.Mutex
}

// NewMTLSSession creates a new mTLS-based session
func NewMTLSSession(myIndex, partyCount int, serverAddr string, clientAddrs []string, tlsConfig *tls.Config) (*MTLSSession, error) {
	ctx, cancel := context.WithCancel(context.Background())

	session := &MTLSSession{
		myIndex:       myIndex,
		partyCount:    partyCount,
		clients:       make([]net.Conn, partyCount),
		writeMu:       make([]sync.Mutex, partyCount),
		messageQueues: make([]chan []byte, partyCount),
		ctx:           ctx,
		cancel:        cancel,
	}

	// Initialize message queues
	for i := 0; i < partyCount; i++ {
		session.messageQueues[i] = make(chan []byte, 100) // Buffered channel
	}

	// Start server if we're the designated server (usually party 0)
	if myIndex == 0 && serverAddr != "" {
		var err error
		session.listener, err = tls.Listen("tcp", serverAddr, tlsConfig)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to start TLS listener: %v", err)
		}

		go session.acceptConnections()
	}

	// Connect to other parties
	go session.connectToParties(clientAddrs, tlsConfig)

	return session, nil
}

func (s *MTLSSession) acceptConnections() {
	defer s.listener.Close()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			fmt.Printf("Error accepting connection: %v\n", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *MTLSSession) connectToParties(clientAddrs []string, tlsConfig *tls.Config) {
	for i, addr := range clientAddrs {
		if i == s.myIndex || addr == "" {
			continue // Skip self or empty addresses
		}

		go func(partyIndex int, address string) {
			for {
				select {
				case <-s.ctx.Done():
					return
				default:
				}

				conn, err := tls.Dial("tcp", address, tlsConfig)
				if err != nil {
					time.Sleep(1 * time.Second) // Retry after delay
					continue
				}
				peerIndex, err := s.peerPartyIndex(conn)
				if err != nil || peerIndex != partyIndex {
					_ = conn.Close()
					time.Sleep(1 * time.Second)
					continue
				}

				s.clientsMu.Lock()
				s.clients[partyIndex] = conn
				s.clientsMu.Unlock()

				go s.handleConnection(conn)
				return
			}
		}(i, addr)
	}
}

func (s *MTLSSession) peerPartyIndex(conn net.Conn) (int, error) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return -1, fmt.Errorf("expected TLS connection, got %T", conn)
	}
	if err := tlsConn.Handshake(); err != nil {
		return -1, fmt.Errorf("TLS handshake failed: %w", err)
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return -1, fmt.Errorf("missing peer certificate")
	}
	cert := state.PeerCertificates[0]

	candidates := make([]string, 0, len(cert.DNSNames)+1)
	candidates = append(candidates, cert.DNSNames...)
	if cert.Subject.CommonName != "" {
		candidates = append(candidates, cert.Subject.CommonName)
	}

	for _, name := range candidates {
		if !strings.HasPrefix(name, "party") {
			continue
		}
		var idx int
		if _, err := fmt.Sscanf(name, "party%d", &idx); err != nil {
			continue
		}
		if idx < 0 || idx >= s.partyCount {
			return -1, fmt.Errorf("peer party index %d out of range [0, %d)", idx, s.partyCount)
		}
		if idx == s.myIndex {
			return -1, fmt.Errorf("peer party index %d matches local index", idx)
		}
		return idx, nil
	}

	return -1, fmt.Errorf("unable to derive peer party index from certificate (CN=%q DNSNames=%v)", cert.Subject.CommonName, cert.DNSNames)
}

func (s *MTLSSession) handleConnection(conn net.Conn) {
	defer conn.Close()

	peerIndex, err := s.peerPartyIndex(conn)
	if err != nil {
		fmt.Printf("Error identifying peer: %v\n", err)
		return
	}

	s.clientsMu.Lock()
	if s.clients[peerIndex] == nil {
		s.clients[peerIndex] = conn
	}
	s.clientsMu.Unlock()

	// Read messages from this connection
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// Read message length (4 bytes)
		var length uint32
		err := binary.Read(conn, binary.BigEndian, &length)
		if err != nil {
			if err != io.EOF {
				fmt.Printf("Error reading message length: %v\n", err)
			}
			return
		}

		if length > maxMessageSize {
			fmt.Printf("Error: message too large: %d bytes (max %d)\n", length, maxMessageSize)
			return
		}

		// Read message data
		data := make([]byte, length)
		_, err = io.ReadFull(conn, data)
		if err != nil {
			fmt.Printf("Error reading message data: %v\n", err)
			return
		}

		sender := peerIndex
		message := data

		// Apply backpressure instead of silently dropping protocol messages.
		if sender >= 0 && sender < s.partyCount {
			select {
			case s.messageQueues[sender] <- message:
			case <-s.ctx.Done():
				return
			}
		}
	}
}

func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

// Send implements mpc.Session interface
func (s *MTLSSession) Send(ctx context.Context, toParty int, msg []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if toParty < 0 || toParty >= s.partyCount || toParty == s.myIndex {
		return fmt.Errorf("invalid target party: %d", toParty)
	}

	s.clientsMu.RLock()
	conn := s.clients[toParty]
	s.clientsMu.RUnlock()

	if conn == nil {
		return fmt.Errorf("no connection to party %d", toParty)
	}

	fullMsg := msg

	// Hold per-connection write lock so length+data are sent atomically.
	s.writeMu[toParty].Lock()
	defer s.writeMu[toParty].Unlock()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetWriteDeadline(deadline); err != nil {
			return fmt.Errorf("failed to set write deadline: %w", err)
		}
		defer func() {
			if err := conn.SetWriteDeadline(time.Time{}); err != nil {
				fmt.Printf("Error clearing write deadline: %v\n", err)
			}
		}()
	}

	// Send length + message
	length := uint32(len(fullMsg))
	err := binary.Write(conn, binary.BigEndian, length)
	if err != nil {
		return fmt.Errorf("failed to send message length: %v", err)
	}

	if err := writeAll(conn, fullMsg); err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}

	return nil
}

// Receive implements mpc.Session interface
func (s *MTLSSession) Receive(ctx context.Context, fromParty int) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if fromParty < 0 || fromParty >= s.partyCount || fromParty == s.myIndex {
		return nil, fmt.Errorf("invalid source party: %d", fromParty)
	}

	select {
	case msg := <-s.messageQueues[fromParty]:
		return msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

// ReceiveAll implements mpc.Session interface
func (s *MTLSSession) ReceiveAll(ctx context.Context, fromParties []int) ([][]byte, error) {
	results := make([][]byte, len(fromParties))

	for i, party := range fromParties {
		msg, err := s.Receive(ctx, party)
		if err != nil {
			return nil, err
		}
		results[i] = msg
	}

	return results, nil
}

// MyIndex implements mpc.Session interface
func (s *MTLSSession) MyIndex() int {
	return s.myIndex
}

// PartyCount implements mpc.Session interface
func (s *MTLSSession) PartyCount() int {
	return s.partyCount
}

// Close implements mpc.Session interface
func (s *MTLSSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	s.cancel()

	if s.listener != nil {
		s.listener.Close()
	}

	s.clientsMu.Lock()
	for _, conn := range s.clients {
		if conn != nil {
			conn.Close()
		}
	}
	s.clientsMu.Unlock()

	return nil
}

// LoadTLSConfig loads TLS configuration from certificate files
func LoadTLSConfig(caCertFile, clientCertFile, clientKeyFile string, isServer bool) (*tls.Config, error) {
	// Load CA certificate
	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// Load client certificate
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %v", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	if !isServer {
		config.ServerName = "localhost"
	}

	return config, nil
}

package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"time"
)

// Party describes a single participant in the MPC cluster.
type Party struct {
	Name    string
	Address string
}

// TLSConfig configures TLS parameters and peer verification.
type TLSConfig struct {
	Certificate tls.Certificate
	RootCAs     *x509.CertPool

	// MinVersion sets the minimum TLS version. Values below TLS 1.3 are
	// upgraded to TLS 1.3 for security. Defaults to tls.VersionTLS13 when zero.
	MinVersion uint16

	// CipherSuites optionally restricts cipher suites (TLS 1.3 ciphers are
	// chosen automatically by Go when MinVersion >= TLS 1.3). Leave empty for
	// secure defaults.
	CipherSuites []uint16

	// ServerNamePolicy optionally computes the SNI value for a peer. Defaults
	// to returning the peer's Party.Name.
	ServerNamePolicy func(p Party) string

	// VerifyPeer optionally performs additional certificate checks. If set, it
	// is invoked after SAN-name binding succeeds.
	VerifyPeer func(cert *x509.Certificate, expectedName string) error

	// SPKIPin optionally holds a SHA-256 hash of the peer SPKI to pin against.
	// If non-empty, connections whose leaf certificate SPKI hash doesn't match
	// are rejected.
	SPKIPin []byte
}

// Timeouts controls operation deadlines. Zero values disable per-op deadlines.
type Timeouts struct {
	Handshake time.Duration // default 10s
	Connect   time.Duration // default 3s
	Read      time.Duration // per-frame read deadline
	Write     time.Duration // per-frame write deadline
}

// Backoff controls reconnect behavior for outbound connections.
type Backoff struct {
	Min    time.Duration // default 200ms
	Max    time.Duration // default 2s
	Factor float64       // default 1.5
	Jitter float64       // default 0.2 (20%)
}

// Buffers configures send/recv channel depths per peer.
type Buffers struct {
	Send int // default 16
	Recv int // default 16
}

// Config drives the mtls transport behavior.
type Config struct {
	SelfIndex  int
	Parties    []Party
	TLS        TLSConfig
	Timeouts   Timeouts
	Backoff    Backoff
	Buffers    Buffers
	MaxMessage int // maximum payload per message in bytes (default 32 MiB)
}

func (c *Config) defaults() {
	if c.MaxMessage <= 0 {
		c.MaxMessage = 32 << 20 // 32 MiB
	}
	if c.Buffers.Send <= 0 {
		c.Buffers.Send = 16
	}
	if c.Buffers.Recv <= 0 {
		c.Buffers.Recv = 16
	}
	if c.Timeouts.Handshake == 0 {
		c.Timeouts.Handshake = 10 * time.Second
	}
	if c.Timeouts.Connect == 0 {
		c.Timeouts.Connect = 3 * time.Second
	}
	if c.Backoff.Min == 0 {
		c.Backoff.Min = 200 * time.Millisecond
	}
	if c.Backoff.Max == 0 {
		c.Backoff.Max = 2 * time.Second
	}
	if c.Backoff.Factor == 0 {
		c.Backoff.Factor = 1.5
	}
	if c.Backoff.Jitter == 0 {
		c.Backoff.Jitter = 0.2
	}
	if c.TLS.MinVersion == 0 {
		c.TLS.MinVersion = tls.VersionTLS13
	}
}

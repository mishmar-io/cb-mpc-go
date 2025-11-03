package mtls

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
)

func TestMTLSBasicSendReceive(t *testing.T) {
	t.Parallel()

	// Generate a demo CA and per-party certs
	caCert, caKey, err := genCA()
	if err != nil {
		t.Fatalf("gen CA: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	// Allocate two ports
	addr0 := freeAddr(t)
	addr1 := freeAddr(t)

	// Party names must appear in SANs
	cert0, err := genLeaf(caCert, caKey, "p0")
	if err != nil {
		t.Fatalf("leaf p0: %v", err)
	}
	cert1, err := genLeaf(caCert, caKey, "p1")
	if err != nil {
		t.Fatalf("leaf p1: %v", err)
	}

	parties := []Party{{Name: "p0", Address: addr0}, {Name: "p1", Address: addr1}}

	cfg0 := Config{
		SelfIndex:  0,
		Parties:    parties,
		TLS:        TLSConfig{Certificate: cert0, RootCAs: caPool},
		Timeouts:   Timeouts{Handshake: 5 * time.Second, Connect: 2 * time.Second, Read: 2 * time.Second, Write: 2 * time.Second},
		MaxMessage: 1 << 20,
	}
	cfg1 := Config{
		SelfIndex:  1,
		Parties:    parties,
		TLS:        TLSConfig{Certificate: cert1, RootCAs: caPool},
		Timeouts:   Timeouts{Handshake: 5 * time.Second, Connect: 2 * time.Second, Read: 2 * time.Second, Write: 2 * time.Second},
		MaxMessage: 1 << 20,
	}

	type res struct {
		t   *Transport
		err error
	}
	ch0 := make(chan res, 1)
	ch1 := make(chan res, 1)
	go func() { tr, e := New(cfg0); ch0 <- res{t: tr, err: e} }()
	go func() { tr, e := New(cfg1); ch1 <- res{t: tr, err: e} }()

	r0 := <-ch0
	r1 := <-ch1
	if r0.err != nil {
		t.Fatalf("new t0: %v", r0.err)
	}
	if r1.err != nil {
		t.Fatalf("new t1: %v", r1.err)
	}
	t0 := r0.t
	t1 := r1.t
	defer func() { _ = t0.Close() }()
	defer func() { _ = t1.Close() }()

	// Simple send/receive
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	msg := []byte("hello from p0")
	if err := t0.Send(ctx, cbmpc.RoleID(1), msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	got, err := t1.Receive(ctx, cbmpc.RoleID(0))
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("mismatch: got %q want %q", string(got), string(msg))
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen :0: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func genCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mtls-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return caCert, key, nil
}

func genLeaf(ca *x509.Certificate, caKey *rsa.PrivateKey, name string) (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name, "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return tls.X509KeyPair(certPEM, keyPEM)
}

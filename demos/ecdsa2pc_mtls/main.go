package main

import (
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"time"

	democommon "github.com/coinbase/cb-mpc-go/demos/common"
	"github.com/coinbase/cb-mpc-go/pkg/mpc"
)

const (
	partyCount = 2
)

func main() {
	cfg := parseConfig()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	tlsConfig, err := democommon.LoadTLSConfig(cfg.caFile, cfg.certFile, cfg.keyFile, cfg.self == 0)
	if err != nil {
		log.Fatalf("load TLS config: %v", err)
	}

	clientAddrs := make([]string, partyCount)
	if cfg.self == 1 {
		clientAddrs[0] = cfg.peerAddr
	}

	session, err := democommon.NewMTLSSession(cfg.self, partyCount, cfg.listenAddr, clientAddrs, tlsConfig)
	if err != nil {
		log.Fatalf("create mTLS session: %v", err)
	}
	defer func() { _ = session.Close() }()

	peer := 1 - cfg.self
	if err := session.WaitForPeers(ctx, []int{peer}); err != nil {
		log.Fatalf("wait for peer %d: %v", peer, err)
	}
	log.Printf("party %d connected to peer %d", cfg.self, peer)

	keyBlob, err := mpc.ECDSA2PDKG(ctx, session, mpc.CurveSecp256k1)
	if err != nil {
		log.Fatalf("party %d dkg: %v", cfg.self, err)
	}

	hash := sha256.Sum256([]byte("cb-mpc-go ecdsa2pc mTLS demo"))
	sidOut, sigDER, err := mpc.ECDSA2PSign(ctx, session, keyBlob, hash[:], nil)
	if err != nil {
		log.Fatalf("party %d sign: %v", cfg.self, err)
	}

	refreshedKeyBlob, err := mpc.ECDSA2PRefresh(ctx, session, keyBlob)
	if err != nil {
		log.Fatalf("party %d refresh: %v", cfg.self, err)
	}

	pubKey, err := mpc.ECDSA2PGetPublicKeyCompressed(refreshedKeyBlob)
	if err != nil {
		log.Fatalf("party %d get public key: %v", cfg.self, err)
	}

	log.Printf("party %d complete", cfg.self)
	log.Printf("party %d public key bytes: %d", cfg.self, len(pubKey))
	log.Printf("party %d sid bytes: %d", cfg.self, len(sidOut))
	log.Printf("party %d signature bytes: %d", cfg.self, len(sigDER))
	if cfg.self == 0 && len(sigDER) == 0 {
		log.Fatalf("party 0 expected a signature but received none")
	}
	if cfg.self == 1 && len(sigDER) != 0 {
		log.Fatalf("party 1 should not receive the signature in this demo")
	}
}

type config struct {
	self       int
	listenAddr string
	peerAddr   string
	caFile     string
	certFile   string
	keyFile    string
	timeout    time.Duration
}

func parseConfig() config {
	cfg := config{}
	flag.IntVar(&cfg.self, "self", -1, "party index (0 or 1)")
	flag.StringVar(&cfg.listenAddr, "listen", "", "listen address for party 0, e.g. 127.0.0.1:9440")
	flag.StringVar(&cfg.peerAddr, "peer", "", "address of party 0 for party 1 to dial")
	flag.StringVar(&cfg.caFile, "ca", "", "path to CA certificate PEM")
	flag.StringVar(&cfg.certFile, "cert", "", "path to party certificate PEM")
	flag.StringVar(&cfg.keyFile, "key", "", "path to party private key PEM")
	flag.DurationVar(&cfg.timeout, "timeout", 30*time.Second, "overall protocol timeout")
	flag.Parse()

	switch cfg.self {
	case 0:
		if cfg.listenAddr == "" {
			log.Fatal("--listen is required for party 0")
		}
	case 1:
		if cfg.peerAddr == "" {
			log.Fatal("--peer is required for party 1")
		}
	default:
		log.Fatal("--self must be 0 or 1")
	}

	for flagName, value := range map[string]string{
		"--ca":   cfg.caFile,
		"--cert": cfg.certFile,
		"--key":  cfg.keyFile,
	} {
		if value == "" {
			log.Fatalf("%s is required", flagName)
		}
	}

	if flag.NArg() != 0 {
		log.Fatalf("unexpected positional arguments: %v", flag.Args())
	}

	fmt.Printf("starting party %d with timeout=%s\n", cfg.self, cfg.timeout)
	return cfg
}

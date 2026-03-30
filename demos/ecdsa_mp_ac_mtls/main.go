package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp256k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	democommon "github.com/coinbase/cb-mpc-go/demos/common"
	"github.com/coinbase/cb-mpc-go/pkg/mpc"
)

const (
	dkgStagePortOffset     = 0
	signStagePortOffset    = 100
	refreshStagePortOffset = 200
	resignStagePortOffset  = 300
	ecdsaPartyCount        = 3
	onlineQuorumCount      = 2
	signReceiver           = 0
)

type config struct {
	self       int
	listenAddr string
	partyAddrs []string
	caFile     string
	certFile   string
	keyFile    string
	timeout    time.Duration
}

func main() {
	cfg := parseConfig()
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	tlsConfig, err := democommon.LoadTLSConfig(cfg.caFile, cfg.certFile, cfg.keyFile, false)
	if err != nil {
		log.Fatalf("load TLS config: %v", err)
	}

	access, quorumPartyIndices := quorumAccessStructure()
	stage0Addrs, err := offsetAddresses(cfg.partyAddrs, dkgStagePortOffset)
	if err != nil {
		log.Fatalf("stage0 addresses: %v", err)
	}

	session, err := democommon.NewMTLSSession(cfg.self, ecdsaPartyCount, stage0Addrs[cfg.self], stage0Addrs, tlsConfig)
	if err != nil {
		log.Fatalf("create DKG session: %v", err)
	}
	if err := session.WaitForPeers(ctx, otherPartyIndices(cfg.self, ecdsaPartyCount)); err != nil {
		log.Fatalf("wait for DKG peers: %v", err)
	}

	acKeyBlob, sidOut, err := mpc.ECDSAMPDKGAC(ctx, session, mpc.CurveSecp256k1, nil, access, quorumPartyIndices)
	if err != nil {
		log.Fatalf("dkg ac: %v", err)
	}
	publicKeyCompressed, err := mpc.ECDSAMPGetPublicKeyCompressed(acKeyBlob)
	if err != nil {
		log.Fatalf("get public key: %v", err)
	}
	log.Printf("party %d DKG AC complete: public key bytes=%d sid bytes=%d", cfg.self, len(publicKeyCompressed), len(sidOut))
	_ = session.Close()

	msgHash := sha256.Sum256([]byte("cb-mpc-go ecdsa mp ac mTLS demo"))
	signStageAddrs, err := offsetAddresses(cfg.partyAddrs[:onlineQuorumCount], signStagePortOffset)
	if err != nil {
		log.Fatalf("sign stage addresses: %v", err)
	}
	sigDER, err := maybeRunSignStage(ctx, cfg, tlsConfig, signStageAddrs, access, acKeyBlob, msgHash[:], publicKeyCompressed, "initial")
	if err != nil {
		log.Fatalf("initial sign stage: %v", err)
	}
	if cfg.self == signReceiver {
		log.Printf("party %d initial sign verified, signature bytes=%d", cfg.self, len(sigDER))
	}

	refreshStageAddrs, err := offsetAddresses(cfg.partyAddrs, refreshStagePortOffset)
	if err != nil {
		log.Fatalf("refresh stage addresses: %v", err)
	}
	refreshSession, err := democommon.NewMTLSSession(cfg.self, ecdsaPartyCount, refreshStageAddrs[cfg.self], refreshStageAddrs, tlsConfig)
	if err != nil {
		log.Fatalf("create refresh session: %v", err)
	}
	if err := refreshSession.WaitForPeers(ctx, otherPartyIndices(cfg.self, ecdsaPartyCount)); err != nil {
		log.Fatalf("wait for refresh peers: %v", err)
	}

	refreshedSIDOut, refreshedKeyBlob, err := mpc.ECDSAMPRefreshAC(ctx, refreshSession, sidOut, acKeyBlob, access, quorumPartyIndices)
	if err != nil {
		log.Fatalf("refresh ac: %v", err)
	}
	refreshedPublicKeyCompressed, err := mpc.ECDSAMPGetPublicKeyCompressed(refreshedKeyBlob)
	if err != nil {
		log.Fatalf("get refreshed public key: %v", err)
	}
	if !equalBytes(publicKeyCompressed, refreshedPublicKeyCompressed) {
		log.Fatalf("refreshed public key mismatch")
	}
	log.Printf("party %d refresh AC complete: sid bytes=%d", cfg.self, len(refreshedSIDOut))
	_ = refreshSession.Close()

	resignStageAddrs, err := offsetAddresses(cfg.partyAddrs[:onlineQuorumCount], resignStagePortOffset)
	if err != nil {
		log.Fatalf("resign stage addresses: %v", err)
	}
	sigDER, err = maybeRunSignStage(ctx, cfg, tlsConfig, resignStageAddrs, access, refreshedKeyBlob, msgHash[:], refreshedPublicKeyCompressed, "refreshed")
	if err != nil {
		log.Fatalf("refreshed sign stage: %v", err)
	}
	if cfg.self == signReceiver {
		log.Printf("party %d refreshed sign verified, signature bytes=%d", cfg.self, len(sigDER))
	} else if cfg.self >= onlineQuorumCount {
		log.Printf("party %d was offline for signing quorum %v and skipped sign stages", cfg.self, quorumPartyIndices)
	}

	log.Printf("party %d ECDSA MP AC showcase complete", cfg.self)
}

func parseConfig() config {
	cfg := config{}
	var partyAddrs string
	flag.IntVar(&cfg.self, "self", -1, "party index (0, 1, or 2)")
	flag.StringVar(&cfg.listenAddr, "listen", "", "base listen address for this party, e.g. 127.0.0.1:9640")
	flag.StringVar(&partyAddrs, "party-addrs", "", "comma-separated base listen addresses for all parties in index order")
	flag.StringVar(&cfg.caFile, "ca", "", "path to CA certificate PEM")
	flag.StringVar(&cfg.certFile, "cert", "", "path to party certificate PEM")
	flag.StringVar(&cfg.keyFile, "key", "", "path to party private key PEM")
	flag.DurationVar(&cfg.timeout, "timeout", 90*time.Second, "overall protocol timeout")
	flag.Parse()

	if cfg.self < 0 || cfg.self >= ecdsaPartyCount {
		log.Fatalf("--self must be in [0,%d)", ecdsaPartyCount)
	}
	cfg.partyAddrs = splitAddresses(partyAddrs)
	if len(cfg.partyAddrs) != ecdsaPartyCount {
		log.Fatalf("--party-addrs must list exactly %d addresses, got %d", ecdsaPartyCount, len(cfg.partyAddrs))
	}
	if cfg.listenAddr == "" {
		log.Fatal("--listen is required")
	}
	if cfg.partyAddrs[cfg.self] != cfg.listenAddr {
		log.Fatalf("--listen must match the address at --party-addrs[%d]", cfg.self)
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
	log.Printf("starting party %d with base listen=%s", cfg.self, cfg.listenAddr)
	return cfg
}

func maybeRunSignStage(ctx context.Context, cfg config, tlsConfig *tls.Config, signAddrs []string, access *mpc.AccessStructure, acKeyBlob []byte, msgHash []byte, publicKeyCompressed []byte, stage string) ([]byte, error) {
	if cfg.self >= onlineQuorumCount {
		log.Printf("party %d skipping %s sign stage; not in online quorum [0 1]", cfg.self, stage)
		return nil, nil
	}

	listenAddr := signAddrs[cfg.self]
	if cfg.self == 1 {
		// Party 1 only needs to dial party 0 in the two-party online quorum.
		listenAddr = ""
	}

	signSession, err := democommon.NewMTLSSession(cfg.self, onlineQuorumCount, listenAddr, signAddrs, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("create %s sign session: %w", stage, err)
	}
	defer func() { _ = signSession.Close() }()

	if err := signSession.WaitForPeers(ctx, otherPartyIndices(cfg.self, onlineQuorumCount)); err != nil {
		return nil, fmt.Errorf("wait for %s sign peers: %w", stage, err)
	}

	sigDER, err := mpc.ECDSAMPSignAC(ctx, signSession, acKeyBlob, access, msgHash, signReceiver)
	if err != nil {
		return nil, fmt.Errorf("%s sign ac: %w", stage, err)
	}

	if cfg.self == signReceiver {
		if err := verifySecp256k1ECDSASignature(publicKeyCompressed, msgHash, sigDER); err != nil {
			return nil, fmt.Errorf("%s signature verify: %w", stage, err)
		}
		return sigDER, nil
	}

	if len(sigDER) != 0 {
		return nil, fmt.Errorf("party %d unexpectedly received %s signature bytes", cfg.self, stage)
	}
	return nil, nil
}

func quorumAccessStructure() (*mpc.AccessStructure, []int) {
	return &mpc.AccessStructure{
		Nodes: []mpc.AccessStructureNode{
			{Type: mpc.AccessNodeLeaf, LeafName: "party0"},
			{Type: mpc.AccessNodeLeaf, LeafName: "party1"},
			{Type: mpc.AccessNodeLeaf, LeafName: "party2"},
			{Type: mpc.AccessNodeThreshold, ThresholdK: 2, Children: []int{0, 1, 2}},
		},
		Root: 3,
	}, []int{0, 1}
}

func verifySecp256k1ECDSASignature(publicKeyCompressed []byte, msgHash []byte, sigDER []byte) error {
	publicKey, err := secp256k1.ParsePubKey(publicKeyCompressed)
	if err != nil {
		return fmt.Errorf("failed to parse secp256k1 public key: %w", err)
	}
	signature, err := secp256k1ecdsa.ParseDERSignature(sigDER)
	if err != nil {
		return fmt.Errorf("failed to parse ECDSA DER signature: %w", err)
	}
	if !signature.Verify(msgHash, publicKey) {
		return fmt.Errorf("ECDSA signature verification failed")
	}
	return nil
}

func offsetAddresses(addrs []string, offset int) ([]string, error) {
	out := make([]string, len(addrs))
	for i, addr := range addrs {
		host, port, err := democommon.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("address %q: %w", addr, err)
		}
		out[i] = democommon.JoinHostPort(host, port+offset)
	}
	return out, nil
}

func splitAddresses(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func otherPartyIndices(self, partyCount int) []int {
	indices := make([]int, 0, partyCount-1)
	for i := 0; i < partyCount; i++ {
		if i != self {
			indices = append(indices, i)
		}
	}
	return indices
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	democommon "github.com/coinbase/cb-mpc-go/demos/common"
	"github.com/coinbase/cb-mpc-go/pkg/mpc"
)

const (
	defaultKeyCount   = 3
	defaultBackupRows = 0
	signReceiver      = 0
)

type keyMaterial struct {
	keyBlob       []byte
	publicKey     []byte
	publicKeyBlob []byte
	publicShare   []byte
}

type config struct {
	self       int
	listenAddr string
	partyAddrs []string
	caFile     string
	certFile   string
	keyFile    string
	timeout    time.Duration
	keyCount   int
}

func main() {
	cfg := parseConfig()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	tlsConfig, err := democommon.LoadTLSConfig(cfg.caFile, cfg.certFile, cfg.keyFile, false)
	if err != nil {
		log.Fatalf("load TLS config: %v", err)
	}

	session, err := democommon.NewMTLSSession(cfg.self, len(cfg.partyAddrs), cfg.listenAddr, cfg.partyAddrs, tlsConfig)
	if err != nil {
		log.Fatalf("create mTLS session: %v", err)
	}
	defer func() { _ = session.Close() }()

	peers := otherPartyIndices(cfg.self, len(cfg.partyAddrs))
	if err := session.WaitForPeers(ctx, peers); err != nil {
		log.Fatalf("wait for peers: %v", err)
	}
	log.Printf("party %d connected to peers %v", cfg.self, peers)

	keys, err := runDKGs(ctx, session, cfg.keyCount)
	if err != nil {
		log.Fatalf("run DKGs: %v", err)
	}

	restoredParty0KeyBlobs := make([][]byte, cfg.keyCount)
	if cfg.self == 0 {
		restoredParty0KeyBlobs, err = backupAndRestoreParty0Shares(keys)
		if err != nil {
			log.Fatalf("backup and restore: %v", err)
		}
		log.Printf("party 0 restored %d signer shares from PVE-AC backup", len(restoredParty0KeyBlobs))
	}

	if err := runSigningShowcase(ctx, session, keys, restoredParty0KeyBlobs); err != nil {
		log.Fatalf("run signing showcase: %v", err)
	}

	log.Printf("party %d showcase complete", cfg.self)
}

func parseConfig() config {
	cfg := config{}
	var partyAddrs string
	flag.IntVar(&cfg.self, "self", -1, "party index")
	flag.StringVar(&cfg.listenAddr, "listen", "", "listen address for this party, e.g. 127.0.0.1:9540")
	flag.StringVar(&partyAddrs, "party-addrs", "", "comma-separated listen addresses for all parties in index order")
	flag.StringVar(&cfg.caFile, "ca", "", "path to CA certificate PEM")
	flag.StringVar(&cfg.certFile, "cert", "", "path to party certificate PEM")
	flag.StringVar(&cfg.keyFile, "key", "", "path to party private key PEM")
	flag.DurationVar(&cfg.timeout, "timeout", 90*time.Second, "overall protocol timeout")
	flag.IntVar(&cfg.keyCount, "key-count", defaultKeyCount, "number of EdDSA-MP keys to generate and back up")
	flag.Parse()

	if cfg.self < 0 {
		log.Fatal("--self is required")
	}
	cfg.partyAddrs = splitAddresses(partyAddrs)
	if len(cfg.partyAddrs) < 3 {
		log.Fatalf("--party-addrs must list at least 3 addresses, got %d", len(cfg.partyAddrs))
	}
	if cfg.self >= len(cfg.partyAddrs) {
		log.Fatalf("--self=%d out of range for %d party addresses", cfg.self, len(cfg.partyAddrs))
	}
	if cfg.listenAddr == "" {
		log.Fatal("--listen is required")
	}
	if cfg.partyAddrs[cfg.self] == "" {
		log.Fatalf("party address for self index %d cannot be empty", cfg.self)
	}
	if cfg.listenAddr != cfg.partyAddrs[cfg.self] {
		log.Fatalf("--listen must match the address at --party-addrs[%d]", cfg.self)
	}
	if cfg.keyCount <= 0 {
		log.Fatal("--key-count must be positive")
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
	log.Printf("starting party %d with listen=%s, partyCount=%d, keyCount=%d", cfg.self, cfg.listenAddr, len(cfg.partyAddrs), cfg.keyCount)
	return cfg
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

func runDKGs(ctx context.Context, session *democommon.MTLSSession, keyCount int) ([]keyMaterial, error) {
	keys := make([]keyMaterial, keyCount)
	for keyIdx := 0; keyIdx < keyCount; keyIdx++ {
		keyBlob, sidOut, err := mpc.EdDSAMPDKGAdditive(ctx, session, mpc.CurveEd25519)
		if err != nil {
			return nil, fmt.Errorf("key %d dkg additive: %w", keyIdx, err)
		}
		if len(sidOut) == 0 {
			return nil, fmt.Errorf("key %d returned empty sid", keyIdx)
		}
		publicKey, err := mpc.EdDSAMPGetPublicKeyCompressed(keyBlob)
		if err != nil {
			return nil, fmt.Errorf("key %d get public key: %w", keyIdx, err)
		}
		keys[keyIdx] = keyMaterial{
			keyBlob:   keyBlob,
			publicKey: publicKey,
		}
		log.Printf("party %d generated key %d: public key bytes=%d sid bytes=%d", session.MyIndex(), keyIdx, len(publicKey), len(sidOut))
	}
	return keys, nil
}

func backupAndRestoreParty0Shares(keys []keyMaterial) ([][]byte, error) {
	access, backupLeafNames, quorumLeafNames := backupAccessStructure()
	backupEKs := make([][]byte, len(backupLeafNames))
	backupDKs := make([][]byte, len(backupLeafNames))
	for i := range backupLeafNames {
		ek, dk, err := mpc.PVEGenerateBasePKERSAKeypair()
		if err != nil {
			return nil, fmt.Errorf("generate backup leaf key %d: %w", i, err)
		}
		backupEKs[i] = ek
		backupDKs[i] = dk
	}

	detachedScalars := make([][]byte, len(keys))
	for keyIdx := range keys {
		publicShare, err := mpc.EdDSAMPGetPublicShareCompressed(keys[keyIdx].keyBlob)
		if err != nil {
			return nil, fmt.Errorf("key %d get public share: %w", keyIdx, err)
		}
		publicKeyBlob, privateScalar, err := mpc.EdDSAMPDetachPrivateScalar(keys[keyIdx].keyBlob)
		if err != nil {
			return nil, fmt.Errorf("key %d detach private scalar: %w", keyIdx, err)
		}
		keys[keyIdx].publicKeyBlob = publicKeyBlob
		keys[keyIdx].publicShare = publicShare
		detachedScalars[keyIdx] = privateScalar
	}

	sensitiveDetachedScalars := mpc.SensitiveSlices(detachedScalars)
	defer func() { _ = sensitiveDetachedScalars.Close() }()

	label := []byte("cb-mpc-go:eddsa-mp-backup-mtls:party0")
	ciphertext, err := mpc.PVEACEncrypt(nil, mpc.CurveEd25519, access, backupLeafNames, backupEKs, label, sensitiveDetachedScalars.Bytes())
	if err != nil {
		return nil, fmt.Errorf("encrypt detached scalars: %w", err)
	}
	count, err := mpc.PVEACGetCount(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("count backup ciphertext rows: %w", err)
	}
	qs, err := mpc.PVEACGetQs(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("extract backup ciphertext Qs: %w", err)
	}
	if err := mpc.PVEACVerify(nil, mpc.CurveEd25519, access, backupLeafNames, backupEKs, ciphertext, qs, label); err != nil {
		return nil, fmt.Errorf("verify backup ciphertext: %w", err)
	}

	quorumLeafIdx := []int{0, 2}
	quorumShares := make([][]byte, len(quorumLeafIdx))
	for i, leafIdx := range quorumLeafIdx {
		share, err := mpc.PVEACPartyDecryptRow(nil, mpc.CurveEd25519, access, ciphertext, defaultBackupRows, backupLeafNames[leafIdx], backupDKs[leafIdx], label)
		if err != nil {
			return nil, fmt.Errorf("decrypt backup share for %s: %w", backupLeafNames[leafIdx], err)
		}
		quorumShares[i] = share
	}

	recoveredScalars, err := mpc.PVEACAggregateToRestoreRow(nil, mpc.CurveEd25519, access, quorumLeafNames, quorumShares, ciphertext, defaultBackupRows, label)
	if err != nil {
		return nil, fmt.Errorf("aggregate backup shares: %w", err)
	}
	sensitiveRecoveredScalars := mpc.SensitiveSlices(recoveredScalars)
	defer func() { _ = sensitiveRecoveredScalars.Close() }()

	restoredKeyBlobs := make([][]byte, len(keys))
	for keyIdx := range keys {
		restoredKeyBlob, err := mpc.EdDSAMPAttachPrivateScalar(keys[keyIdx].publicKeyBlob, sensitiveRecoveredScalars.Bytes()[keyIdx], keys[keyIdx].publicShare)
		if err != nil {
			return nil, fmt.Errorf("reattach key %d: %w", keyIdx, err)
		}
		restoredKeyBlobs[keyIdx] = restoredKeyBlob
	}

	log.Printf("party 0 backed up %d detached shares into one %d-row ciphertext (%d bytes)", len(keys), count, len(ciphertext))
	return restoredKeyBlobs, nil
}

func backupAccessStructure() (*mpc.AccessStructure, []string, []string) {
	leafNames := []string{"backup0", "backup1", "backup2"}
	return &mpc.AccessStructure{
		Nodes: []mpc.AccessStructureNode{
			{Type: mpc.AccessNodeLeaf, LeafName: leafNames[0]},
			{Type: mpc.AccessNodeLeaf, LeafName: leafNames[1]},
			{Type: mpc.AccessNodeLeaf, LeafName: leafNames[2]},
			{Type: mpc.AccessNodeThreshold, ThresholdK: 2, Children: []int{0, 1, 2}},
		},
		Root: 3,
	}, leafNames, []string{leafNames[0], leafNames[2]}
}

func runSigningShowcase(ctx context.Context, session *democommon.MTLSSession, keys []keyMaterial, restoredParty0KeyBlobs [][]byte) error {
	for keyIdx, key := range keys {
		keyBlob := key.keyBlob
		if session.MyIndex() == signReceiver && len(restoredParty0KeyBlobs) != 0 {
			keyBlob = restoredParty0KeyBlobs[keyIdx]
		}

		msg := []byte(fmt.Sprintf("cb-mpc-go eddsa mp backup mTLS demo key %d", keyIdx))
		sig, err := mpc.EdDSAMPSignAdditive(ctx, session, keyBlob, msg, signReceiver)
		if err != nil {
			return fmt.Errorf("key %d sign additive: %w", keyIdx, err)
		}

		if session.MyIndex() == signReceiver {
			if !ed25519.Verify(ed25519.PublicKey(key.publicKey), msg, sig) {
				return fmt.Errorf("key %d signature failed verification", keyIdx)
			}
			log.Printf("party %d verified restored signature for key %d: public key bytes=%d signature bytes=%d", session.MyIndex(), keyIdx, len(key.publicKey), len(sig))
			continue
		}
		if len(sig) != 0 {
			return fmt.Errorf("party %d should not receive signature bytes for key %d", session.MyIndex(), keyIdx)
		}
		log.Printf("party %d participated in signing key %d", session.MyIndex(), keyIdx)
	}
	return nil
}

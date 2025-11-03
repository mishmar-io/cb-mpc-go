// Package cbmpc provides an MPC API for Go.
//
// It offers two integration paths:
//  1. Native-backed protocols via CGO that wrap the C++ implementations in the
//     cb-mpc submodule.
//  2. Pure-Go protocols that communicate over a pluggable Transport.
//
// # Architecture
//
// Layers:
//   - pkg/cbmpc/ - Public Go API (jobs, roles, transport interface, protocols)
//   - pkg/cbmpc/internal/backend/ - CGO bindings layer for native-backed jobs
//   - cb-mpc/ - C++ MPC protocol implementations (git submodule)
//   - pkg/cbmpc/transport/ - Transport implementations (e.g., mTLS, mocknet)
//
// # Build Requirements
//
// CGO is required only for native-backed functionality. Pure-Go protocols and
// transports do not require CGO.
//
// # Protocol Documentation
//
// For native-backed protocols, see specifications under cb-mpc/src/cbmpc/.
// For Go-native protocols, see subpackages under pkg/cbmpc/.
//
// # Example Usage (Go-native protocol)
//
//	// Create a mock network for testing
//	net := mocknet.New()
//
//	// Set up two-party jobs
//	names := [2]string{"party1", "party2"}
//	transport1 := net.Ep2P(cbmpc.RoleID(0), cbmpc.RoleID(1))
//	transport2 := net.Ep2P(cbmpc.RoleID(1), cbmpc.RoleID(0))
//
//	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
//	defer cancel()
//
//	job1, _ := cbmpc.NewGoJob2PWithContext(ctx, transport1, cbmpc.RoleP1, names)
//	defer job1.Close()
//
//	job2, _ := cbmpc.NewGoJob2PWithContext(ctx, transport2, cbmpc.RoleP2, names)
//	defer job2.Close()
//
//	// Run Go-native agreerandom
//	result1, _ := agreerandom.GoAgreeRandom(ctx, job1, 256)
//	result2, _ := agreerandom.GoAgreeRandom(ctx, job2, 256)
//
// # Subpackages
//
// Protocol implementations and support packages:
//   - accessstructure - DSL for access control structures
//   - agreerandom - Multi-party random agreement protocols
//   - curve - Elliptic curve types and operations
//   - ecdsa2p - 2-party ECDSA protocols
//   - ecdsamp - Multi-party threshold ECDSA protocols
//   - kem - Key Encapsulation Mechanism (KEM) for PVE
//   - logging - Minimal logging facade (slog adapter)
//   - transport/mocknet - In-memory transport for unit tests
//   - transport/mtls - mTLS-based transport for real deployments
//   - paillier - Homomorphic Paillier cryptosystem
//   - pve - Publicly Verifiable Encryption
//   - schnorr2p - 2-party Schnorr signature protocols
//   - schnorrmp - Multi-party threshold Schnorr protocols
//   - zk - Zero-knowledge proof protocols
package cbmpc

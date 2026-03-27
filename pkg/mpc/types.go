package mpc

import (
	"context"
	"fmt"
	"io"
)

// Curve matches cbmpc_curve_id_t.
type Curve int32

const (
	CurveP256      Curve = 1
	CurveSecp256k1 Curve = 2
	CurveEd25519   Curve = 3
)

func (c Curve) String() string {
	switch c {
	case CurveP256:
		return "p256"
	case CurveSecp256k1:
		return "secp256k1"
	case CurveEd25519:
		return "ed25519"
	default:
		return fmt.Sprintf("unknown(%d)", int32(c))
	}
}

// Session is the transport contract for interactive protocols.
//
// Production implementations should provide authenticated and confidential
// channels (e.g., mTLS) and enforce reasonable message size limits to avoid
// memory-exhaustion attacks from untrusted peers.
type Session interface {
	io.Closer
	Send(ctx context.Context, toParty int, msg []byte) error
	Receive(ctx context.Context, fromParty int) ([]byte, error)
	ReceiveAll(ctx context.Context, fromParties []int) ([][]byte, error)
	MyIndex() int
	PartyCount() int
}

// AccessStructureNodeType matches cbmpc_access_structure_node_type_t.
type AccessStructureNodeType int32

const (
	AccessNodeLeaf      AccessStructureNodeType = 1
	AccessNodeAnd       AccessStructureNodeType = 2
	AccessNodeOr        AccessStructureNodeType = 3
	AccessNodeThreshold AccessStructureNodeType = 4
)

// AccessStructureNode is a Go tree node for access-structure APIs.
type AccessStructureNode struct {
	Type       AccessStructureNodeType
	LeafName   string
	ThresholdK int
	Children   []int
}

// AccessStructure is the Go representation of an access-structure tree.
type AccessStructure struct {
	Nodes []AccessStructureNode
	Root  int
}

func defaultPartyNames(count int) []string {
	names := make([]string, count)
	for i := 0; i < count; i++ {
		names[i] = fmt.Sprintf("party%d", i)
	}
	return names
}

func partyNamesFromIndices(indices []int) []string {
	names := make([]string, len(indices))
	for i, idx := range indices {
		names[i] = fmt.Sprintf("party%d", idx)
	}
	return names
}

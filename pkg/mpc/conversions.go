package mpc

import (
	"fmt"
	"math"

	cinterop "github.com/coinbase/cb-mpc-go/internal/cgo"
)

func toCGOCurve(curve Curve) (cinterop.CurveID, error) {
	switch curve {
	case CurveP256:
		return cinterop.CurveP256, nil
	case CurveSecp256k1:
		return cinterop.CurveSecp256k1, nil
	case CurveEd25519:
		return cinterop.CurveEd25519, nil
	default:
		return 0, fmt.Errorf("unsupported curve %d", int32(curve))
	}
}

func toCGOAccessStructure(access *AccessStructure) (*cinterop.AccessStructure, error) {
	if access == nil {
		return nil, fmt.Errorf("access structure cannot be nil")
	}
	if len(access.Nodes) == 0 {
		return nil, fmt.Errorf("access structure must contain at least one node")
	}
	if len(access.Nodes) > math.MaxInt32 {
		return nil, fmt.Errorf("access structure has too many nodes: %d", len(access.Nodes))
	}
	if access.Root > math.MaxInt32 {
		return nil, fmt.Errorf("access structure root index %d exceeds int32 range", access.Root)
	}
	if access.Root < 0 || access.Root >= len(access.Nodes) {
		return nil, fmt.Errorf("access structure root index %d out of range [0, %d)", access.Root, len(access.Nodes))
	}
	nodes := make([]cinterop.AccessStructureNode, len(access.Nodes))
	for i, node := range access.Nodes {
		if node.ThresholdK < math.MinInt32 || node.ThresholdK > math.MaxInt32 {
			return nil, fmt.Errorf("access structure node %d has threshold_k out of int32 range: %d", i, node.ThresholdK)
		}
		children := make([]int32, len(node.Children))
		for j, child := range node.Children {
			if child > math.MaxInt32 {
				return nil, fmt.Errorf("access structure node %d child[%d]=%d exceeds int32 range", i, j, child)
			}
			if child < 0 || child >= len(access.Nodes) {
				return nil, fmt.Errorf("access structure node %d child[%d]=%d out of range [0, %d)", i, j, child, len(access.Nodes))
			}
			children[j] = int32(child)
		}
		nodes[i] = cinterop.AccessStructureNode{
			Type:       cinterop.AccessStructureNodeType(node.Type),
			LeafName:   node.LeafName,
			ThresholdK: int32(node.ThresholdK),
			Children:   children,
		}
	}
	return &cinterop.AccessStructure{
		Nodes: nodes,
		Root:  int32(access.Root),
	}, nil
}

package mpc

import (
	"context"

	cinterop "github.com/coinbase/cb-mpc-go/internal/cgo"
)

func TDH2DKGAdditive(ctx context.Context, session Session, curve Curve) ([]byte, [][]byte, []byte, []byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return cinterop.TDH2DKGAdditive(ctx, session, cgoCurve)
}

func TDH2DKGAC(ctx context.Context, session Session, curve Curve, sidIn []byte, access *AccessStructure, quorumPartyIndices []int) ([]byte, [][]byte, []byte, []byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return cinterop.TDH2DKGAC(ctx, session, cgoCurve, sidIn, cgoAccess, quorumPartyIndices)
}

func TDH2Encrypt(publicKey []byte, plaintext []byte, label []byte) ([]byte, error) {
	return cinterop.TDH2Encrypt(publicKey, plaintext, label)
}

func TDH2Verify(publicKey []byte, ciphertext []byte, label []byte) error {
	return cinterop.TDH2Verify(publicKey, ciphertext, label)
}

func TDH2PartialDecrypt(privateShare []byte, ciphertext []byte, label []byte) ([]byte, error) {
	return cinterop.TDH2PartialDecrypt(privateShare, ciphertext, label)
}

func TDH2CombineAdditive(publicKey []byte, publicShares [][]byte, label []byte, partialDecryptions [][]byte, ciphertext []byte) ([]byte, error) {
	return cinterop.TDH2CombineAdditive(publicKey, publicShares, label, partialDecryptions, ciphertext)
}

func TDH2CombineAC(access *AccessStructure, publicKey []byte, partyNames []string, publicShares [][]byte, label []byte, partialPartyNames []string, partialDecryptions [][]byte, ciphertext []byte) ([]byte, error) {
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, err
	}
	return cinterop.TDH2CombineAC(cgoAccess, publicKey, partyNames, publicShares, label, partialPartyNames, partialDecryptions, ciphertext)
}

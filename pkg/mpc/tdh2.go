package mpc

import (
	"context"

	cinterop "github.com/coinbase/cb-mpc-go/internal/cgo"
)

// TDH2DKGAdditive performs multi-party distributed key generation for TDH2 threshold encryption with additive shares.
func TDH2DKGAdditive(ctx context.Context, session Session, curve Curve) ([]byte, [][]byte, []byte, []byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, nil, nil, nil, wrapPublicError("TDH2DKGAdditive", err)
	}
	publicKey, publicShares, privateShare, sidOut, err := cinterop.TDH2DKGAdditive(ctx, session, cgoCurve)
	return wrapResult4("TDH2DKGAdditive", publicKey, publicShares, privateShare, sidOut, err)
}

// TDH2DKGAC performs multi-party TDH2 DKG governed by an access-structure quorum policy.
func TDH2DKGAC(ctx context.Context, session Session, curve Curve, sidIn []byte, access *AccessStructure, quorumPartyIndices []int) ([]byte, [][]byte, []byte, []byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, nil, nil, nil, wrapPublicError("TDH2DKGAC", err)
	}
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, nil, nil, nil, wrapPublicError("TDH2DKGAC", err)
	}
	publicKey, publicShares, privateShare, sidOut, err := cinterop.TDH2DKGAC(ctx, session, cgoCurve, sidIn, cgoAccess, quorumPartyIndices)
	return wrapResult4("TDH2DKGAC", publicKey, publicShares, privateShare, sidOut, err)
}

// TDH2Encrypt encrypts plaintext under a TDH2 public key with the given label.
func TDH2Encrypt(publicKey []byte, plaintext []byte, label []byte) ([]byte, error) {
	ciphertext, err := cinterop.TDH2Encrypt(publicKey, plaintext, label)
	return wrapResult1("TDH2Encrypt", ciphertext, err)
}

// TDH2Verify checks the validity of a TDH2 ciphertext against a public key and label.
func TDH2Verify(publicKey []byte, ciphertext []byte, label []byte) error {
	err := cinterop.TDH2Verify(publicKey, ciphertext, label)
	return wrapPublicError("TDH2Verify", err)
}

// TDH2PartialDecrypt produces this party's partial decryption share for a TDH2 ciphertext.
func TDH2PartialDecrypt(privateShare []byte, ciphertext []byte, label []byte) ([]byte, error) {
	partialDecryption, err := cinterop.TDH2PartialDecrypt(privateShare, ciphertext, label)
	return wrapResult1("TDH2PartialDecrypt", partialDecryption, err)
}

// TDH2CombineAdditive combines partial decryptions from all parties (additive shares) to recover the plaintext.
func TDH2CombineAdditive(publicKey []byte, publicShares [][]byte, label []byte, partialDecryptions [][]byte, ciphertext []byte) ([]byte, error) {
	plaintext, err := cinterop.TDH2CombineAdditive(publicKey, publicShares, label, partialDecryptions, ciphertext)
	return wrapResult1("TDH2CombineAdditive", plaintext, err)
}

// TDH2CombineAC combines partial decryptions from a qualified quorum under an access-structure policy to recover the plaintext.
func TDH2CombineAC(access *AccessStructure, publicKey []byte, partyNames []string, publicShares [][]byte, label []byte, partialPartyNames []string, partialDecryptions [][]byte, ciphertext []byte) ([]byte, error) {
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, wrapPublicError("TDH2CombineAC", err)
	}
	plaintext, err := cinterop.TDH2CombineAC(cgoAccess, publicKey, partyNames, publicShares, label, partialPartyNames, partialDecryptions, ciphertext)
	return wrapResult1("TDH2CombineAC", plaintext, err)
}

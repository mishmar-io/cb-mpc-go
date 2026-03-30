package mpc

import (
	"context"

	cinterop "github.com/coinbase/cb-mpc-go/internal/cgo"
)

// ECDSA2PDKG performs two-party distributed key generation for ECDSA on the given curve.
func ECDSA2PDKG(ctx context.Context, session Session, curve Curve) ([]byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, wrapPublicError("ECDSA2PDKG", err)
	}
	keyBlob, err := cinterop.ECDSA2PDKG(ctx, session, cgoCurve)
	return wrapResult1("ECDSA2PDKG", keyBlob, err)
}

// ECDSA2PRefresh refreshes a two-party ECDSA key share without changing the joint public key.
func ECDSA2PRefresh(ctx context.Context, session Session, keyBlob []byte) ([]byte, error) {
	refreshedKeyBlob, err := cinterop.ECDSA2PRefresh(ctx, session, keyBlob)
	return wrapResult1("ECDSA2PRefresh", refreshedKeyBlob, err)
}

// ECDSA2PSign produces a two-party ECDSA signature over msgHash, returning a session ID and DER-encoded signature.
func ECDSA2PSign(ctx context.Context, session Session, keyBlob []byte, msgHash []byte, sidIn []byte) ([]byte, []byte, error) {
	sidOut, sigDER, err := cinterop.ECDSA2PSign(ctx, session, keyBlob, msgHash, sidIn)
	return wrapResult2("ECDSA2PSign", sidOut, sigDER, err)
}

// ECDSA2PGetPublicKeyCompressed extracts the compressed joint public key from a two-party ECDSA key blob.
func ECDSA2PGetPublicKeyCompressed(keyBlob []byte) ([]byte, error) {
	publicKey, err := cinterop.ECDSA2PGetPublicKeyCompressed(keyBlob)
	return wrapResult1("ECDSA2PGetPublicKeyCompressed", publicKey, err)
}

// ECDSA2PGetPublicShareCompressed extracts this party's compressed public share from a two-party ECDSA key blob.
func ECDSA2PGetPublicShareCompressed(keyBlob []byte) ([]byte, error) {
	publicShare, err := cinterop.ECDSA2PGetPublicShareCompressed(keyBlob)
	return wrapResult1("ECDSA2PGetPublicShareCompressed", publicShare, err)
}

// ECDSA2PDetachPrivateScalar splits a two-party ECDSA key blob into a public-only blob and a raw private scalar.
func ECDSA2PDetachPrivateScalar(keyBlob []byte) ([]byte, []byte, error) {
	publicKeyBlob, privateScalar, err := cinterop.ECDSA2PDetachPrivateScalar(keyBlob)
	return wrapResult2("ECDSA2PDetachPrivateScalar", publicKeyBlob, privateScalar, err)
}

// ECDSA2PAttachPrivateScalar re-assembles a two-party ECDSA key blob from a public blob, private scalar, and public share.
func ECDSA2PAttachPrivateScalar(publicKeyBlob []byte, privateScalar []byte, publicShareCompressed []byte) ([]byte, error) {
	keyBlob, err := cinterop.ECDSA2PAttachPrivateScalar(publicKeyBlob, privateScalar, publicShareCompressed)
	return wrapResult1("ECDSA2PAttachPrivateScalar", keyBlob, err)
}

// ECDSAMPDKGAdditive performs multi-party distributed key generation for ECDSA with additive shares.
func ECDSAMPDKGAdditive(ctx context.Context, session Session, curve Curve) ([]byte, []byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, nil, wrapPublicError("ECDSAMPDKGAdditive", err)
	}
	keyBlob, sidOut, err := cinterop.ECDSAMPDKGAdditive(ctx, session, cgoCurve)
	return wrapResult2("ECDSAMPDKGAdditive", keyBlob, sidOut, err)
}

// ECDSAMPDKGAC performs multi-party ECDSA DKG governed by an access-structure quorum policy.
func ECDSAMPDKGAC(ctx context.Context, session Session, curve Curve, sidIn []byte, access *AccessStructure, quorumPartyIndices []int) ([]byte, []byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, nil, wrapPublicError("ECDSAMPDKGAC", err)
	}
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, nil, wrapPublicError("ECDSAMPDKGAC", err)
	}
	acKeyBlob, sidOut, err := cinterop.ECDSAMPDKGAC(ctx, session, cgoCurve, sidIn, cgoAccess, quorumPartyIndices)
	return wrapResult2("ECDSAMPDKGAC", acKeyBlob, sidOut, err)
}

// ECDSAMPRefreshAdditive refreshes multi-party ECDSA additive key shares without changing the joint public key.
func ECDSAMPRefreshAdditive(ctx context.Context, session Session, sidIn []byte, keyBlob []byte) ([]byte, []byte, error) {
	sidOut, refreshedKeyBlob, err := cinterop.ECDSAMPRefreshAdditive(ctx, session, sidIn, keyBlob)
	return wrapResult2("ECDSAMPRefreshAdditive", sidOut, refreshedKeyBlob, err)
}

// ECDSAMPRefreshAC refreshes multi-party ECDSA key shares under an access-structure quorum policy.
func ECDSAMPRefreshAC(ctx context.Context, session Session, sidIn []byte, acKeyBlob []byte, access *AccessStructure, quorumPartyIndices []int) ([]byte, []byte, error) {
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, nil, wrapPublicError("ECDSAMPRefreshAC", err)
	}
	sidOut, refreshedKeyBlob, err := cinterop.ECDSAMPRefreshAC(ctx, session, sidIn, acKeyBlob, cgoAccess, quorumPartyIndices)
	return wrapResult2("ECDSAMPRefreshAC", sidOut, refreshedKeyBlob, err)
}

// ECDSAMPSignAdditive produces a multi-party ECDSA signature with additive shares; only sigReceiver gets the result.
func ECDSAMPSignAdditive(ctx context.Context, session Session, keyBlob []byte, msgHash []byte, sigReceiver int) ([]byte, error) {
	sigDER, err := cinterop.ECDSAMPSignAdditive(ctx, session, keyBlob, msgHash, sigReceiver)
	return wrapResult1("ECDSAMPSignAdditive", sigDER, err)
}

// ECDSAMPSignAC produces a multi-party ECDSA signature under an access-structure quorum policy.
func ECDSAMPSignAC(ctx context.Context, session Session, acKeyBlob []byte, access *AccessStructure, msgHash []byte, sigReceiver int) ([]byte, error) {
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, wrapPublicError("ECDSAMPSignAC", err)
	}
	sigDER, err := cinterop.ECDSAMPSignAC(ctx, session, acKeyBlob, cgoAccess, msgHash, sigReceiver)
	return wrapResult1("ECDSAMPSignAC", sigDER, err)
}

// ECDSAMPGetPublicKeyCompressed extracts the compressed joint public key from a multi-party ECDSA key blob.
func ECDSAMPGetPublicKeyCompressed(keyBlob []byte) ([]byte, error) {
	publicKey, err := cinterop.ECDSAMPGetPublicKeyCompressed(keyBlob)
	return wrapResult1("ECDSAMPGetPublicKeyCompressed", publicKey, err)
}

// ECDSAMPGetPublicShareCompressed extracts this party's compressed public share from a multi-party ECDSA key blob.
func ECDSAMPGetPublicShareCompressed(keyBlob []byte) ([]byte, error) {
	publicShare, err := cinterop.ECDSAMPGetPublicShareCompressed(keyBlob)
	return wrapResult1("ECDSAMPGetPublicShareCompressed", publicShare, err)
}

// ECDSAMPDetachPrivateScalar splits a multi-party ECDSA key blob into a public-only blob and a raw private scalar.
func ECDSAMPDetachPrivateScalar(keyBlob []byte) ([]byte, []byte, error) {
	publicKeyBlob, privateScalar, err := cinterop.ECDSAMPDetachPrivateScalar(keyBlob)
	return wrapResult2("ECDSAMPDetachPrivateScalar", publicKeyBlob, privateScalar, err)
}

// ECDSAMPAttachPrivateScalar re-assembles a multi-party ECDSA key blob from a public blob, private scalar, and public share.
func ECDSAMPAttachPrivateScalar(publicKeyBlob []byte, privateScalarFixed []byte, publicShareCompressed []byte) ([]byte, error) {
	keyBlob, err := cinterop.ECDSAMPAttachPrivateScalar(publicKeyBlob, privateScalarFixed, publicShareCompressed)
	return wrapResult1("ECDSAMPAttachPrivateScalar", keyBlob, err)
}

package mpc

import (
	"context"

	cinterop "github.com/coinbase/cb-mpc-go/internal/cgo"
)

// EdDSA2PDKG performs two-party distributed key generation for EdDSA on the given curve.
func EdDSA2PDKG(ctx context.Context, session Session, curve Curve) ([]byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, wrapPublicError("EdDSA2PDKG", err)
	}
	keyBlob, err := cinterop.EdDSA2PDKG(ctx, session, cgoCurve)
	return wrapResult1("EdDSA2PDKG", keyBlob, err)
}

// EdDSA2PRefresh refreshes a two-party EdDSA key share without changing the joint public key.
func EdDSA2PRefresh(ctx context.Context, session Session, keyBlob []byte) ([]byte, error) {
	refreshedKeyBlob, err := cinterop.EdDSA2PRefresh(ctx, session, keyBlob)
	return wrapResult1("EdDSA2PRefresh", refreshedKeyBlob, err)
}

// EdDSA2PSign produces a two-party EdDSA signature over msg.
func EdDSA2PSign(ctx context.Context, session Session, keyBlob []byte, msg []byte) ([]byte, error) {
	signature, err := cinterop.EdDSA2PSign(ctx, session, keyBlob, msg)
	return wrapResult1("EdDSA2PSign", signature, err)
}

// EdDSA2PGetPublicKeyCompressed extracts the compressed joint public key from a two-party EdDSA key blob.
func EdDSA2PGetPublicKeyCompressed(keyBlob []byte) ([]byte, error) {
	publicKey, err := cinterop.EdDSA2PGetPublicKeyCompressed(keyBlob)
	return wrapResult1("EdDSA2PGetPublicKeyCompressed", publicKey, err)
}

// EdDSA2PGetPublicShareCompressed extracts this party's compressed public share from a two-party EdDSA key blob.
func EdDSA2PGetPublicShareCompressed(keyBlob []byte) ([]byte, error) {
	publicShare, err := cinterop.EdDSA2PGetPublicShareCompressed(keyBlob)
	return wrapResult1("EdDSA2PGetPublicShareCompressed", publicShare, err)
}

// EdDSA2PDetachPrivateScalar splits a two-party EdDSA key blob into a public-only blob and a raw private scalar.
func EdDSA2PDetachPrivateScalar(keyBlob []byte) ([]byte, []byte, error) {
	publicKeyBlob, privateScalar, err := cinterop.EdDSA2PDetachPrivateScalar(keyBlob)
	return wrapResult2("EdDSA2PDetachPrivateScalar", publicKeyBlob, privateScalar, err)
}

// EdDSA2PAttachPrivateScalar re-assembles a two-party EdDSA key blob from a public blob, private scalar, and public share.
func EdDSA2PAttachPrivateScalar(publicKeyBlob []byte, privateScalarFixed []byte, publicShareCompressed []byte) ([]byte, error) {
	keyBlob, err := cinterop.EdDSA2PAttachPrivateScalar(publicKeyBlob, privateScalarFixed, publicShareCompressed)
	return wrapResult1("EdDSA2PAttachPrivateScalar", keyBlob, err)
}

// EdDSAMPDKGAdditive performs multi-party distributed key generation for EdDSA with additive shares.
func EdDSAMPDKGAdditive(ctx context.Context, session Session, curve Curve) ([]byte, []byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, nil, wrapPublicError("EdDSAMPDKGAdditive", err)
	}
	keyBlob, sidOut, err := cinterop.EdDSAMPDKGAdditive(ctx, session, cgoCurve)
	return wrapResult2("EdDSAMPDKGAdditive", keyBlob, sidOut, err)
}

// EdDSAMPDKGAC performs multi-party EdDSA DKG governed by an access-structure quorum policy.
func EdDSAMPDKGAC(ctx context.Context, session Session, curve Curve, sidIn []byte, access *AccessStructure, quorumPartyIndices []int) ([]byte, []byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, nil, wrapPublicError("EdDSAMPDKGAC", err)
	}
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, nil, wrapPublicError("EdDSAMPDKGAC", err)
	}
	acKeyBlob, sidOut, err := cinterop.EdDSAMPDKGAC(ctx, session, cgoCurve, sidIn, cgoAccess, quorumPartyIndices)
	return wrapResult2("EdDSAMPDKGAC", acKeyBlob, sidOut, err)
}

// EdDSAMPRefreshAdditive refreshes multi-party EdDSA additive key shares without changing the joint public key.
func EdDSAMPRefreshAdditive(ctx context.Context, session Session, sidIn []byte, keyBlob []byte) ([]byte, []byte, error) {
	sidOut, refreshedKeyBlob, err := cinterop.EdDSAMPRefreshAdditive(ctx, session, sidIn, keyBlob)
	return wrapResult2("EdDSAMPRefreshAdditive", sidOut, refreshedKeyBlob, err)
}

// EdDSAMPRefreshAC refreshes multi-party EdDSA key shares under an access-structure quorum policy.
func EdDSAMPRefreshAC(ctx context.Context, session Session, sidIn []byte, acKeyBlob []byte, access *AccessStructure, quorumPartyIndices []int) ([]byte, []byte, error) {
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, nil, wrapPublicError("EdDSAMPRefreshAC", err)
	}
	sidOut, refreshedKeyBlob, err := cinterop.EdDSAMPRefreshAC(ctx, session, sidIn, acKeyBlob, cgoAccess, quorumPartyIndices)
	return wrapResult2("EdDSAMPRefreshAC", sidOut, refreshedKeyBlob, err)
}

// EdDSAMPSignAdditive produces a multi-party EdDSA signature with additive shares; only sigReceiver gets the result.
func EdDSAMPSignAdditive(ctx context.Context, session Session, keyBlob []byte, msg []byte, sigReceiver int) ([]byte, error) {
	signature, err := cinterop.EdDSAMPSignAdditive(ctx, session, keyBlob, msg, sigReceiver)
	return wrapResult1("EdDSAMPSignAdditive", signature, err)
}

// EdDSAMPSignAC produces a multi-party EdDSA signature under an access-structure quorum policy.
func EdDSAMPSignAC(ctx context.Context, session Session, acKeyBlob []byte, access *AccessStructure, msg []byte, sigReceiver int) ([]byte, error) {
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, wrapPublicError("EdDSAMPSignAC", err)
	}
	signature, err := cinterop.EdDSAMPSignAC(ctx, session, acKeyBlob, cgoAccess, msg, sigReceiver)
	return wrapResult1("EdDSAMPSignAC", signature, err)
}

// EdDSAMPGetPublicKeyCompressed extracts the compressed joint public key from a multi-party EdDSA key blob.
func EdDSAMPGetPublicKeyCompressed(keyBlob []byte) ([]byte, error) {
	publicKey, err := cinterop.EdDSAMPGetPublicKeyCompressed(keyBlob)
	return wrapResult1("EdDSAMPGetPublicKeyCompressed", publicKey, err)
}

// EdDSAMPGetPublicShareCompressed extracts this party's compressed public share from a multi-party EdDSA key blob.
func EdDSAMPGetPublicShareCompressed(keyBlob []byte) ([]byte, error) {
	publicShare, err := cinterop.EdDSAMPGetPublicShareCompressed(keyBlob)
	return wrapResult1("EdDSAMPGetPublicShareCompressed", publicShare, err)
}

// EdDSAMPDetachPrivateScalar splits a multi-party EdDSA key blob into a public-only blob and a raw private scalar.
func EdDSAMPDetachPrivateScalar(keyBlob []byte) ([]byte, []byte, error) {
	publicKeyBlob, privateScalar, err := cinterop.EdDSAMPDetachPrivateScalar(keyBlob)
	return wrapResult2("EdDSAMPDetachPrivateScalar", publicKeyBlob, privateScalar, err)
}

// EdDSAMPAttachPrivateScalar re-assembles a multi-party EdDSA key blob from a public blob, private scalar, and public share.
func EdDSAMPAttachPrivateScalar(publicKeyBlob []byte, privateScalarFixed []byte, publicShareCompressed []byte) ([]byte, error) {
	keyBlob, err := cinterop.EdDSAMPAttachPrivateScalar(publicKeyBlob, privateScalarFixed, publicShareCompressed)
	return wrapResult1("EdDSAMPAttachPrivateScalar", keyBlob, err)
}

// Schnorr2PDKG performs two-party distributed key generation for Schnorr signatures on the given curve.
func Schnorr2PDKG(ctx context.Context, session Session, curve Curve) ([]byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, wrapPublicError("Schnorr2PDKG", err)
	}
	keyBlob, err := cinterop.Schnorr2PDKG(ctx, session, cgoCurve)
	return wrapResult1("Schnorr2PDKG", keyBlob, err)
}

// Schnorr2PRefresh refreshes a two-party Schnorr key share without changing the joint public key.
func Schnorr2PRefresh(ctx context.Context, session Session, keyBlob []byte) ([]byte, error) {
	refreshedKeyBlob, err := cinterop.Schnorr2PRefresh(ctx, session, keyBlob)
	return wrapResult1("Schnorr2PRefresh", refreshedKeyBlob, err)
}

// Schnorr2PSign produces a two-party Schnorr signature over msg.
func Schnorr2PSign(ctx context.Context, session Session, keyBlob []byte, msg []byte) ([]byte, error) {
	signature, err := cinterop.Schnorr2PSign(ctx, session, keyBlob, msg)
	return wrapResult1("Schnorr2PSign", signature, err)
}

// Schnorr2PGetPublicKeyCompressed extracts the compressed joint public key from a two-party Schnorr key blob.
func Schnorr2PGetPublicKeyCompressed(keyBlob []byte) ([]byte, error) {
	publicKey, err := cinterop.Schnorr2PGetPublicKeyCompressed(keyBlob)
	return wrapResult1("Schnorr2PGetPublicKeyCompressed", publicKey, err)
}

// Schnorr2PExtractPublicKeyXOnly extracts the x-only public key from a two-party Schnorr key blob.
func Schnorr2PExtractPublicKeyXOnly(keyBlob []byte) ([]byte, error) {
	publicKey, err := cinterop.Schnorr2PExtractPublicKeyXOnly(keyBlob)
	return wrapResult1("Schnorr2PExtractPublicKeyXOnly", publicKey, err)
}

// Schnorr2PGetPublicShareCompressed extracts this party's compressed public share from a two-party Schnorr key blob.
func Schnorr2PGetPublicShareCompressed(keyBlob []byte) ([]byte, error) {
	publicShare, err := cinterop.Schnorr2PGetPublicShareCompressed(keyBlob)
	return wrapResult1("Schnorr2PGetPublicShareCompressed", publicShare, err)
}

// Schnorr2PDetachPrivateScalar splits a two-party Schnorr key blob into a public-only blob and a raw private scalar.
func Schnorr2PDetachPrivateScalar(keyBlob []byte) ([]byte, []byte, error) {
	publicKeyBlob, privateScalar, err := cinterop.Schnorr2PDetachPrivateScalar(keyBlob)
	return wrapResult2("Schnorr2PDetachPrivateScalar", publicKeyBlob, privateScalar, err)
}

// Schnorr2PAttachPrivateScalar re-assembles a two-party Schnorr key blob from a public blob, private scalar, and public share.
func Schnorr2PAttachPrivateScalar(publicKeyBlob []byte, privateScalarFixed []byte, publicShareCompressed []byte) ([]byte, error) {
	keyBlob, err := cinterop.Schnorr2PAttachPrivateScalar(publicKeyBlob, privateScalarFixed, publicShareCompressed)
	return wrapResult1("Schnorr2PAttachPrivateScalar", keyBlob, err)
}

// SchnorrMPDKGAdditive performs multi-party distributed key generation for Schnorr with additive shares.
func SchnorrMPDKGAdditive(ctx context.Context, session Session, curve Curve) ([]byte, []byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, nil, wrapPublicError("SchnorrMPDKGAdditive", err)
	}
	keyBlob, sidOut, err := cinterop.SchnorrMPDKGAdditive(ctx, session, cgoCurve)
	return wrapResult2("SchnorrMPDKGAdditive", keyBlob, sidOut, err)
}

// SchnorrMPDKGAC performs multi-party Schnorr DKG governed by an access-structure quorum policy.
func SchnorrMPDKGAC(ctx context.Context, session Session, curve Curve, sidIn []byte, access *AccessStructure, quorumPartyIndices []int) ([]byte, []byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, nil, wrapPublicError("SchnorrMPDKGAC", err)
	}
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, nil, wrapPublicError("SchnorrMPDKGAC", err)
	}
	acKeyBlob, sidOut, err := cinterop.SchnorrMPDKGAC(ctx, session, cgoCurve, sidIn, cgoAccess, quorumPartyIndices)
	return wrapResult2("SchnorrMPDKGAC", acKeyBlob, sidOut, err)
}

// SchnorrMPRefreshAdditive refreshes multi-party Schnorr additive key shares without changing the joint public key.
func SchnorrMPRefreshAdditive(ctx context.Context, session Session, sidIn []byte, keyBlob []byte) ([]byte, []byte, error) {
	sidOut, refreshedKeyBlob, err := cinterop.SchnorrMPRefreshAdditive(ctx, session, sidIn, keyBlob)
	return wrapResult2("SchnorrMPRefreshAdditive", sidOut, refreshedKeyBlob, err)
}

// SchnorrMPRefreshAC refreshes multi-party Schnorr key shares under an access-structure quorum policy.
func SchnorrMPRefreshAC(ctx context.Context, session Session, sidIn []byte, acKeyBlob []byte, access *AccessStructure, quorumPartyIndices []int) ([]byte, []byte, error) {
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, nil, wrapPublicError("SchnorrMPRefreshAC", err)
	}
	sidOut, refreshedKeyBlob, err := cinterop.SchnorrMPRefreshAC(ctx, session, sidIn, acKeyBlob, cgoAccess, quorumPartyIndices)
	return wrapResult2("SchnorrMPRefreshAC", sidOut, refreshedKeyBlob, err)
}

// SchnorrMPSignAdditive produces a multi-party Schnorr signature with additive shares; only sigReceiver gets the result.
func SchnorrMPSignAdditive(ctx context.Context, session Session, keyBlob []byte, msg []byte, sigReceiver int) ([]byte, error) {
	signature, err := cinterop.SchnorrMPSignAdditive(ctx, session, keyBlob, msg, sigReceiver)
	return wrapResult1("SchnorrMPSignAdditive", signature, err)
}

// SchnorrMPSignAC produces a multi-party Schnorr signature under an access-structure quorum policy.
func SchnorrMPSignAC(ctx context.Context, session Session, acKeyBlob []byte, access *AccessStructure, msg []byte, sigReceiver int) ([]byte, error) {
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, wrapPublicError("SchnorrMPSignAC", err)
	}
	signature, err := cinterop.SchnorrMPSignAC(ctx, session, acKeyBlob, cgoAccess, msg, sigReceiver)
	return wrapResult1("SchnorrMPSignAC", signature, err)
}

// SchnorrMPGetPublicKeyCompressed extracts the compressed joint public key from a multi-party Schnorr key blob.
func SchnorrMPGetPublicKeyCompressed(keyBlob []byte) ([]byte, error) {
	publicKey, err := cinterop.SchnorrMPGetPublicKeyCompressed(keyBlob)
	return wrapResult1("SchnorrMPGetPublicKeyCompressed", publicKey, err)
}

// SchnorrMPExtractPublicKeyXOnly extracts the x-only public key from a multi-party Schnorr key blob.
func SchnorrMPExtractPublicKeyXOnly(keyBlob []byte) ([]byte, error) {
	publicKey, err := cinterop.SchnorrMPExtractPublicKeyXOnly(keyBlob)
	return wrapResult1("SchnorrMPExtractPublicKeyXOnly", publicKey, err)
}

// SchnorrMPGetPublicShareCompressed extracts this party's compressed public share from a multi-party Schnorr key blob.
func SchnorrMPGetPublicShareCompressed(keyBlob []byte) ([]byte, error) {
	publicShare, err := cinterop.SchnorrMPGetPublicShareCompressed(keyBlob)
	return wrapResult1("SchnorrMPGetPublicShareCompressed", publicShare, err)
}

// SchnorrMPDetachPrivateScalar splits a multi-party Schnorr key blob into a public-only blob and a raw private scalar.
func SchnorrMPDetachPrivateScalar(keyBlob []byte) ([]byte, []byte, error) {
	publicKeyBlob, privateScalar, err := cinterop.SchnorrMPDetachPrivateScalar(keyBlob)
	return wrapResult2("SchnorrMPDetachPrivateScalar", publicKeyBlob, privateScalar, err)
}

// SchnorrMPAttachPrivateScalar re-assembles a multi-party Schnorr key blob from a public blob, private scalar, and public share.
func SchnorrMPAttachPrivateScalar(publicKeyBlob []byte, privateScalarFixed []byte, publicShareCompressed []byte) ([]byte, error) {
	keyBlob, err := cinterop.SchnorrMPAttachPrivateScalar(publicKeyBlob, privateScalarFixed, publicShareCompressed)
	return wrapResult1("SchnorrMPAttachPrivateScalar", keyBlob, err)
}

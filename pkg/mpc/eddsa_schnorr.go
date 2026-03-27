package mpc

import (
	"context"

	cinterop "github.com/coinbase/cb-mpc-go/internal/cgo"
)

func EdDSA2PDKG(ctx context.Context, session Session, curve Curve) ([]byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, err
	}
	return cinterop.EdDSA2PDKG(ctx, session, cgoCurve)
}

func EdDSA2PRefresh(ctx context.Context, session Session, keyBlob []byte) ([]byte, error) {
	return cinterop.EdDSA2PRefresh(ctx, session, keyBlob)
}

func EdDSA2PSign(ctx context.Context, session Session, keyBlob []byte, msg []byte) ([]byte, error) {
	return cinterop.EdDSA2PSign(ctx, session, keyBlob, msg)
}

func EdDSA2PGetPublicKeyCompressed(keyBlob []byte) ([]byte, error) {
	return cinterop.EdDSA2PGetPublicKeyCompressed(keyBlob)
}

func EdDSA2PGetPublicShareCompressed(keyBlob []byte) ([]byte, error) {
	return cinterop.EdDSA2PGetPublicShareCompressed(keyBlob)
}

func EdDSA2PDetachPrivateScalar(keyBlob []byte) ([]byte, []byte, error) {
	return cinterop.EdDSA2PDetachPrivateScalar(keyBlob)
}

func EdDSA2PAttachPrivateScalar(publicKeyBlob []byte, privateScalarFixed []byte, publicShareCompressed []byte) ([]byte, error) {
	return cinterop.EdDSA2PAttachPrivateScalar(publicKeyBlob, privateScalarFixed, publicShareCompressed)
}

func EdDSAMPDKGAdditive(ctx context.Context, session Session, curve Curve) ([]byte, []byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, nil, err
	}
	return cinterop.EdDSAMPDKGAdditive(ctx, session, cgoCurve)
}

func EdDSAMPDKGAC(ctx context.Context, session Session, curve Curve, sidIn []byte, access *AccessStructure, quorumPartyIndices []int) ([]byte, []byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, nil, err
	}
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, nil, err
	}
	return cinterop.EdDSAMPDKGAC(ctx, session, cgoCurve, sidIn, cgoAccess, quorumPartyIndices)
}

func EdDSAMPRefreshAdditive(ctx context.Context, session Session, sidIn []byte, keyBlob []byte) ([]byte, []byte, error) {
	return cinterop.EdDSAMPRefreshAdditive(ctx, session, sidIn, keyBlob)
}

func EdDSAMPRefreshAC(ctx context.Context, session Session, sidIn []byte, acKeyBlob []byte, access *AccessStructure, quorumPartyIndices []int) ([]byte, []byte, error) {
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, nil, err
	}
	return cinterop.EdDSAMPRefreshAC(ctx, session, sidIn, acKeyBlob, cgoAccess, quorumPartyIndices)
}

func EdDSAMPSignAdditive(ctx context.Context, session Session, keyBlob []byte, msg []byte, sigReceiver int) ([]byte, error) {
	return cinterop.EdDSAMPSignAdditive(ctx, session, keyBlob, msg, sigReceiver)
}

func EdDSAMPSignAC(ctx context.Context, session Session, acKeyBlob []byte, access *AccessStructure, msg []byte, sigReceiver int) ([]byte, error) {
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, err
	}
	return cinterop.EdDSAMPSignAC(ctx, session, acKeyBlob, cgoAccess, msg, sigReceiver)
}

func EdDSAMPGetPublicKeyCompressed(keyBlob []byte) ([]byte, error) {
	return cinterop.EdDSAMPGetPublicKeyCompressed(keyBlob)
}

func EdDSAMPGetPublicShareCompressed(keyBlob []byte) ([]byte, error) {
	return cinterop.EdDSAMPGetPublicShareCompressed(keyBlob)
}

func EdDSAMPDetachPrivateScalar(keyBlob []byte) ([]byte, []byte, error) {
	return cinterop.EdDSAMPDetachPrivateScalar(keyBlob)
}

func EdDSAMPAttachPrivateScalar(publicKeyBlob []byte, privateScalarFixed []byte, publicShareCompressed []byte) ([]byte, error) {
	return cinterop.EdDSAMPAttachPrivateScalar(publicKeyBlob, privateScalarFixed, publicShareCompressed)
}

func Schnorr2PDKG(ctx context.Context, session Session, curve Curve) ([]byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, err
	}
	return cinterop.Schnorr2PDKG(ctx, session, cgoCurve)
}

func Schnorr2PRefresh(ctx context.Context, session Session, keyBlob []byte) ([]byte, error) {
	return cinterop.Schnorr2PRefresh(ctx, session, keyBlob)
}

func Schnorr2PSign(ctx context.Context, session Session, keyBlob []byte, msg []byte) ([]byte, error) {
	return cinterop.Schnorr2PSign(ctx, session, keyBlob, msg)
}

func Schnorr2PGetPublicKeyCompressed(keyBlob []byte) ([]byte, error) {
	return cinterop.Schnorr2PGetPublicKeyCompressed(keyBlob)
}

func Schnorr2PExtractPublicKeyXOnly(keyBlob []byte) ([]byte, error) {
	return cinterop.Schnorr2PExtractPublicKeyXOnly(keyBlob)
}

func Schnorr2PGetPublicShareCompressed(keyBlob []byte) ([]byte, error) {
	return cinterop.Schnorr2PGetPublicShareCompressed(keyBlob)
}

func Schnorr2PDetachPrivateScalar(keyBlob []byte) ([]byte, []byte, error) {
	return cinterop.Schnorr2PDetachPrivateScalar(keyBlob)
}

func Schnorr2PAttachPrivateScalar(publicKeyBlob []byte, privateScalarFixed []byte, publicShareCompressed []byte) ([]byte, error) {
	return cinterop.Schnorr2PAttachPrivateScalar(publicKeyBlob, privateScalarFixed, publicShareCompressed)
}

func SchnorrMPDKGAdditive(ctx context.Context, session Session, curve Curve) ([]byte, []byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, nil, err
	}
	return cinterop.SchnorrMPDKGAdditive(ctx, session, cgoCurve)
}

func SchnorrMPDKGAC(ctx context.Context, session Session, curve Curve, sidIn []byte, access *AccessStructure, quorumPartyIndices []int) ([]byte, []byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, nil, err
	}
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, nil, err
	}
	return cinterop.SchnorrMPDKGAC(ctx, session, cgoCurve, sidIn, cgoAccess, quorumPartyIndices)
}

func SchnorrMPRefreshAdditive(ctx context.Context, session Session, sidIn []byte, keyBlob []byte) ([]byte, []byte, error) {
	return cinterop.SchnorrMPRefreshAdditive(ctx, session, sidIn, keyBlob)
}

func SchnorrMPRefreshAC(ctx context.Context, session Session, sidIn []byte, acKeyBlob []byte, access *AccessStructure, quorumPartyIndices []int) ([]byte, []byte, error) {
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, nil, err
	}
	return cinterop.SchnorrMPRefreshAC(ctx, session, sidIn, acKeyBlob, cgoAccess, quorumPartyIndices)
}

func SchnorrMPSignAdditive(ctx context.Context, session Session, keyBlob []byte, msg []byte, sigReceiver int) ([]byte, error) {
	return cinterop.SchnorrMPSignAdditive(ctx, session, keyBlob, msg, sigReceiver)
}

func SchnorrMPSignAC(ctx context.Context, session Session, acKeyBlob []byte, access *AccessStructure, msg []byte, sigReceiver int) ([]byte, error) {
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, err
	}
	return cinterop.SchnorrMPSignAC(ctx, session, acKeyBlob, cgoAccess, msg, sigReceiver)
}

func SchnorrMPGetPublicKeyCompressed(keyBlob []byte) ([]byte, error) {
	return cinterop.SchnorrMPGetPublicKeyCompressed(keyBlob)
}

func SchnorrMPExtractPublicKeyXOnly(keyBlob []byte) ([]byte, error) {
	return cinterop.SchnorrMPExtractPublicKeyXOnly(keyBlob)
}

func SchnorrMPGetPublicShareCompressed(keyBlob []byte) ([]byte, error) {
	return cinterop.SchnorrMPGetPublicShareCompressed(keyBlob)
}

func SchnorrMPDetachPrivateScalar(keyBlob []byte) ([]byte, []byte, error) {
	return cinterop.SchnorrMPDetachPrivateScalar(keyBlob)
}

func SchnorrMPAttachPrivateScalar(publicKeyBlob []byte, privateScalarFixed []byte, publicShareCompressed []byte) ([]byte, error) {
	return cinterop.SchnorrMPAttachPrivateScalar(publicKeyBlob, privateScalarFixed, publicShareCompressed)
}

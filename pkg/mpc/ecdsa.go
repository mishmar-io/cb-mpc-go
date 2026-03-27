package mpc

import (
	"context"

	cinterop "github.com/coinbase/cb-mpc-go/internal/cgo"
)

func ECDSA2PDKG(ctx context.Context, session Session, curve Curve) ([]byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, err
	}
	return cinterop.ECDSA2PDKG(ctx, session, cgoCurve)
}

func ECDSA2PRefresh(ctx context.Context, session Session, keyBlob []byte) ([]byte, error) {
	return cinterop.ECDSA2PRefresh(ctx, session, keyBlob)
}

func ECDSA2PSign(ctx context.Context, session Session, keyBlob []byte, msgHash []byte, sidIn []byte) ([]byte, []byte, error) {
	return cinterop.ECDSA2PSign(ctx, session, keyBlob, msgHash, sidIn)
}

func ECDSA2PGetPublicKeyCompressed(keyBlob []byte) ([]byte, error) {
	return cinterop.ECDSA2PGetPublicKeyCompressed(keyBlob)
}

func ECDSA2PGetPublicShareCompressed(keyBlob []byte) ([]byte, error) {
	return cinterop.ECDSA2PGetPublicShareCompressed(keyBlob)
}

func ECDSA2PDetachPrivateScalar(keyBlob []byte) ([]byte, []byte, error) {
	return cinterop.ECDSA2PDetachPrivateScalar(keyBlob)
}

func ECDSA2PAttachPrivateScalar(publicKeyBlob []byte, privateScalar []byte, publicShareCompressed []byte) ([]byte, error) {
	return cinterop.ECDSA2PAttachPrivateScalar(publicKeyBlob, privateScalar, publicShareCompressed)
}

func ECDSAMPDKGAdditive(ctx context.Context, session Session, curve Curve) ([]byte, []byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, nil, err
	}
	return cinterop.ECDSAMPDKGAdditive(ctx, session, cgoCurve)
}

func ECDSAMPDKGAC(ctx context.Context, session Session, curve Curve, sidIn []byte, access *AccessStructure, quorumPartyIndices []int) ([]byte, []byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, nil, err
	}
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, nil, err
	}
	return cinterop.ECDSAMPDKGAC(ctx, session, cgoCurve, sidIn, cgoAccess, quorumPartyIndices)
}

func ECDSAMPRefreshAdditive(ctx context.Context, session Session, sidIn []byte, keyBlob []byte) ([]byte, []byte, error) {
	return cinterop.ECDSAMPRefreshAdditive(ctx, session, sidIn, keyBlob)
}

func ECDSAMPRefreshAC(ctx context.Context, session Session, sidIn []byte, acKeyBlob []byte, access *AccessStructure, quorumPartyIndices []int) ([]byte, []byte, error) {
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, nil, err
	}
	return cinterop.ECDSAMPRefreshAC(ctx, session, sidIn, acKeyBlob, cgoAccess, quorumPartyIndices)
}

func ECDSAMPSignAdditive(ctx context.Context, session Session, keyBlob []byte, msgHash []byte, sigReceiver int) ([]byte, error) {
	return cinterop.ECDSAMPSignAdditive(ctx, session, keyBlob, msgHash, sigReceiver)
}

func ECDSAMPSignAC(ctx context.Context, session Session, acKeyBlob []byte, access *AccessStructure, msgHash []byte, sigReceiver int) ([]byte, error) {
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, err
	}
	return cinterop.ECDSAMPSignAC(ctx, session, acKeyBlob, cgoAccess, msgHash, sigReceiver)
}

func ECDSAMPGetPublicKeyCompressed(keyBlob []byte) ([]byte, error) {
	return cinterop.ECDSAMPGetPublicKeyCompressed(keyBlob)
}

func ECDSAMPGetPublicShareCompressed(keyBlob []byte) ([]byte, error) {
	return cinterop.ECDSAMPGetPublicShareCompressed(keyBlob)
}

func ECDSAMPDetachPrivateScalar(keyBlob []byte) ([]byte, []byte, error) {
	return cinterop.ECDSAMPDetachPrivateScalar(keyBlob)
}

func ECDSAMPAttachPrivateScalar(publicKeyBlob []byte, privateScalarFixed []byte, publicShareCompressed []byte) ([]byte, error) {
	return cinterop.ECDSAMPAttachPrivateScalar(publicKeyBlob, privateScalarFixed, publicShareCompressed)
}

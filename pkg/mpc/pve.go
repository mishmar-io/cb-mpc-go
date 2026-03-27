package mpc

import cinterop "github.com/coinbase/cb-mpc-go/internal/cgo"

type (
	PVEBasePKECallbacks          = cinterop.PVEBasePKECallbacks
	PVERSAOAEPHSMDecapCallbacks  = cinterop.PVERSAOAEPHSMDecapCallbacks
	PVEECIESP256HSMECDHCallbacks = cinterop.PVEECIESP256HSMECDHCallbacks
	PVEBaseKEMCallbacks          = cinterop.PVEBaseKEMCallbacks
)

func PVEGenerateBasePKERSAKeypair() ([]byte, []byte, error) {
	return cinterop.PVEGenerateBasePKERSAKeypair()
}

func PVEGenerateBasePKEECIESP256Keypair() ([]byte, []byte, error) {
	return cinterop.PVEGenerateBasePKEECIESP256Keypair()
}

func PVEBasePKEECIESP256EKFromOCT(pubKeyOct []byte) ([]byte, error) {
	return cinterop.PVEBasePKEECIESP256EKFromOCT(pubKeyOct)
}

func PVEEncrypt(basePKE *PVEBasePKECallbacks, curve Curve, ek []byte, label []byte, x []byte) ([]byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, err
	}
	return cinterop.PVEEncrypt(basePKE, cgoCurve, ek, label, x)
}

func PVEVerify(basePKE *PVEBasePKECallbacks, curve Curve, ek []byte, ciphertext []byte, qCompressed []byte, label []byte) error {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return err
	}
	return cinterop.PVEVerify(basePKE, cgoCurve, ek, ciphertext, qCompressed, label)
}

func PVEDecrypt(basePKE *PVEBasePKECallbacks, curve Curve, dk []byte, ek []byte, ciphertext []byte, label []byte) ([]byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, err
	}
	return cinterop.PVEDecrypt(basePKE, cgoCurve, dk, ek, ciphertext, label)
}

func PVEDecryptRSAOAEPHSM(curve Curve, dkHandle []byte, ek []byte, ciphertext []byte, label []byte, callbacks *PVERSAOAEPHSMDecapCallbacks) ([]byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, err
	}
	return cinterop.PVEDecryptRSAOAEPHSM(cgoCurve, dkHandle, ek, ciphertext, label, callbacks)
}

func PVEDecryptECIESP256HSM(curve Curve, dkHandle []byte, ek []byte, ciphertext []byte, label []byte, callbacks *PVEECIESP256HSMECDHCallbacks) ([]byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, err
	}
	return cinterop.PVEDecryptECIESP256HSM(cgoCurve, dkHandle, ek, ciphertext, label, callbacks)
}

func PVEEncryptWithKEM(curve Curve, kemCallbacks *PVEBaseKEMCallbacks, ek []byte, label []byte, x []byte) ([]byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, err
	}
	return cinterop.PVEEncryptWithKEM(cgoCurve, kemCallbacks, ek, label, x)
}

func PVEVerifyWithKEM(curve Curve, kemCallbacks *PVEBaseKEMCallbacks, ek []byte, ciphertext []byte, qCompressed []byte, label []byte) error {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return err
	}
	return cinterop.PVEVerifyWithKEM(cgoCurve, kemCallbacks, ek, ciphertext, qCompressed, label)
}

func PVEDecryptWithKEM(curve Curve, kemCallbacks *PVEBaseKEMCallbacks, dk []byte, ek []byte, ciphertext []byte, label []byte) ([]byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, err
	}
	return cinterop.PVEDecryptWithKEM(cgoCurve, kemCallbacks, dk, ek, ciphertext, label)
}

func PVEGetQ(ciphertext []byte) ([]byte, error) {
	return cinterop.PVEGetQ(ciphertext)
}

func PVEGetLabel(ciphertext []byte) ([]byte, error) {
	return cinterop.PVEGetLabel(ciphertext)
}

func PVEBatchEncrypt(basePKE *PVEBasePKECallbacks, curve Curve, ek []byte, label []byte, xs [][]byte) ([]byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, err
	}
	return cinterop.PVEBatchEncrypt(basePKE, cgoCurve, ek, label, xs)
}

func PVEBatchVerify(basePKE *PVEBasePKECallbacks, curve Curve, ek []byte, ciphertext []byte, qsCompressed [][]byte, label []byte) error {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return err
	}
	return cinterop.PVEBatchVerify(basePKE, cgoCurve, ek, ciphertext, qsCompressed, label)
}

func PVEBatchDecrypt(basePKE *PVEBasePKECallbacks, curve Curve, dk []byte, ek []byte, ciphertext []byte, label []byte) ([][]byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, err
	}
	return cinterop.PVEBatchDecrypt(basePKE, cgoCurve, dk, ek, ciphertext, label)
}

func PVEBatchDecryptRSAOAEPHSM(curve Curve, dkHandle []byte, ek []byte, ciphertext []byte, label []byte, callbacks *PVERSAOAEPHSMDecapCallbacks) ([][]byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, err
	}
	return cinterop.PVEBatchDecryptRSAOAEPHSM(cgoCurve, dkHandle, ek, ciphertext, label, callbacks)
}

func PVEBatchDecryptECIESP256HSM(curve Curve, dkHandle []byte, ek []byte, ciphertext []byte, label []byte, callbacks *PVEECIESP256HSMECDHCallbacks) ([][]byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, err
	}
	return cinterop.PVEBatchDecryptECIESP256HSM(cgoCurve, dkHandle, ek, ciphertext, label, callbacks)
}

func PVEBatchGetCount(ciphertext []byte) (int, error) {
	return cinterop.PVEBatchGetCount(ciphertext)
}

func PVEBatchGetQs(ciphertext []byte) ([][]byte, error) {
	return cinterop.PVEBatchGetQs(ciphertext)
}

func PVEBatchGetLabel(ciphertext []byte) ([]byte, error) {
	return cinterop.PVEBatchGetLabel(ciphertext)
}

func PVEACEncrypt(basePKE *PVEBasePKECallbacks, curve Curve, access *AccessStructure, leafNames []string, leafEKs [][]byte, label []byte, xs [][]byte) ([]byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, err
	}
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, err
	}
	return cinterop.PVEACEncrypt(basePKE, cgoCurve, cgoAccess, leafNames, leafEKs, label, xs)
}

func PVEACVerify(basePKE *PVEBasePKECallbacks, curve Curve, access *AccessStructure, leafNames []string, leafEKs [][]byte, ciphertext []byte, qsCompressed [][]byte, label []byte) error {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return err
	}
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return err
	}
	return cinterop.PVEACVerify(basePKE, cgoCurve, cgoAccess, leafNames, leafEKs, ciphertext, qsCompressed, label)
}

func PVEACPartyDecryptRow(basePKE *PVEBasePKECallbacks, curve Curve, access *AccessStructure, ciphertext []byte, rowIndex int, leafName string, dk []byte, label []byte) ([]byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, err
	}
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, err
	}
	return cinterop.PVEACPartyDecryptRow(basePKE, cgoCurve, cgoAccess, ciphertext, rowIndex, leafName, dk, label)
}

func PVEACPartyDecryptRowRSAOAEPHSM(curve Curve, access *AccessStructure, ciphertext []byte, rowIndex int, leafName string, dkHandle []byte, ek []byte, label []byte, callbacks *PVERSAOAEPHSMDecapCallbacks) ([]byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, err
	}
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, err
	}
	return cinterop.PVEACPartyDecryptRowRSAOAEPHSM(cgoCurve, cgoAccess, ciphertext, rowIndex, leafName, dkHandle, ek, label, callbacks)
}

func PVEACPartyDecryptRowECIESP256HSM(curve Curve, access *AccessStructure, ciphertext []byte, rowIndex int, leafName string, dkHandle []byte, ek []byte, label []byte, callbacks *PVEECIESP256HSMECDHCallbacks) ([]byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, err
	}
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, err
	}
	return cinterop.PVEACPartyDecryptRowECIESP256HSM(cgoCurve, cgoAccess, ciphertext, rowIndex, leafName, dkHandle, ek, label, callbacks)
}

func PVEACAggregateToRestoreRow(basePKE *PVEBasePKECallbacks, curve Curve, access *AccessStructure, quorumLeafNames []string, quorumShares [][]byte, ciphertext []byte, rowIndex int, label []byte) ([][]byte, error) {
	cgoCurve, err := toCGOCurve(curve)
	if err != nil {
		return nil, err
	}
	cgoAccess, err := toCGOAccessStructure(access)
	if err != nil {
		return nil, err
	}
	return cinterop.PVEACAggregateToRestoreRow(basePKE, cgoCurve, cgoAccess, quorumLeafNames, quorumShares, ciphertext, rowIndex, label)
}

func PVEACGetCount(ciphertext []byte) (int, error) {
	return cinterop.PVEACGetCount(ciphertext)
}

func PVEACGetQs(ciphertext []byte) ([][]byte, error) {
	return cinterop.PVEACGetQs(ciphertext)
}

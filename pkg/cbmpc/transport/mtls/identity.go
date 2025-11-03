package mtls

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
)

// certHasSANName returns true if the certificate contains the provided name
// in its DNS SAN entries. CN is intentionally ignored.
func certHasSANName(cert *x509.Certificate, name string) bool {
	for _, dns := range cert.DNSNames {
		if dns == name {
			return true
		}
	}
	return false
}

func verifyPeerIdentity(cert *x509.Certificate, expectedName string, spkiPin []byte, custom func(*x509.Certificate, string) error) error {
	if cert == nil {
		return errors.New("mtls: nil certificate")
	}
	if expectedName == "" {
		return errors.New("mtls: empty expected peer name")
	}
	if !certHasSANName(cert, expectedName) {
		return fmt.Errorf("mtls: peer certificate SAN mismatch: expected %q", expectedName)
	}
	if len(spkiPin) > 0 {
		h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		if !bytes.Equal(spkiPin, h[:]) {
			return errors.New("mtls: SPKI pin mismatch")
		}
	}
	if custom != nil {
		if err := custom(cert, expectedName); err != nil {
			return err
		}
	}
	return nil
}

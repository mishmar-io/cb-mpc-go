package mpc

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/coinbase/cb-mpc-go/pkg/mpctest"
)

func TestHelperAPIs(t *testing.T) {
	t.Run("zeroize", func(t *testing.T) {
		b := []byte{0x01, 0x02, 0x03}
		Zeroize(b)
		if !bytes.Equal(b, []byte{0x00, 0x00, 0x00}) {
			t.Fatalf("Zeroize did not clear bytes: got=%x", b)
		}
	})

	t.Run("zeroize slices", func(t *testing.T) {
		slices := [][]byte{
			{0x01, 0x02},
			nil,
			{0x03, 0x04, 0x05},
		}
		ZeroizeSlices(slices)
		if !bytes.Equal(slices[0], []byte{0x00, 0x00}) {
			t.Fatalf("ZeroizeSlices did not clear first slice: got=%x", slices[0])
		}
		if slices[1] != nil {
			t.Fatalf("ZeroizeSlices unexpectedly modified nil slice")
		}
		if !bytes.Equal(slices[2], []byte{0x00, 0x00, 0x00}) {
			t.Fatalf("ZeroizeSlices did not clear third slice: got=%x", slices[2])
		}
	})

	t.Run("sensitive bytes", func(t *testing.T) {
		buf := []byte{0xAA, 0xBB, 0xCC}
		sensitive := SensitiveBytes(Sensitive(buf))
		if !bytes.Equal(sensitive.Bytes(), buf) {
			t.Fatalf("Sensitive.Bytes mismatch: got=%x want=%x", sensitive.Bytes(), buf)
		}
		if got := fmt.Sprintf("%v", sensitive); got != "<sensitive>" {
			t.Fatalf("Sensitive formatting leaked content: got=%q", got)
		}
		if err := sensitive.Close(); err != nil {
			t.Fatalf("Sensitive.Close returned error: %v", err)
		}
		if !bytes.Equal(buf, []byte{0x00, 0x00, 0x00}) {
			t.Fatalf("Sensitive.Close did not clear backing bytes: got=%x", buf)
		}
	})

	t.Run("sensitive byte slices", func(t *testing.T) {
		bufs := [][]byte{
			{0x10, 0x20},
			{0x30, 0x40, 0x50},
		}
		sensitive := SensitiveByteSlices(SensitiveSlices(bufs))
		if got, want := sensitive.Bytes(), bufs; len(got) != len(want) {
			t.Fatalf("SensitiveSlices.Bytes length mismatch: got=%d want=%d", len(got), len(want))
		}
		if got := fmt.Sprintf("%#v", sensitive); got != "<sensitive>" {
			t.Fatalf("SensitiveSlices formatting leaked content: got=%q", got)
		}
		if err := sensitive.Close(); err != nil {
			t.Fatalf("SensitiveSlices.Close returned error: %v", err)
		}
		if !bytes.Equal(bufs[0], []byte{0x00, 0x00}) {
			t.Fatalf("SensitiveSlices.Close did not clear first slice: got=%x", bufs[0])
		}
		if !bytes.Equal(bufs[1], []byte{0x00, 0x00, 0x00}) {
			t.Fatalf("SensitiveSlices.Close did not clear second slice: got=%x", bufs[1])
		}
	})

	t.Run("curve string", func(t *testing.T) {
		nodeType := AccessStructureNodeType(AccessNodeThreshold)
		if nodeType != AccessNodeThreshold {
			t.Fatalf("AccessStructureNodeType assignment mismatch: got=%v want=%v", nodeType, AccessNodeThreshold)
		}
		tests := []struct {
			curve Curve
			want  string
		}{
			{curve: CurveP256, want: "p256"},
			{curve: CurveSecp256k1, want: "secp256k1"},
			{curve: CurveEd25519, want: "ed25519"},
			{curve: Curve(99), want: "unknown(99)"},
		}
		for _, tc := range tests {
			if got := tc.curve.String(); got != tc.want {
				t.Fatalf("Curve.String mismatch for %d: got=%q want=%q", tc.curve, got, tc.want)
			}
		}
	})

	t.Run("error wrapper", func(t *testing.T) {
		wrapped := &Error{
			Op:  "sign",
			Err: ErrInvalidParameter,
		}
		if got, want := wrapped.Error(), "mpc.sign: "+ErrInvalidParameter.Error(); got != want {
			t.Fatalf("Error() mismatch: got=%q want=%q", got, want)
		}
		if !errors.Is(wrapped, ErrInvalidParameter) {
			t.Fatalf("Error.Unwrap did not expose underlying sentinel")
		}
		for _, err := range []error{
			ErrInvalidParameter,
			ErrInvalidData,
			ErrNetworkFailure,
			ErrProtocolFailure,
			ErrInvalidSignature,
			ErrInvalidKeyShare,
			ErrSessionClosed,
		} {
			if err == nil {
				t.Fatal("expected exported sentinel error to be non-nil")
			}
		}
	})

	t.Run("session interface methods", func(t *testing.T) {
		sessions := mpctest.NewMockNetwork(2)
		var session Session = sessions[1]
		if got, want := session.MyIndex(), 1; got != want {
			t.Fatalf("Session.MyIndex mismatch: got=%d want=%d", got, want)
		}
		if got, want := session.PartyCount(), 2; got != want {
			t.Fatalf("Session.PartyCount mismatch: got=%d want=%d", got, want)
		}
		if err := session.Close(); err != nil {
			t.Fatalf("Session.Close returned error: %v", err)
		}
		_ = sessions[0].Close()
	})
}

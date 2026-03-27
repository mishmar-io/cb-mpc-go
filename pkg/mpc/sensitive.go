package mpc

import (
	"fmt"
)

// SensitiveBytes is a best-effort wrapper for secret byte slices.
//
// It implements io.Closer via Close(), which overwrites the backing array with
// zeros. It also implements fmt.Formatter to avoid accidental logging via fmt
// (prints "<sensitive>" for all verbs).
//
// Notes:
//   - This cannot prevent callers from copying the data (e.g., via append or
//     string conversion).
//   - It is still safe and useful to call Close() multiple times.
type SensitiveBytes []byte

func Sensitive(b []byte) SensitiveBytes { return SensitiveBytes(b) }

func (s SensitiveBytes) Bytes() []byte { return []byte(s) }

func (s SensitiveBytes) Close() error {
	Zeroize([]byte(s))
	return nil
}

func (s SensitiveBytes) Format(state fmt.State, verb rune) {
	_, _ = state.Write([]byte("<sensitive>"))
}

// SensitiveByteSlices is a best-effort wrapper for secret byte-slice lists.
// See SensitiveBytes for caveats.
type SensitiveByteSlices [][]byte

func SensitiveSlices(bs [][]byte) SensitiveByteSlices { return SensitiveByteSlices(bs) }

func (s SensitiveByteSlices) Bytes() [][]byte { return [][]byte(s) }

func (s SensitiveByteSlices) Close() error {
	ZeroizeSlices([][]byte(s))
	return nil
}

func (s SensitiveByteSlices) Format(state fmt.State, verb rune) {
	_, _ = state.Write([]byte("<sensitive>"))
}

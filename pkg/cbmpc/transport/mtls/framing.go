package mtls

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

func writeFrame(conn net.Conn, timeout time.Duration, payload []byte, maxLen int) error {
	// Ensure header length encoding remains within 32-bit range.
	const maxUint32 = 1<<32 - 1
	if len(payload) > maxUint32 {
		return fmt.Errorf("mtls: frame too large for 32-bit header (%d bytes)", len(payload))
	}
	if maxLen > 0 && len(payload) > maxLen {
		return fmt.Errorf("mtls: frame too large (%d bytes)", len(payload))
	}
	if timeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload))) // #nosec G115 -- len checked to fit in 32 bits above
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := conn.Write(payload)
	return err
}

func readFrame(conn net.Conn, timeout time.Duration, maxLen int) ([]byte, error) {
	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	}
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(lenBuf[:]))
	if n < 0 {
		return nil, fmt.Errorf("mtls: negative frame length")
	}
	if maxLen > 0 && n > maxLen {
		return nil, fmt.Errorf("mtls: frame too large (%d bytes)", n)
	}
	if n == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

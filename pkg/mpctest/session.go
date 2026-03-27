package mpctest

import (
	"context"
	"io"
)

// Session mirrors the transport contract used by interactive MPC protocols.
// Concrete types in this package also satisfy `mpc.Session`.
type Session interface {
	io.Closer
	Send(ctx context.Context, toParty int, msg []byte) error
	Receive(ctx context.Context, fromParty int) ([]byte, error)
	ReceiveAll(ctx context.Context, fromParties []int) ([][]byte, error)
	MyIndex() int
	PartyCount() int
}

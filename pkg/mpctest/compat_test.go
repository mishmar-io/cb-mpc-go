package mpctest_test

import (
	"github.com/mishmar-io/cb-mpc-go/pkg/mpc"
	"github.com/mishmar-io/cb-mpc-go/pkg/mpctest"
)

var (
	_ mpc.Transport = (*mpctest.MockTransport)(nil)
	_ mpc.Transport = (*mpctest.MaliciousTransport)(nil)
)

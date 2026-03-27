package mpctest_test

import (
	"github.com/coinbase/cb-mpc-go/pkg/mpc"
	"github.com/coinbase/cb-mpc-go/pkg/mpctest"
)

var (
	_ mpc.Session = (*mpctest.MockSession)(nil)
	_ mpc.Session = (*mpctest.MaliciousSession)(nil)
)

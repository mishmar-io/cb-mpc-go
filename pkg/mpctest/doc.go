// Package mpctest provides insecure Session helpers for tests and local demos.
//
// WARNING: This package is not a production transport. The in-memory helpers
// provide no authentication, no confidentiality, and no cross-process
// networking. Production applications should implement `mpc.Session` with an
// authenticated and confidential transport such as mTLS.
package mpctest

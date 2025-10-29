// Package jobptr allows internal protocol packages to obtain the opaque native
// job pointer from job handles without exposing this capability to external
// library users. The cbmpc package wires up a getter during init.
package jobptr

import "unsafe"

// Get is initialized by package cbmpc to retrieve the opaque native job pointer
// from job handles. It is intentionally not set outside cbmpc.
var Get func(any) (unsafe.Pointer, error)

// Ptr returns the opaque native job pointer for internal protocol packages.
// Do not use outside internal packages.
func Ptr(j any) (unsafe.Pointer, error) {
	if Get == nil {
		panic("jobptr.Get not initialized")
	}
	return Get(j)
}

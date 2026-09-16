//go:build !unix

package upgrade

// Privileged helpers are rejected before file activation on non-Unix hosts.
func helperOwnerID() int { return 0 }

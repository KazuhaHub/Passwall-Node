//go:build !unix

package policylive

// reserve has no cross-process reservation off unix: the free check alone.
func reserve(int) bool { return true }

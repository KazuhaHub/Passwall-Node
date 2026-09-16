//go:build !linux

package upgrade

import "os"

// RunDockerHelper rejects non-Linux hosts before ownership validation. Tests
// exercise the transaction controller without preparing privileged paths.
func dockerFileOwner(os.FileInfo) (uint32, uint32, bool) { return 0, 0, false }

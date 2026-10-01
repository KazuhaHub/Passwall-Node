//go:build !linux

package upgrade

import "errors"

// readSelfMountinfo has no source outside Linux. RunDockerHelper refuses other
// hosts before it gets here; tests substitute dockerHelperOptions.Mountinfo.
func readSelfMountinfo() (string, error) {
	return "", errors.New("self-identity needs /proc/self/mountinfo")
}

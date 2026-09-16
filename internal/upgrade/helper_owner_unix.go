//go:build unix

package upgrade

import "os"

func helperOwnerID() int { return os.Geteuid() }

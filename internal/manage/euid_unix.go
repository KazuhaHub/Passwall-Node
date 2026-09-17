//go:build !windows

package manage

import "os"

func effectiveUID() int { return os.Geteuid() }

//go:build !linux && !darwin

package agent

import (
	"fmt"
	"runtime"
	"time"
)

// No generic time.Now fallback: Go monotonic readings need not include sleep.
// Windows interrupt time includes an estimated sleep bias; typical timer
// resolution is not a hard error bound. Unverified platforms remain task-clock
// unavailable, not core-down.
func readTaskElapsed() (time.Duration, error) {
	return 0, fmt.Errorf("verified suspend-inclusive task clock is unsupported on %s", runtime.GOOS)
}

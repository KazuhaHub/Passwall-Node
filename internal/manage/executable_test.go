package manage

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestInstallSkeletonDefaultInspectionRefusesNonExecutableBinary(t *testing.T) {
	a, _, _ := newTestApp(t, "")
	a.executable = newApp(strings.NewReader(""), io.Discard, io.Discard).executable
	if err := os.Chmod(a.paths.binary, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := a.validateInstallSkeleton(); err == nil || !strings.Contains(err.Error(), "not executable") {
		t.Fatal("default installation inspection must retain the POSIX executable requirement")
	}
}

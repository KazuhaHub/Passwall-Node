//go:build !windows

package main

import (
	"os"
	"testing"
)

func assertPrivateAcceptanceFile(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != mode {
		t.Fatalf("acceptance file must have mode %o", mode)
	}
}

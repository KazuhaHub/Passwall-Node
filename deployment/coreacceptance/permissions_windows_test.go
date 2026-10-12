package main

import (
	"os"
	"testing"

	"github.com/KazuhaHub/passwall-node/v4/internal/privatefs"
)

func assertPrivateAcceptanceFile(t *testing.T, path string, _ os.FileMode) {
	t.Helper()
	if err := privatefs.Check(path, false); err != nil {
		t.Fatal("acceptance file must have a private Windows ACL")
	}
}

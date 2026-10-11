//go:build !windows

package manage

import (
	"os"
	"testing"
)

func assertPrivateCredentialFixture(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("credential must have mode 0600")
	}
}

func makeUnwritableDirectoryFixture(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o700) })
}

func makeSharedCredentialFixture(_ *testing.T, _ string) {}

func fixtureExecutable(info os.FileInfo) bool { return info.Mode()&0o111 != 0 }

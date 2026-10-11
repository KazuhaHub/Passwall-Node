package upgrade

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/KazuhaHub/passwall-node/v4/internal/privatefs"
	"golang.org/x/sys/windows"
)

func makeSharedUpgradeRootFixture(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal("build shared owned fixture descriptor")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal("build shared owned fixture ACL")
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal("set shared owned fixture ACL")
	}
	runtime.KeepAlive(sd)
	if privatefs.Check(path, true) == nil {
		t.Fatal("shared fixture must actually grant ordinary identities access")
	}
}

func TestWindowsDocumentReplacementPreservesOldBytesOnFailureAndCleansTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	name := "receipt.json"
	path := filepath.Join(dir, name)
	if err := AtomicDocument(dir, name, map[string]int{"version": 1}, 0o600); err != nil {
		t.Fatal("write first document")
	}
	h, err := privatefs.Open(path, false)
	if err != nil {
		t.Fatal("pin owned target fixture")
	}
	if err := AtomicDocument(dir, name, map[string]int{"version": 2}, 0o600); err == nil {
		_ = windows.CloseHandle(h)
		t.Fatal("replacement must fail while target denies delete sharing")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != `{"version":1}` {
		_ = windows.CloseHandle(h)
		t.Fatal("failed replacement must preserve prior document bytes")
	}
	if err := windows.CloseHandle(h); err != nil {
		t.Fatal("release owned target fixture")
	}
	if err := AtomicDocument(dir, name, map[string]int{"version": 2}, 0o600); err != nil {
		t.Fatal("replace released document")
	}
	var got map[string]int
	if err := ReadDocument(dir, name, &got); err != nil || got["version"] != 2 || privatefs.Check(path, false) != nil {
		t.Fatal("replacement must be complete, readable and private")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != name {
		t.Fatal("both successful and failed writes must clean temporary files")
	}
}

func TestWindowsDocumentsRefuseSharedDirectoriesBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	makeSharedUpgradeRootFixture(t, dir)
	if err := AtomicDocument(dir, "receipt.json", map[string]int{"version": 1}, 0o600); err == nil {
		t.Fatal("shared document directory must be refused before writing")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("shared directory refusal must not create or publish a document")
	}
}

package deployment

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBuildProvenanceGateRejectsWrongArtifacts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX gate; release inspection runs on Linux")
	}
	mod, err := os.ReadFile("../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	var compiler string
	for _, line := range strings.Split(string(mod), "\n") {
		if value, ok := strings.CutPrefix(line, "toolchain "); ok {
			compiler = value
		}
	}
	clean := "binary: " + compiler + "\n\tpath\tgithub.com/KazuhaHub/passwall-node/cmd/node\n\tbuild\tGOOS=linux\n\tbuild\tGOARCH=arm64\n\tbuild\tCGO_ENABLED=0\n\tbuild\tvcs.revision=abc123\n\tbuild\tvcs.modified=false\n"
	for _, test := range []struct {
		name, info string
		valid      bool
	}{
		{"correct", clean, true},
		{"old-compiler", strings.Replace(clean, compiler, "go1.25.0", 1), false},
		{"wrong-platform", strings.Replace(clean, "GOOS=linux", "GOOS=darwin", 1), false},
		{"wrong-architecture", strings.Replace(clean, "GOARCH=arm64", "GOARCH=amd64", 1), false},
		{"wrong-commit", strings.Replace(clean, "revision=abc123", "revision=def456", 1), false},
		{"dirty-source", strings.Replace(clean, "modified=false", "modified=true", 1), false},
		{"missing-source-proof", strings.Replace(clean, "\tbuild\tvcs.modified=false\n", "", 1), false},
		{"cgo", strings.Replace(clean, "CGO_ENABLED=0", "CGO_ENABLED=1", 1), false},
		{"wrong-command", strings.Replace(clean, "/cmd/node", "/cmd/contract-agent", 1), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "go"), []byte("#!/bin/sh\nprintf '%s' '"+test.info+"'\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("sh", "deployment/check-build.sh", "binary", "linux", "arm64", "abc123")
			cmd.Dir = ".."
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			out, err := cmd.CombinedOutput()
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v err=%v output=%s", test.valid, err, out)
			}
		})
	}
}

package deployment

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Keep the source-build image aligned with the CI compiler (go.mod's
// preferred toolchain), and both container paths on the same patched base.
func TestBuildBaselinesStayAligned(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		b, err := os.ReadFile("../" + path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	mod := read("go.mod")
	toolchain := regexp.MustCompile(`(?m)^toolchain go(\d+\.\d+\.\d+)$`).FindStringSubmatch(mod)
	if len(toolchain) != 2 {
		t.Fatal("go.mod must name one exact preferred build toolchain")
	}
	source, release := read("Dockerfile"), read("Dockerfile.release")
	if !strings.Contains(source, "FROM golang:"+toolchain[1]+"-alpine") {
		t.Fatal("source-build compiler disagrees with go.mod toolchain")
	}
	basePattern := regexp.MustCompile(`(?m)^FROM alpine:(\d+\.\d+\.\d+)$`)
	base, releaseBase := basePattern.FindAllStringSubmatch(source, -1), basePattern.FindAllStringSubmatch(release, -1)
	if len(base) != 1 || len(releaseBase) != 1 || base[0][1] != releaseBase[0][1] {
		t.Fatal("source and release images must share one exact patched runtime base")
	}
	for _, path := range []string{".github/workflows/test.yml", ".github/workflows/release.yml"} {
		workflow := read(path)
		if !strings.Contains(workflow, "go-version-file: go.mod") || !strings.Contains(workflow, `GOTOOLCHAIN: "local"`) || !strings.Contains(workflow, "deployment/check-build.sh") {
			t.Fatalf("%s must select and inspect the pinned compiler without auto-upgrading", path)
		}
	}
}

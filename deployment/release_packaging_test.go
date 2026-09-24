package deployment

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// THE RELEASE'S ARCHIVES ARE A FUNCTION OF THE COMMIT, like the binaries in them.
//
// The publishing action makes a release public before its assets upload and, with
// overwrite_files off, keeps whatever an earlier attempt uploaded. So a re-run of
// the release job after a failed upload packages again, and if packaging were not
// deterministic the signed manifest it writes would describe archives other than
// the ones already beside it. The step is RUN here twice, a second apart, under
// different umasks, from fresh directories, and the two dist/ trees must be the
// same bytes; then the bytes are read for what made them differ before.
func TestTheReleasePackagingIsReproducible(t *testing.T) {
	if _, err := exec.LookPath("zip"); err != nil {
		t.Skip("zip packages the Windows archives")
	}
	raw, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	script := extractStepScript(t, workflowJob(t, string(raw), "release"), "      - name: Package archives and checksums\n")
	// An even second: zip keeps two-second resolution.
	committed := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	const version = "4.0.99.1"

	pack := func(t *testing.T, umask string) map[string][]byte {
		t.Helper()
		work := t.TempDir()
		write := func(name string, mode os.FileMode) {
			t.Helper()
			path := filepath.Join(work, name)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(name+"\n"), mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
		}
		// What the checkout holds, with git's modes.
		for name, mode := range map[string]os.FileMode{
			"LICENSE": 0o644, "NOTICE": 0o644, "README.md": 0o644, "HANDOFF.md": 0o644,
			"compose.example.yaml": 0o644, "install.sh": 0o755, "deployment/install.sh": 0o644,
		} {
			write(name, mode)
		}
		env := append(os.Environ(),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.test",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.test",
			"GIT_AUTHOR_DATE="+committed.Format(time.RFC3339),
			"GIT_COMMITTER_DATE="+committed.Format(time.RFC3339),
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		)
		for _, args := range [][]string{{"init", "--quiet"}, {"add", "."}, {"commit", "--quiet", "-m", "release"}} {
			cmd := exec.Command("git", args...)
			cmd.Dir, cmd.Env = work, env
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v\n%s", args, err, out)
			}
		}
		// And the six binaries as a download leaves them: no executable bit.
		for _, platform := range []string{"linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64", "windows-amd64", "windows-arm64"} {
			ext := ""
			if strings.HasPrefix(platform, "windows") {
				ext = ".exe"
			}
			write(filepath.Join("artifacts", "passwall-node-"+platform, "passwall-node"+ext), 0o644)
		}
		// publish-core-catalog has tests of its own; here it writes a fixed
		// document where it is told to.
		bin := filepath.Join(t.TempDir(), "bin")
		if err := os.Mkdir(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		goStub := "#!/bin/sh\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = -output ]; then printf '{}\\n' > \"$2\"; exit 0; fi\n  shift\ndone\nexit 1\n"
		if err := os.WriteFile(filepath.Join(bin, "go"), []byte(goStub), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", "-c", "umask "+umask+"\n"+script)
		cmd.Dir = work
		cmd.Env = append(env, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "VERSION="+version)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("packaging under umask %s: %v\n%s", umask, err, out)
		}
		dist := map[string][]byte{}
		entries, err := os.ReadDir(filepath.Join(work, "dist"))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			data, err := os.ReadFile(filepath.Join(work, "dist", entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			dist[entry.Name()] = data
		}
		return dist
	}

	first := pack(t, "022")
	// A later second, so a copy time or a compressor's clock would differ.
	for start := time.Now().Unix(); time.Now().Unix() == start; {
		time.Sleep(20 * time.Millisecond)
	}
	second := pack(t, "077")
	if len(first) != 9 {
		t.Fatalf("the step published %d assets, want six archives, the template, the catalog and the manifest", len(first))
	}
	for name, data := range first {
		if !bytes.Equal(data, second[name]) {
			t.Errorf("%s differs between two packagings of one commit", name)
		}
	}

	t.Run("tar.gz", func(t *testing.T) {
		pkg := "passwall-node_" + version + "_linux_amd64"
		compressed, err := gzip.NewReader(bytes.NewReader(first[pkg+".tar.gz"]))
		if err != nil {
			t.Fatal(err)
		}
		if compressed.Name != "" || !compressed.ModTime.IsZero() {
			t.Errorf("gzip header records name %q and time %v", compressed.Name, compressed.ModTime)
		}
		reader := tar.NewReader(compressed)
		var names []string
		for {
			header, err := reader.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			names = append(names, header.Name)
			if header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" {
				t.Errorf("%s is owned by %d:%d (%q:%q), want a bare numeric 0:0", header.Name, header.Uid, header.Gid, header.Uname, header.Gname)
			}
			if !header.ModTime.Equal(committed) {
				t.Errorf("%s is dated %v, not the commit's %v", header.Name, header.ModTime.UTC(), committed)
			}
			assertPackagedMode(t, header.Name, fs.FileMode(header.Mode).Perm(), header.Typeflag == tar.TypeDir)
		}
		assertSortedPackage(t, pkg, names)
	})

	t.Run("zip", func(t *testing.T) {
		pkg := "passwall-node_" + version + "_windows_amd64"
		data := first[pkg+".zip"]
		archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, file := range archive.File {
			names = append(names, file.Name)
			if len(file.Extra) != 0 {
				t.Errorf("%s carries extra fields (uid, gid or access time)", file.Name)
			}
			if !file.Modified.Equal(committed) {
				t.Errorf("%s is dated %v, not the commit's %v", file.Name, file.Modified, committed)
			}
			assertPackagedMode(t, file.Name, file.Mode().Perm(), file.Mode().IsDir())
		}
		assertSortedPackage(t, pkg, names)
	})
}

// AND THE BINARIES INSIDE ARE STAMPED WITH THE SAME COMMIT'S TIME. The stamp is
// one line of a setup step that also talks to the API and compiles, so it is
// read rather than run: a clock reading here is what made two builds of one tag
// differ.
func TestTheReleaseStampsTheCommitTimeNotTheClock(t *testing.T) {
	raw, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `build_date=$(date -u -d "@$(git show -s --format=%ct "$release_sha")" +%FT%TZ)`) {
		t.Fatal("setup does not date the build stamp from the tagged commit")
	}
	if strings.Contains(text, "build_date=$(date -u +") {
		t.Fatal("setup stamps the build with the clock, which differs on every run of one tag")
	}
}

// The binary and the offline installer run from the extracted package; nothing
// else does, and nothing is writable by anyone but its owner.
func assertPackagedMode(t *testing.T, name string, mode fs.FileMode, dir bool) {
	t.Helper()
	want := fs.FileMode(0o644)
	base := filepath.Base(strings.TrimSuffix(name, "/"))
	if dir || base == "passwall-node" || base == "passwall-node.exe" || (base == "install.sh" && !strings.Contains(name, "/deployment/")) {
		want = 0o755
	}
	if mode != want {
		t.Errorf("%s has mode %v, want %v", name, mode, want)
	}
}

func assertSortedPackage(t *testing.T, pkg string, names []string) {
	t.Helper()
	if !sort.StringsAreSorted(names) {
		t.Errorf("members are not in byte order: %v", names)
	}
	for _, name := range names {
		if name != pkg+"/" && !strings.HasPrefix(name, pkg+"/") {
			t.Errorf("%s is outside the package directory %s", name, pkg)
		}
	}
	if len(names) != 10 {
		t.Errorf("the package holds %d members, want its directory, deployment/ and eight files: %v", len(names), names)
	}
}

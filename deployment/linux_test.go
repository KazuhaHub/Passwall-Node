package deployment

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func installationOptions() Options {
	return Options{Endpoint: "https://panel.example/psp/v1/node/sync", AgentID: "agt_node-1", Credential: "pspn_" + strings.Repeat("a", 40), Version: "v1.2.3-rc.1"}
}

func TestRenderLinuxValidation(t *testing.T) {
	for _, version := range []string{"v0.0.0", "v1.2.3", "v1.2.3-beta.0", "v1.2.3-0a", "v1.2.3-a-b"} {
		o := installationOptions()
		o.Version = version
		if _, err := RenderLinux(o); err != nil {
			t.Errorf("valid version %q: %v", version, err)
		}
	}
	invalid := []struct {
		name string
		edit func(*Options)
	}{
		{"latest", func(o *Options) { o.Version = "latest" }},
		{"missing-v", func(o *Options) { o.Version = "1.2.3" }},
		{"leading-zero", func(o *Options) { o.Version = "v01.2.3" }},
		{"numeric-prerelease-leading-zero", func(o *Options) { o.Version = "v1.2.3-rc.01" }},
		{"build-metadata", func(o *Options) { o.Version = "v1.2.3+build" }},
		{"version-injection", func(o *Options) { o.Version = "v1.2.3;touch /tmp/bad" }},
		{"http", func(o *Options) { o.Endpoint = "http://panel.example/v1/node/sync" }},
		{"query", func(o *Options) { o.Endpoint += "?token=secret" }},
		{"fragment", func(o *Options) { o.Endpoint += "#fragment" }},
		{"userinfo", func(o *Options) { o.Endpoint = "https://user:secret@panel.example/v1/node/sync" }},
		{"wrong-path", func(o *Options) { o.Endpoint = "https://panel.example/api" }},
		{"traversal", func(o *Options) { o.Endpoint = "https://panel.example/../v1/node/sync" }},
		{"encoded-traversal", func(o *Options) { o.Endpoint = "https://panel.example/%2e%2e/v1/node/sync" }},
		{"double-slash", func(o *Options) { o.Endpoint = "https://panel.example//v1/node/sync" }},
		{"newline", func(o *Options) { o.Endpoint = "https://panel.example/\n/v1/node/sync" }},
		{"empty-agent", func(o *Options) { o.AgentID = "" }},
		{"agent-injection", func(o *Options) { o.AgentID = "a;id" }},
		{"short-secret", func(o *Options) { o.Credential = "short" }},
		{"oversize-secret", func(o *Options) { o.Credential = strings.Repeat("a", 257) }},
		{"secret-newline", func(o *Options) { o.Credential += "\n" }},
		{"secret-space", func(o *Options) { o.Credential += " " }},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			o := installationOptions()
			test.edit(&o)
			if script, err := RenderLinux(o); err == nil || script != "" {
				t.Fatal("invalid input returned an installation script")
			}
		})
	}
}

type shellFixture struct {
	t              *testing.T
	dir, root, bin string
	archive, sums  string
	options        Options
	architecture   string
}

func newShellFixture(t *testing.T) *shellFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture requires a POSIX host; it never invokes real system services")
	}
	for _, command := range []string{"sh", "tar", "sha256sum", "install", "awk"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("shell fixture requires %s", command)
		}
	}
	f := &shellFixture{t: t, dir: t.TempDir(), options: installationOptions(), architecture: "amd64"}
	f.root = filepath.Join(f.dir, "opt", "passwall-node")
	f.bin = filepath.Join(f.dir, "commands")
	for _, directory := range []string{f.bin, filepath.Join(f.dir, "opt"), filepath.Join(f.dir, "etc", "systemd", "system"), filepath.Join(f.dir, "run", "systemd", "system")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.writeCommand("id", `printf '%s\n' "${FAKE_UID:-0}"`)
	f.writeCommand("uname", `case "$1" in -s) printf '%s\n' "${FAKE_OS:-Linux}" ;; -m) printf '%s\n' "${FAKE_ARCH:-x86_64}" ;; *) exit 1 ;; esac`)
	f.writeCommand("getent", `printf 'passwall-node:x:10001:10001::%s:/usr/sbin/nologin\n' "$FAKE_INSTALL_ROOT"`)
	f.writeCommand("useradd", `printf '%s\n' "$*" >> "$FAKE_COMMAND_LOG"`)
	f.writeCommand("chown", `printf '%s\n' "$*" >> "$FAKE_COMMAND_LOG"`)
	f.writeCommand("systemctl", `
printf '%s\n' "$*" >> "$FAKE_COMMAND_LOG"
[ "${FAKE_SERVICE_FAIL:-0}" != 1 ] || exit 1
if [ "$1" = show ]; then
    case "$3" in
        --property=ActiveState)
            count=0
            [ ! -f "$FAKE_READY_COUNT" ] || read -r count < "$FAKE_READY_COUNT"
            count=$((count + 1))
            printf '%s\n' "$count" > "$FAKE_READY_COUNT"
            if [ "${FAKE_SERVICE_DELAY:-0}" = 1 ] && [ "$count" -lt 2 ]; then
                printf '%s\n' activating
            else
                printf '%s\n' "${FAKE_ACTIVE_STATE:-active}"
            fi ;;
        --property=SubState) printf '%s\n' "${FAKE_SUB_STATE:-running}" ;;
        --property=MainPID) printf '%s\n' "${FAKE_MAIN_PID:-12345}" ;;
        *) exit 1 ;;
    esac
fi
`)
	// Isolated shell tests never reach real systemd. A bounded number of fake
	// polls models expiry; production uses real coreutils timeout deadlines.
	f.writeCommand("sleep", `
count=0
[ ! -f "$FAKE_READY_COUNT" ] || read -r count < "$FAKE_READY_COUNT"
[ "$count" -lt 3 ]
`)
	f.writeCommand("timeout", `
printf '%s\n' "$*" >> "$FAKE_TIMEOUT_LOG"
shift 2
if [ "${FAKE_READINESS_TIMEOUT:-0}" = 1 ] && [ "$1" = sh ]; then exit 124; fi
exec "$@"
`)
	f.writeCommand("curl", `
printf '%s\n' "$*" >> "$FAKE_NETWORK_LOG"
output=
url=
while [ "$#" -gt 0 ]; do
    case "$1" in --output) output=$2; shift 2 ;; https://*) url=$1; shift ;; *) shift ;; esac
done
[ -n "$output" ] && [ -n "$url" ] || exit 1
[ "${FAKE_DOWNLOAD_FAIL:-}" != manifest ] || { case "$url" in */SHA256SUMS.txt) exit 22 ;; esac; }
[ "${FAKE_DOWNLOAD_FAIL:-}" != archive ] || { case "$url" in *.tar.gz) exit 22 ;; esac; }
case "$url" in */SHA256SUMS.txt) cp "$FAKE_SUMS" "$output" ;; *.tar.gz) cp "$FAKE_ARCHIVE" "$output" ;; *) exit 1 ;; esac
`)
	f.archive = filepath.Join(f.dir, "release.tar.gz")
	f.sums = filepath.Join(f.dir, "SHA256SUMS.txt")
	f.makeArchive(nil)
	return f
}

func (f *shellFixture) writeCommand(name, body string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.bin, name), []byte("#!/bin/sh\nset -eu\n"+body+"\n"), 0o700); err != nil {
		f.t.Fatal(err)
	}
}

func (f *shellFixture) makeArchive(extra *tar.Header) {
	f.t.Helper()
	var contents bytes.Buffer
	gzipWriter := gzip.NewWriter(&contents)
	tarWriter := tar.NewWriter(gzipWriter)
	packageName := "passwall-node_" + f.options.Version + "_linux_" + f.architecture
	for _, name := range []string{"passwall-node", "LICENSE", "NOTICE"} {
		data := []byte("license fixture\n")
		if name == "passwall-node" {
			data = []byte("#!/bin/sh\nprintf '%s\\n' '" + f.options.Version + " (test)'\n")
		}
		header := &tar.Header{Name: packageName + "/" + name, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg}
		if extra != nil && extra.Name == header.Name {
			header.Typeflag = extra.Typeflag
			header.Linkname = extra.Linkname
			header.Size = 0
			data = nil
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			f.t.Fatal(err)
		}
		if _, err := tarWriter.Write(data); err != nil {
			f.t.Fatal(err)
		}
	}
	if extra != nil && !strings.HasPrefix(extra.Name, packageName+"/") {
		if err := tarWriter.WriteHeader(extra); err != nil {
			f.t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		f.t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(f.archive, contents.Bytes(), 0o600); err != nil {
		f.t.Fatal(err)
	}
	digest := sha256.Sum256(contents.Bytes())
	if err := os.WriteFile(f.sums, []byte(fmt.Sprintf("%x  %s.tar.gz\n", digest, packageName)), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *shellFixture) run(extraEnvironment ...string) (string, error) {
	return f.runTerminal(false, extraEnvironment...)
}

func (f *shellFixture) runTerminal(tty bool, extraEnvironment ...string) (string, error) {
	f.t.Helper()
	script, err := RenderLinux(f.options)
	if err != nil {
		f.t.Fatal(err)
	}
	// Substitute only fixed system paths in this test copy. The production
	// installer has no prefix override, sudo bypass or mock-execution option.
	script = strings.NewReplacer("/opt/", filepath.Join(f.dir, "opt")+"/", "/run/systemd/system", filepath.Join(f.dir, "run", "systemd", "system"), "/etc/systemd/system", filepath.Join(f.dir, "etc", "systemd", "system")).Replace(script)
	path := filepath.Join(f.dir, "private-install.sh")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		f.t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "sh", path)
	if tty {
		if _, err := exec.LookPath("script"); err != nil {
			f.t.Skip("TTY fixture requires script; it never invokes real system services")
		}
		switch runtime.GOOS {
		case "linux":
			command = exec.CommandContext(ctx, "script", "--quiet", "--return", "--command", "sh "+shellQuote(path), "/dev/null")
		case "darwin":
			command = exec.CommandContext(ctx, "script", "-q", filepath.Join(f.dir, "private-tty.log"), "sh", path)
		default:
			f.t.Skip("TTY fixture supports Linux and Darwin script implementations")
		}
	}
	command.WaitDelay = time.Second
	command.Env = append(os.Environ(),
		"PATH="+f.bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_INSTALL_ROOT="+f.root, "FAKE_ARCHIVE="+f.archive, "FAKE_SUMS="+f.sums,
		"FAKE_NETWORK_LOG="+filepath.Join(f.dir, "network.log"), "FAKE_COMMAND_LOG="+filepath.Join(f.dir, "commands.log"),
		"FAKE_READY_COUNT="+filepath.Join(f.dir, "ready.count"), "FAKE_TIMEOUT_LOG="+filepath.Join(f.dir, "timeout.log"))
	command.Env = append(command.Env, extraEnvironment...)
	output, err := command.CombinedOutput()
	if bytes.Contains(output, []byte(f.options.Credential)) {
		f.t.Fatal("secret appeared in installer output")
	}
	for _, name := range []string{"network.log", "commands.log", "timeout.log"} {
		data, _ := os.ReadFile(filepath.Join(f.dir, name))
		if bytes.Contains(data, []byte(f.options.Credential)) {
			f.t.Fatal("secret appeared in command arguments")
		}
	}
	return string(output), err
}

func (f *shellFixture) networkCalls() int {
	data, _ := os.ReadFile(filepath.Join(f.dir, "network.log"))
	return strings.Count(string(data), "\n")
}

func TestLinuxInstallPlatformGuards(t *testing.T) {
	for _, test := range []struct {
		name, variable string
	}{
		{"nonroot", "FAKE_UID=1000"}, {"not-linux", "FAKE_OS=Darwin"}, {"wrong-arch", "FAKE_ARCH=riscv64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newShellFixture(t)
			if _, err := f.run(test.variable); err == nil || f.networkCalls() != 0 {
				t.Fatal("platform guard did not stop before networking")
			}
		})
	}
	t.Run("missing-systemd", func(t *testing.T) {
		f := newShellFixture(t)
		if err := os.Remove(filepath.Join(f.dir, "run", "systemd", "system")); err != nil {
			t.Fatal(err)
		}
		if _, err := f.run(); err == nil || f.networkCalls() != 0 {
			t.Fatal("missing systemd did not stop before networking")
		}
	})
}

func TestLinuxInstallChecksumFailureIsRetryable(t *testing.T) {
	f := newShellFixture(t)
	if err := os.WriteFile(f.sums, []byte(strings.Repeat("0", 64)+"  passwall-node_"+f.options.Version+"_linux_amd64.tar.gz\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := f.run(); err == nil || !strings.Contains(output, "[4/6] ERROR") || !strings.Contains(output, "checksum verification failed") {
		t.Fatalf("checksum failure not rejected: %v %s", err, output)
	}
	if _, err := os.Stat(f.root); !os.IsNotExist(err) {
		t.Fatal("failed verification published an identity or data directory")
	}
	f.makeArchive(nil)
	if output, err := f.run(); err != nil {
		t.Fatalf("retry failed: %v %s", err, output)
	}
}

func TestLinuxInstallArm64(t *testing.T) {
	f := newShellFixture(t)
	f.architecture = "arm64"
	f.makeArchive(nil)
	if output, err := f.run("FAKE_ARCH=aarch64"); err != nil {
		t.Fatalf("arm64 installation failed: %v %s", err, output)
	}
	data, _ := os.ReadFile(filepath.Join(f.dir, "network.log"))
	if !bytes.Contains(data, []byte("_linux_arm64.tar.gz")) || bytes.Contains(data, []byte("_linux_amd64.tar.gz")) {
		t.Fatal("arm64 did not download the exact architecture asset")
	}
}

func TestLinuxInstallDoesNotReplaceForeignInstallationOrUnit(t *testing.T) {
	t.Run("foreign-directory", func(t *testing.T) {
		f := newShellFixture(t)
		if err := os.MkdirAll(filepath.Join(f.root, "data"), 0o700); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(f.root, "data", "foreign.db")
		if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := f.run(); err == nil || f.networkCalls() != 0 {
			t.Fatal("foreign directory did not stop before networking")
		}
		if data, _ := os.ReadFile(marker); string(data) != "keep" {
			t.Fatal("foreign data was changed")
		}
	})
	t.Run("foreign-unit", func(t *testing.T) {
		f := newShellFixture(t)
		path := filepath.Join(f.dir, "etc", "systemd", "system", "passwall-node.service")
		if err := os.WriteFile(path, []byte("foreign service"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := f.run(); err == nil || f.networkCalls() != 0 {
			t.Fatal("foreign unit was not rejected")
		}
		if data, _ := os.ReadFile(path); string(data) != "foreign service" {
			t.Fatal("foreign unit was replaced")
		}
	})
}

func TestLinuxInstallRejectsAmbiguousChecksumAndLinks(t *testing.T) {
	t.Run("missing-target-checksum", func(t *testing.T) {
		f := newShellFixture(t)
		data, err := os.ReadFile(f.sums)
		if err != nil {
			t.Fatal(err)
		}
		data = bytes.ReplaceAll(data, []byte("_linux_amd64.tar.gz"), []byte("_darwin_amd64.tar.gz"))
		if err := os.WriteFile(f.sums, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := f.run(); err == nil {
			t.Fatal("checksum for a different asset was accepted")
		}
	})
	t.Run("duplicate-checksum", func(t *testing.T) {
		f := newShellFixture(t)
		data, err := os.ReadFile(f.sums)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.sums, append(data, data...), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := f.run(); err == nil {
			t.Fatal("ambiguous checksum accepted")
		}
	})
	t.Run("linked-binary", func(t *testing.T) {
		f := newShellFixture(t)
		f.makeArchive(&tar.Header{Name: "passwall-node_" + f.options.Version + "_linux_amd64/passwall-node", Typeflag: tar.TypeSymlink, Linkname: "/bin/sh"})
		if _, err := f.run(); err == nil {
			t.Fatal("linked binary accepted")
		}
	})
}

func TestLinuxInstallPreservesIdentityAndStateOnRerun(t *testing.T) {
	f := newShellFixture(t)
	// Shell metacharacters are allowed by the wire credential contract. They
	// must remain bytes in a private file, never substitutions or commands.
	f.options.Credential = "pspn_'\"$(id);`id`{}" + strings.Repeat("x", 32)
	if output, err := f.run(); err != nil {
		t.Fatalf("install failed: %v %s", err, output)
	}
	if f.networkCalls() != 2 {
		t.Fatal("installation did not download exactly the pinned archive and checksums")
	}
	network, _ := os.ReadFile(filepath.Join(f.dir, "network.log"))
	for _, required := range []string{"--proto =https", "--proto-redir =https", "--tlsv1.2", "--connect-timeout 15", "--max-time", "https://github.com/KazuhaHub/Passwall-Node/releases/download/" + f.options.Version + "/"} {
		if !bytes.Contains(network, []byte(required)) {
			t.Errorf("download missing security/pinning option %q", required)
		}
	}
	credentialPath := filepath.Join(f.root, "config", "credential")
	credential, err := os.ReadFile(credentialPath)
	if err != nil || string(credential) != f.options.Credential+"\n" {
		t.Fatal("credential quoting did not preserve bytes")
	}
	info, err := os.Stat(credentialPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("credential is not private")
	}
	for _, directory := range []string{"data", "config"} {
		info, err := os.Stat(filepath.Join(f.root, directory))
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatal("persistent directory is not private")
		}
	}
	statePath := filepath.Join(f.root, "data", "state.db")
	if err := os.WriteFile(statePath, []byte("durable-state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := f.run(); err != nil {
		t.Fatalf("rerun failed: %v %s", err, output)
	}
	state, _ := os.ReadFile(statePath)
	if string(state) != "durable-state" || f.networkCalls() != 2 {
		t.Fatal("rerun overwrote state or performed network access")
	}
	for _, test := range []struct {
		name string
		edit func(*Options)
	}{
		{"identity", func(o *Options) { o.AgentID += "2" }},
		{"endpoint", func(o *Options) { o.Endpoint = "https://other.example/v1/node/sync" }},
		{"credential", func(o *Options) { o.Credential += "2" }},
		{"version", func(o *Options) { o.Version = "v2.0.0" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := f.options
			defer func() { f.options = original }()
			test.edit(&f.options)
			if _, err := f.run(); err == nil || f.networkCalls() != 2 {
				t.Fatal("mismatched rerun did not fail closed before networking")
			}
			actual, _ := os.ReadFile(credentialPath)
			state, _ := os.ReadFile(statePath)
			if !bytes.Equal(actual, credential) || string(state) != "durable-state" {
				t.Fatal("mismatched rerun overwrote credential or state")
			}
		})
	}
	for _, name := range []string{"passwall-node.service", "config/environment"} {
		data, err := os.ReadFile(filepath.Join(f.root, name))
		if err != nil || bytes.Contains(data, []byte(f.options.Credential)) {
			t.Fatal("credential leaked into unit or environment file")
		}
	}
}

func TestLinuxInstallServiceFailureRetainsStateAndRetryIsOffline(t *testing.T) {
	f := newShellFixture(t)
	if _, err := f.run("FAKE_SERVICE_FAIL=1"); err == nil {
		t.Fatal("service failure was ignored")
	}
	if _, err := os.Stat(filepath.Join(f.root, "config", "credential")); err != nil {
		t.Fatal("service failure discarded installed identity")
	}
	if output, err := f.run(); err != nil || f.networkCalls() != 2 {
		t.Fatalf("offline service retry failed: %v %s", err, output)
	}
}

func TestLinuxInstallIgnoresUntrustedArchivePaths(t *testing.T) {
	f := newShellFixture(t)
	f.makeArchive(&tar.Header{Name: "../../outside", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
	if output, err := f.run(); err != nil {
		t.Fatalf("install failed with an unrelated archive member: %v %s", err, output)
	}
	if _, err := os.Lstat(filepath.Join(f.dir, "outside")); !os.IsNotExist(err) {
		t.Fatal("unrelated archive path was extracted")
	}
}

func TestLinuxInstallPhaseFeedbackFreshAndOfflineRerun(t *testing.T) {
	f := newShellFixture(t)
	checkPhases := func(output string) {
		t.Helper()
		previous := -1
		for number := 1; number <= 6; number++ {
			marker := fmt.Sprintf("Passwall Node [%d/6]", number)
			index := strings.Index(output, marker)
			if index <= previous {
				t.Fatalf("missing/out-of-order phase %d: %s", number, output)
			}
			previous = index
		}
		for _, required := range []string{"Agent startup confirmed only", "proxy readiness are not confirmed", "verify the server connection, core state and configured nodes in PSP", "test proxy traffic"} {
			if !strings.Contains(output, required) {
				t.Fatalf("installer omitted truthful next step %q", required)
			}
		}
	}
	output, err := f.run()
	if err != nil {
		t.Fatalf("fresh installation failed: %v %s", err, output)
	}
	checkPhases(output)
	if !strings.Contains(output, "Download exact release "+f.options.Version+" (linux/amd64)") || !strings.Contains(output, "Verify checksum, archive members and executable version") {
		t.Fatal("fresh feedback omitted pinned download/checksum verification")
	}
	network, _ := os.ReadFile(filepath.Join(f.dir, "network.log"))
	for _, line := range strings.Split(strings.TrimSpace(string(network)), "\n") {
		if !strings.HasPrefix(line, "--disable --fail ") {
			t.Fatal("curl did not disable local configuration as its first argument")
		}
	}
	if bytes.Contains(network, []byte("--progress-bar")) || strings.Count(string(network), "--silent") != 2 {
		t.Fatal("non-TTY install emitted a curl transfer meter")
	}
	output, err = f.run()
	if err != nil {
		t.Fatalf("offline rerun failed: %v %s", err, output)
	}
	checkPhases(output)
	if !strings.Contains(output, "download skipped (offline rerun)") || !strings.Contains(output, "checksum download not repeated") || strings.Contains(output, "Downloading release archive") || f.networkCalls() != 2 {
		t.Fatal("matching rerun feedback did not accurately describe offline retention")
	}
}

func TestLinuxInstallDownloadFailureHasPhaseAndRetainsRetry(t *testing.T) {
	for _, failure := range []string{"manifest", "archive"} {
		t.Run(failure, func(t *testing.T) {
			f := newShellFixture(t)
			output, err := f.run("FAKE_DOWNLOAD_FAIL=" + failure)
			if err == nil || !strings.Contains(output, "[3/6] ERROR") || !strings.Contains(output, "download failed; no installation was published") {
				t.Fatalf("download failure omitted phase-specific safe error: %v %s", err, output)
			}
			if _, err := os.Stat(f.root); !os.IsNotExist(err) {
				t.Fatal("download failure published an identity")
			}
			if output, err := f.run(); err != nil {
				t.Fatalf("download retry failed: %v %s", err, output)
			}
		})
	}
}

func TestLinuxInstallTransferMeterOnlyOnTTY(t *testing.T) {
	f := newShellFixture(t)
	if output, err := f.runTerminal(true); err != nil {
		t.Fatalf("TTY fixture install failed: %v %s", err, output)
	}
	network, _ := os.ReadFile(filepath.Join(f.dir, "network.log"))
	lines := strings.Split(strings.TrimSpace(string(network)), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "--disable --fail ") || !strings.HasPrefix(lines[1], "--disable --fail ") || !strings.Contains(lines[0], "--silent") || !strings.Contains(lines[1], "--progress-bar") || strings.Contains(lines[1], "--silent") {
		t.Fatal("TTY archive download did not selectively enable the transfer meter")
	}
}

func TestLinuxInstallHelperFailureIsPrivateAndRetainsState(t *testing.T) {
	f := newShellFixture(t)
	if output, err := f.run(); err != nil {
		t.Fatalf("initial install failed: %v %s", err, output)
	}
	statePath := filepath.Join(f.root, "data", "state.db")
	if err := os.WriteFile(statePath, []byte("retained-state"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A helper's raw diagnostic output is untrusted private material, not a
	// terminal message. The fixture deliberately emits the credential on failure.
	body := "#!/bin/sh\ncase \"$1\" in\n--upgrade-info) exit 0 ;;\n--enable-remote-upgrade) printf '%s\\n' " + shellQuote(f.options.Credential) + "; exit 1 ;;\nesac\nexit 1\n"
	if err := os.WriteFile(filepath.Join(f.root, "bin", "passwall-node"), []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	output, err := f.run()
	if err == nil || !strings.Contains(output, "[5/6] ERROR") || !strings.Contains(output, "remote upgrade setup failed") || strings.Contains(output, "[6/6]") || f.networkCalls() != 2 {
		t.Fatalf("helper failure omitted private phase-specific stop: %v %s", err, output)
	}
	state, err := os.ReadFile(statePath)
	if err != nil || string(state) != "retained-state" {
		t.Fatal("helper failure replaced installed data")
	}
}

func TestLinuxInstallUnexpectedFailureStillReportsCurrentPhase(t *testing.T) {
	f := newShellFixture(t)
	f.writeCommand("install", "exit 1")
	output, err := f.run()
	if err == nil || !strings.Contains(output, "[5/6] ERROR") || !strings.Contains(output, "inspect this phase before retrying") {
		t.Fatalf("unexpected filesystem failure omitted current phase: %v %s", err, output)
	}
	if _, err := os.Stat(f.root); !os.IsNotExist(err) {
		t.Fatal("unexpected failure published an incomplete identity")
	}
}

func TestLinuxInstallReadinessRequiresRunningProcessAndIsBounded(t *testing.T) {
	for _, test := range []struct {
		name, variable string
	}{
		{"failed", "FAKE_ACTIVE_STATE=failed"},
		{"inactive", "FAKE_ACTIVE_STATE=inactive"},
		{"not-running", "FAKE_SUB_STATE=exited"},
		{"zero-pid", "FAKE_MAIN_PID=0"},
		{"malformed-pid", "FAKE_MAIN_PID=invalid"},
		{"readiness-timeout", "FAKE_READINESS_TIMEOUT=1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newShellFixture(t)
			output, err := f.run(test.variable)
			if err == nil || !strings.Contains(output, "[6/6] ERROR") || !strings.Contains(output, "active/running with a nonzero PID within 30s") || strings.Contains(output, "Agent startup confirmed only") {
				t.Fatalf("unready process was incorrectly accepted: %v %s", err, output)
			}
			credential, err := os.ReadFile(filepath.Join(f.root, "config", "credential"))
			if err != nil || string(credential) != f.options.Credential+"\n" {
				t.Fatal("startup check failure discarded the original installed identity")
			}
			if output, err := f.run(); err != nil || f.networkCalls() != 2 {
				t.Fatalf("same-identity offline startup retry failed: %v %s", err, output)
			}
		})
	}
	t.Run("delayed-running", func(t *testing.T) {
		f := newShellFixture(t)
		if output, err := f.run("FAKE_SERVICE_DELAY=1"); err != nil {
			t.Fatalf("bounded delayed start failed: %v %s", err, output)
		}
		timeouts, _ := os.ReadFile(filepath.Join(f.dir, "timeout.log"))
		for _, required := range []string{"--kill-after=5s 30s systemctl daemon-reload", "--kill-after=5s 30s systemctl enable --now", "--kill-after=1s 30s sh -c", "--kill-after=1s 3s systemctl show"} {
			if !bytes.Contains(timeouts, []byte(required)) {
				t.Fatalf("startup omitted a real command/deadline bound %q", required)
			}
		}
		commands, _ := os.ReadFile(filepath.Join(f.dir, "commands.log"))
		if strings.Contains(strings.ToLower(string(commands)), "restart") || strings.Contains(string(commands), "x-ui") {
			t.Fatal("process readiness changed/restarted another service")
		}
	})
}

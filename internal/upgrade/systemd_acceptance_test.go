package upgrade

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/KazuhaHub/passwall-node/deployment"
)

// This is a narrow kernel/systemd permission acceptance, not an agent upgrade,
// authenticated PSP readiness, binary rollback or proxy-traffic acceptance.
// It creates ONLY two randomly named transient units on disposable CI hosts.
func TestUpgradeSystemdProcInspection(t *testing.T) {
	if os.Getenv("PN_SYSTEMD_ACCEPTANCE") != "1" {
		t.Skip("real systemd acceptance is disabled; dedicated native CI sets PN_SYSTEMD_ACCEPTANCE=1")
	}
	if runtime.GOOS != "linux" || os.Geteuid() <= 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Fatal("refusing transient root units outside a non-root disposable GitHub-hosted Linux runner")
	}
	release, err := os.ReadFile("/etc/os-release")
	if err != nil || !strings.Contains(string(release), "\nID=ubuntu\n") || !strings.Contains(string(release), "\nVERSION_ID=\"24.04\"\n") {
		t.Fatal("real systemd acceptance requires Ubuntu 24.04")
	}
	init, err := os.ReadFile("/proc/1/comm")
	if err != nil || strings.TrimSpace(string(init)) != "systemd" {
		t.Fatal("real systemd PID 1 is required; containers are not accepted")
	}
	for _, name := range []string{"/usr/bin/sudo", "/usr/bin/systemd-run", "/usr/bin/systemctl", "/usr/bin/sleep", "/usr/bin/sh", "/usr/bin/id", "/usr/bin/awk", "/usr/bin/sha256sum"} {
		if info, err := os.Stat(name); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			t.Fatal("a required native systemd acceptance tool is missing")
		}
	}
	properties, err := upgradeProbeProperties(deployment.RemoteUpgradeAssets()["passwall-node-upgrade.service"])
	if err != nil {
		t.Fatal(err)
	}
	var random [24]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal("cannot mint disposable unit identities")
	}
	nonce := hex.EncodeToString(random[:])
	description := "Passwall-Node isolated proc acceptance " + nonce
	daemon := "pn-proc-daemon-" + nonce + ".service"
	probe := "pn-proc-probe-" + nonce + ".service"
	owned := make(map[string]bool, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	t.Cleanup(func() {
		// Cancellation of the test deadline must not skip bounded own-unit cleanup.
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		for _, name := range []string{probe, daemon} {
			if !owned[name] {
				continue
			}
			state, err := upgradeProbeShow(cleanup, name)
			if err != nil {
				t.Error("cannot inspect owned transient unit for cleanup")
				continue
			}
			if state["LoadState"] == "not-found" {
				continue // Successfully exited transient units can be collected by PID 1.
			}
			if state["Description"] != description || state["Transient"] != "yes" {
				t.Error("refusing cleanup of a replaced or foreign unit")
				continue
			}
			if _, err := upgradeProbeCommand(cleanup, "/usr/bin/systemctl", "stop", name); err != nil {
				t.Error("cannot stop an owned acceptance unit")
				continue
			}
			state, err = upgradeProbeShow(cleanup, name)
			if err != nil {
				t.Error("cannot recheck transient unit before reset-failed")
				continue
			}
			if state["LoadState"] == "not-found" {
				continue
			}
			if state["Description"] != description || state["Transient"] != "yes" {
				t.Error("refusing reset-failed of a replaced or foreign unit")
				continue
			}
			if _, err := upgradeProbeCommand(cleanup, "/usr/bin/systemctl", "reset-failed", name); err != nil {
				t.Error("cannot reset an owned acceptance unit")
			}
		}
	})
	start := func(name string, arguments ...string) (string, error) {
		state, err := upgradeProbeShow(ctx, name)
		if err != nil || state["LoadState"] != "not-found" {
			return "", errors.New("refusing a pre-existing acceptance unit")
		}
		args := []string{"--quiet", "--unit=" + name, "--description=" + description, "--service-type=exec", "--expand-environment=no", "--property=TimeoutStopSec=10s"}
		output, runErr := upgradeProbeCommand(ctx, "/usr/bin/systemd-run", append(args, arguments...)...)
		// A failed command may have published its own failed unit. Claim only
		// exact provenance, never merely the randomly chosen name.
		state, err = upgradeProbeShow(ctx, name)
		if err != nil {
			return "", err
		}
		if state["LoadState"] != "not-found" {
			if state["Description"] != description || state["Transient"] != "yes" {
				return "", errors.New("acceptance unit identity changed during creation")
			}
			owned[name] = true
		}
		return output, runErr
	}
	uid, gid := strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid())
	if _, err := start(daemon, "--property=User="+uid, "--property=Group="+gid, "--property=NoNewPrivileges=true", "--property=CapabilityBoundingSet=", "--property=RuntimeMaxSec=150s", "--", "/usr/bin/sleep", "150"); err != nil {
		t.Fatal(err)
	}
	state, err := upgradeProbeShow(ctx, daemon)
	if err != nil || state["ActiveState"] != "active" || !owned[daemon] {
		t.Fatal("non-root acceptance daemon did not become active")
	}
	pid, err := strconv.Atoi(state["MainPID"])
	if err != nil || pid <= 1 {
		t.Fatal("acceptance daemon has no valid systemd MainPID")
	}
	wantDigest, err := BinaryDigest("/usr/bin/sleep")
	if err != nil {
		t.Fatal("cannot hash the native acceptance executable")
	}
	// /proc/PID/exe is guarded by PTRACE_MODE_READ_FSCREDS, not merely DAC.
	// Cross-UID CAP_SYS_PTRACE is tested with the ACTUAL helper's capability
	// set, never root's unrestricted default. No process memory is inspected.
	// https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html
	const inspect = `set -eu
test "$(/usr/bin/id -u)" = 0
test "$(/usr/bin/awk '/^NoNewPrivs:/ {print $2}' /proc/self/status)" = 1
/usr/bin/awk -v expected="$2" '/^Uid:/ {found=1; if (NF != 5) exit 1; for (i=2; i<=5; i++) if ($i != expected || $i == 0) exit 1} END {if (!found) exit 1}' "/proc/$1/status"
actual=$(/usr/bin/sha256sum "/proc/$1/exe")
test "${actual%% *}" = "$3"
printf '%s\n' systemd-probe-ok
`
	args := []string{"--wait", "--pipe", "--property=User=0", "--property=Group=0", "--property=RuntimeMaxSec=30s"}
	args = append(args, properties...)
	args = append(args, "--", "/usr/bin/sh", "-c", inspect, "pn-proc-probe", strconv.Itoa(pid), uid, wantDigest)
	output, err := start(probe, args...)
	if err != nil || strings.TrimSpace(output) != "systemd-probe-ok" {
		t.Fatalf("restricted helper cannot confirm its non-root MainPID UID/executable digest: %v", err)
	}
	state, err = upgradeProbeShow(ctx, daemon)
	if err != nil || state["MainPID"] != strconv.Itoa(pid) || state["ActiveState"] != "active" {
		t.Fatal("acceptance daemon changed while inspected")
	}
	t.Logf("native %s: restricted root probe verified non-root UID=%s MainPID=%d executable_sha256=%s", runtime.GOARCH, uid, pid, wantDigest)
}

func upgradeProbeProperties(unit string) ([]string, error) {
	wanted := map[string]string{"NoNewPrivileges": "true", "ProtectSystem": "strict", "ProtectHome": "true", "PrivateTmp": "true"}
	seen := map[string]bool{}
	var properties []string
	section := ""
	for _, line := range strings.Split(unit, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		key, value, present := strings.Cut(line, "=")
		if section != "[Service]" || !present {
			continue
		}
		if expected, required := wanted[key]; required {
			if seen[key] || value != expected {
				return nil, errors.New("helper sandbox must keep its strict singleton protection directives")
			}
			seen[key] = true
			properties = append(properties, "--property="+line)
		} else if key == "CapabilityBoundingSet" {
			if seen[key] {
				return nil, errors.New("helper capability set must be a single explicit allowlist")
			}
			seen[key] = true
			allowed := map[string]bool{"CAP_CHOWN": true, "CAP_DAC_OVERRIDE": true, "CAP_FOWNER": true, "CAP_SYS_PTRACE": true}
			caps := strings.Fields(value)
			if len(caps) == 0 {
				return nil, errors.New("helper capability set must not be empty")
			}
			for _, capability := range caps {
				if !allowed[capability] {
					return nil, errors.New("helper probe refuses unrestricted, duplicate or unrelated capabilities")
				}
				delete(allowed, capability)
			}
			properties = append(properties, "--property="+line)
		}
	}
	if len(seen) != len(wanted)+1 {
		return nil, errors.New("helper sandbox omits an explicit required protection")
	}
	return properties, nil
}

func upgradeProbeCommand(ctx context.Context, tool string, arguments ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/sudo", append([]string{"-n", "--", tool}, arguments...)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	stdout, stderr := &releaseOutput{}, &releaseOutput{}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		digest := sha256.Sum256(stderr.content.Bytes())
		// These two fixed systemd tools and the inspection script have no
		// credentials, URLs or network payload. Preserve bounded diagnostics
		// for permission failures, never command stdout, environment or journal.
		return "", fmt.Errorf("bounded acceptance command failed (tool=%s stderr_bytes=%d stderr_sha256=%x stderr=%q)", tool, stderr.content.Len(), digest, upgradeProbeStderr(stderr.content.String()))
	}
	return stdout.content.String(), nil
}

func upgradeProbeStderr(text string) string {
	var result strings.Builder
	for _, value := range text {
		if unicode.IsControl(value) || unicode.Is(unicode.Cf, value) {
			value = ' '
		}
		if result.Len()+len(string(value)) > 2048 {
			break
		}
		result.WriteRune(value)
	}
	return result.String()
}

func upgradeProbeShow(ctx context.Context, name string) (map[string]string, error) {
	output, err := upgradeProbeCommand(ctx, "/usr/bin/systemctl", "show", name, "--property=LoadState,Description,Transient,MainPID,ActiveState")
	if err != nil {
		return nil, err
	}
	result := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || result[key] != "" {
			return nil, errors.New("systemd returned malformed unit metadata")
		}
		result[key] = value
	}
	if result["LoadState"] == "" {
		return nil, errors.New("systemd omitted a unit load state")
	}
	return result, nil
}

func TestUpgradeSystemdSandboxContract(t *testing.T) {
	unit := deployment.RemoteUpgradeAssets()["passwall-node-upgrade.service"]
	properties, err := upgradeProbeProperties(unit)
	if err != nil || len(properties) != 5 {
		t.Fatalf("invalid real helper probe sandbox: properties=%v error=%v", properties, err)
	}
	for _, changed := range []string{
		strings.ReplaceAll(unit, "NoNewPrivileges=true", "NoNewPrivileges=false"),
		strings.ReplaceAll(unit, "ProtectSystem=strict", "ProtectSystem=full"),
		strings.ReplaceAll(unit, "CAP_CHOWN", "~CAP_CHOWN"),
		strings.ReplaceAll(unit, "CAP_CHOWN", "CAP_SYS_ADMIN"),
		unit + "\nCapabilityBoundingSet=CAP_CHOWN\n",
		unit + "\nNoNewPrivileges=true\n",
	} {
		if _, err := upgradeProbeProperties(changed); err == nil {
			t.Fatal("probe accepted weakened or ambiguous helper sandbox")
		}
	}
}

func TestUpgradeSystemdDiagnosticsAreBounded(t *testing.T) {
	text := upgradeProbeStderr("\x1b[31mpermission denied\x00\n\u202e" + strings.Repeat("x", 4096))
	if len(text) > 2048 || !strings.Contains(text, "permission denied") {
		t.Fatal("systemd error diagnostics omitted the reason or exceeded their bound")
	}
	for _, value := range text {
		if unicode.IsControl(value) || unicode.Is(unicode.Cf, value) {
			t.Fatal("systemd error diagnostics retained control characters")
		}
	}
}

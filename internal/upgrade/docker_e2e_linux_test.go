package upgrade

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// THE UPDATER HANDOVER STANDS ON DOCKER'S BEHAVIOUR, NOT ONLY ON THIS PACKAGE'S
// CODE, and none of that behaviour is something a unit test can see. A successor
// that finds itself through /proc/self/mountinfo, a lock two containers share
// through one bind-mounted directory, a clone the Engine creates without pulling and
// Compose leaves alone, a crash the restart policy recovers and an API stop it does
// not — each is a claim about the daemon and the kernel, and the design is only as
// sound as the claim. So each is probed against a real daemon, on stock Ubuntu
// 24.04 on both architectures the release ships, before anything is built on it.
//
// THESE PROBES GATE THE DESIGN, NOT A RELEASE. They run in docker-updater.yml, never
// in test.yml, whose every job a release waits for.
//
// They restart the Docker daemon and SIGKILL host processes, so they run only as
// root on a disposable GitHub-hosted Ubuntu 24.04 runner with no containers of its
// own, re-executed through sudo the way TestUpgradeSystemdRealNodeE2E is. They never
// pull: every container runs one of two images built here, FROM scratch, holding
// this very test binary, whose TestDockerProbeHelper is the process inside. That
// keeps the probes off every registry, and makes the lock probe use the same flock
// call the updater will.
func TestDockerEngineAssumptions(t *testing.T) {
	if os.Getenv("PN_DOCKER_UPDATER_E2E") != "1" {
		t.Skip("Docker engine probes run only in docker-updater.yml, on a disposable GitHub-hosted runner")
	}
	if os.Geteuid() != 0 {
		runDockerE2EAsRoot(t, "^TestDockerEngineAssumptions$")
		return
	}
	if os.Getenv("PN_DOCKER_UPDATER_E2E_ROOT") != "1" {
		t.Fatal("privileged Docker probes must be launched through their guarded CI test driver")
	}
	p := newDockerProbe(t)
	t.Run("A1 mountinfo names the container", p.probeMountinfo)
	t.Run("A2 flock spans two containers and dies with its holder", p.probeFlock)
	t.Run("A4 an API create of an absent image pulls nothing", p.probeCreateDoesNotPull)
	t.Run("A5 a host-PID SIGKILL is a crash the restart policy recovers", p.probeHostKillIsACrash)
	t.Run("A7 compose leaves a clone carrying its labels alone", p.probeComposeLeavesTheClone)
	t.Run("A8 a clone without a Hostname gets its own", p.probeHostname)
	t.Run("A9 a container's Image is its tag's image ID", p.probeImageIdentity)
	// LAST, because it stops every container on the host.
	t.Run("A3 A5 A6 a daemon restart keeps renames, API stops and never-started containers", p.probeDaemonRestart)
	p.assertNothingPulled(t)
}

// TestDockerProbeHelper is not a test of its own. It is the process inside the
// containers TestDockerEngineAssumptions starts, chosen by the role in its
// environment, and it does nothing anywhere else.
func TestDockerProbeHelper(t *testing.T) {
	role := os.Getenv(dockerProbeRoleEnv)
	if role == "" {
		t.Skip("runs only as the process inside a Docker probe container")
	}
	// PID 1 IGNORES A SIGNAL IT HAS NO HANDLER FOR, so without this an API stop
	// would wait out its whole timeout and then kill.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	switch role {
	case "idle":
		mountinfo, err := os.ReadFile("/proc/self/mountinfo")
		if err != nil {
			t.Fatal(err)
		}
		hostname, err := os.Hostname()
		if err != nil {
			t.Fatal(err)
		}
		line, err := json.Marshal(dockerProbeReport{Hostname: hostname, Mountinfo: string(mountinfo)})
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("%s%s\n", dockerProbeReportPrefix, line)
	case "flock":
		holdDockerProbeLock(ctx, t, os.Getenv("PN_DOCKER_PROBE_LOCK"), os.Getenv("PN_DOCKER_PROBE_STATE"))
	default:
		t.Fatalf("unknown Docker probe role %q", role)
	}
	<-ctx.Done()
}

const (
	dockerProbeRoleEnv      = "PN_DOCKER_PROBE_ROLE"
	dockerProbeReportPrefix = "PN_DOCKER_PROBE_REPORT "
	// Every probe image carries the run label, and Docker merges image labels into
	// each container's, so it finds everything a run created, clones included.
	dockerProbeRunLabel   = "io.kazuhahub.passwall-node.probe-run"
	dockerProbeImageLabel = "io.kazuhahub.passwall-node.probe-image"
	// The image runs this test binary, so the helper role is chosen by environment
	// and the test by -test.run. A zero -test.timeout is no timeout: the process
	// lives as long as its container.
	dockerProbeDockerfile = `FROM scratch
COPY probe /probe
ENV PN_DOCKER_PROBE_ROLE=idle
ENTRYPOINT ["/probe", "-test.run=TestDockerProbeHelper", "-test.timeout=0"]
`
)

// dockerProbeReport is what an idle probe process prints once, on start: what it
// sees as its own mountinfo and hostname, from inside the container.
type dockerProbeReport struct {
	Hostname  string `json:"hostname"`
	Mountinfo string `json:"mountinfo"`
}

// dockerProbeContainer is the slice of a container inspect the probes read. It is
// decoded here rather than through dockerContainer, which carries only the fields
// the agent swap needs.
type dockerProbeContainer struct {
	ID           string `json:"Id"`
	Name         string `json:"Name"`
	Image        string `json:"Image"`
	RestartCount int    `json:"RestartCount"`
	State        struct {
		Running   bool      `json:"Running"`
		Pid       int       `json:"Pid"`
		StartedAt time.Time `json:"StartedAt"`
	} `json:"State"`
	Config struct {
		Hostname string            `json:"Hostname"`
		Labels   map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
}

type dockerProbe struct {
	engine *dockerHTTP
	cli    string
	nonce  string
	// prefix starts every container and project name this run creates.
	prefix         string
	imageA, imageB string
	// template is a running container, started like an updater is, that the
	// API clones are made from.
	template string
	// images is the local image store once the probe images are built; nothing
	// after that may add to it.
	images []string
	watch  *dockerPullWatch
}

// runDockerE2EAsRoot re-executes this test binary as root, through sudo, with an
// explicit environment rather than the caller's, as TestUpgradeSystemdRealNodeE2E
// does. The Docker CLI's path is resolved here, where the runner's PATH is, and
// passed on as an absolute path. Output is streamed: a probe that hangs should be
// visible before the job's timeout, not after it.
func runDockerE2EAsRoot(t *testing.T, pattern string) {
	t.Helper()
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Fatal("refusing privileged Docker probes outside a disposable GitHub-hosted runner")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal("cannot locate the test executable")
	}
	cli, err := exec.LookPath("docker")
	if err != nil || !filepath.IsAbs(cli) {
		t.Fatal("the Docker CLI is not on PATH as an absolute path")
	}
	arguments := []string{"-n", "env", "PATH=/usr/bin:/bin", "LANG=C", "GITHUB_ACTIONS=true", "RUNNER_ENVIRONMENT=github-hosted",
		"PN_DOCKER_UPDATER_E2E=1", "PN_DOCKER_UPDATER_E2E_ROOT=1", "PN_DOCKER_CLI=" + cli,
		binary, "-test.run=" + pattern, "-test.v", "-test.timeout=12m"}
	ctx, cancel := context.WithTimeout(context.Background(), 13*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/sudo", arguments...)
	command.WaitDelay = 2 * time.Second
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err := command.Run(); err != nil {
		t.Fatalf("the privileged Docker probes failed: %v", err)
	}
}

// dockerE2EGuard refuses any host but the one these probes are written for.
func dockerE2EGuard(ctx context.Context, engine *dockerHTTP, cli string) error {
	if os.Geteuid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		return errors.New("refusing privileged Docker probes outside a root disposable GitHub-hosted runner")
	}
	release, err := os.ReadFile("/etc/os-release")
	if err != nil || !strings.Contains(string(release), "\nID=ubuntu\n") || !strings.Contains(string(release), "\nVERSION_ID=\"24.04\"\n") {
		return errors.New("Docker probes require Ubuntu 24.04")
	}
	if !filepath.IsAbs(cli) {
		return errors.New("Docker probes require an explicit absolute Docker CLI path")
	}
	if err := engine.Ping(ctx); err != nil {
		return errors.New("the Docker Engine socket is not reachable")
	}
	// THEY RESTART THE DAEMON, which stops every container on the host. A host
	// running containers this run did not create is not one to do that on.
	var existing []json.RawMessage
	if err := engine.call(ctx, http.MethodGet, "/"+dockerAPIVersion+"/containers/json?all=1", nil, []int{http.StatusOK}, &existing); err != nil {
		return errors.New("cannot list the host's containers")
	}
	if len(existing) != 0 {
		return fmt.Errorf("refusing Docker probes on a host that already has %d containers", len(existing))
	}
	return nil
}

func newDockerProbe(t *testing.T) *dockerProbe {
	t.Helper()
	engine, err := newDockerHTTP(dockerSocket)
	if err != nil {
		t.Fatal(err)
	}
	p := &dockerProbe{engine: engine, cli: os.Getenv("PN_DOCKER_CLI")}
	if err := dockerE2EGuard(t.Context(), engine, p.cli); err != nil {
		t.Fatal(err)
	}
	var random [4]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	p.nonce = hex.EncodeToString(random[:])
	p.prefix = "pnprobe-" + p.nonce
	t.Cleanup(func() { p.cleanup(t) })
	// Every pull from here on is a failure; the watch starts before the build so
	// that one would be seen too.
	p.watch = p.watchPulls(t, time.Now())

	// WHAT RAN, for whoever reads a red run: the daemon, Compose, and the image
	// store the identity probe is about.
	t.Logf("Docker Engine %s", p.docker(t, "version", "--format", "{{.Server.Version}} (API {{.Server.APIVersion}})"))
	t.Logf("Docker Compose %s", p.docker(t, "compose", "version", "--short"))
	t.Logf("storage %s", p.docker(t, "info", "--format", "{{.Driver}} {{json .DriverStatus}} live-restore={{.LiveRestoreEnabled}}"))

	p.buildImages(t)
	p.images = p.imageIDs(t)
	p.template = p.run(t, "template", "--network", "none", "--restart", "unless-stopped", p.imageA)
	p.waitRunning(t, p.template)
	return p
}

// buildImages builds the two probe images. They hold the same binary and differ
// only by a label, so they are two image IDs a clone can move between.
func (p *dockerProbe) buildImages(t *testing.T) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// FROM SCRATCH HAS NO DYNAMIC LOADER. A test binary built with cgo would fail
	// in every container with a bare "no such file or directory", which reads like
	// anything but the cause.
	executable, err := elf.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	for _, program := range executable.Progs {
		if program.Type == elf.PT_INTERP {
			executable.Close()
			t.Fatal("the probe containers run this test binary FROM scratch, which has no dynamic loader: build it with CGO_ENABLED=0")
		}
	}
	executable.Close()

	dir := t.TempDir()
	source, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := os.OpenFile(filepath.Join(dir, "probe"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(target, source); err != nil {
		target.Close()
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerProbeDockerfile), 0o644); err != nil {
		t.Fatal(err)
	}
	p.imageA, p.imageB = p.prefix+":a", p.prefix+":b"
	for variant, tag := range map[string]string{"a": p.imageA, "b": p.imageB} {
		p.docker(t, "build", "--label", dockerProbeRunLabel+"="+p.nonce, "--label", dockerProbeImageLabel+"="+variant, "--tag", tag, dir)
	}
}

// A1: the updater finds its own container ID in /proc/self/mountinfo, in the root
// of the /etc/hostname bind mount, because its hostname is the one thing a clone
// copies. Checked with the network an updater runs in and with Docker's default.
func (p *dockerProbe) probeMountinfo(t *testing.T) {
	for _, network := range []string{"none", "bridge"} {
		id := p.run(t, "a1-"+network, "--network", network, "--restart", "no", p.imageA)
		container := p.mustInspect(t, id)
		report := p.report(t, id)
		mounted, line, err := dockerHostnameMountID(report.Mountinfo)
		if err != nil {
			t.Fatalf("network %s: %v\n%s", network, err, report.Mountinfo)
		}
		t.Logf("network %s: %s", network, line)
		if mounted != container.ID {
			t.Errorf("network %s: the /etc/hostname mount names %s, but the container is %s", network, mounted, container.ID)
		}
		if container.Config.Hostname != container.ID[:12] || report.Hostname != container.Config.Hostname {
			t.Errorf("network %s: hostname %q inside, %q inspected, want both %q", network, report.Hostname, container.Config.Hostname, container.ID[:12])
		}
	}
}

// A2: an flock on a file in a host directory bind-mounted into two containers
// excludes the second, and the kernel releases it when the holder is SIGKILLed —
// the updater's lock relies on both. The host, which shares the inode, is excluded
// as well.
func (p *dockerProbe) probeFlock(t *testing.T) {
	shared := t.TempDir()
	lock := filepath.Join(shared, "lock")
	holder := func(name string) string {
		return p.run(t, "a2-"+name, "--network", "none", "--restart", "no",
			"--env", dockerProbeRoleEnv+"=flock",
			"--env", "PN_DOCKER_PROBE_LOCK=/shared/lock",
			"--env", "PN_DOCKER_PROBE_STATE=/shared/"+name+".state",
			"--volume", shared+":/shared", p.imageA)
	}
	state := func(name string) string {
		data, _ := os.ReadFile(filepath.Join(shared, name+".state"))
		return string(data)
	}
	first := holder("first")
	p.wait(t, 30*time.Second, "the first container to take the lock", func() (bool, error) { return state("first") == "held", nil })
	if dockerProbeHostCanLock(t, lock) {
		t.Fatal("the host took a lock a container holds")
	}
	holder("second")
	p.wait(t, 30*time.Second, "the second container to find the lock taken", func() (bool, error) { return state("second") == "waiting", nil })
	time.Sleep(time.Second)
	if got := state("second"); got != "waiting" {
		t.Fatalf("the second container's lock is %q while the first holds it", got)
	}
	holding := p.mustInspect(t, first)
	if err := syscall.Kill(holding.State.Pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	p.wait(t, 10*time.Second, "the second container to take the lock its killed holder held", func() (bool, error) { return state("second") == "held", nil })
	if dockerProbeHostCanLock(t, lock) {
		t.Fatal("the host took a lock the second container holds")
	}
}

// A4: the Engine API's create answers 404 for an image that is not in the local
// store and pulls nothing; only the CLI pulls. The successor is created by
// reference and must never cause a pull.
func (p *dockerProbe) probeCreateDoesNotPull(t *testing.T) {
	ctx := t.Context()
	// A TAG THAT EXISTS IN THE REGISTRY, so a create that did pull would leave the
	// image behind. One that did not exist would fail that pull and leave nothing
	// to see.
	reference := DockerImageRepository + ":beta"
	if _, err := p.engine.InspectImage(ctx, reference); !errors.Is(err, errDockerNotFound) {
		t.Fatalf("this probe needs %s absent from the local store; inspecting it = %v", reference, err)
	}
	name := p.prefix + "-a4"
	if _, err := p.engine.CreateReplacement(ctx, name, p.templateSource(t), dockerImage{}, reference); !errors.Is(err, errDockerNotFound) {
		t.Fatalf("creating from an absent image = %v, want the Engine's 404", err)
	}
	if _, err := p.engine.InspectContainer(ctx, name); !errors.Is(err, errDockerNotFound) {
		t.Fatalf("a create that failed left a container: %v", err)
	}
	if _, err := p.engine.InspectImage(ctx, reference); !errors.Is(err, errDockerNotFound) {
		t.Fatalf("the create pulled %s: %v", reference, err)
	}
}

// A5, the crash half: a SIGKILL sent to a container's HOST pid is a process exit
// the daemon did not ask for, so unless-stopped restarts it and RestartCount
// counts it. The handover's crash cases are injected this way and never through
// `docker kill` or `docker stop`, which the daemon initiates.
func (p *dockerProbe) probeHostKillIsACrash(t *testing.T) {
	id := p.run(t, "a5-crash", "--network", "none", "--restart", "unless-stopped", p.imageA)
	kill := func(count int) {
		t.Helper()
		before := p.waitRunning(t, id)
		if before.RestartCount != count-1 {
			t.Fatalf("RestartCount = %d before kill %d", before.RestartCount, count)
		}
		if err := syscall.Kill(before.State.Pid, syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		var after dockerProbeContainer
		p.wait(t, 30*time.Second, fmt.Sprintf("a restart after kill %d", count), func() (bool, error) {
			container, err := p.inspect(t.Context(), id)
			after = container
			return err == nil && container.State.Running && container.RestartCount == count && container.State.Pid != before.State.Pid, err
		})
		if !after.State.StartedAt.After(before.State.StartedAt) {
			t.Errorf("StartedAt %s did not move past %s across a restart", after.State.StartedAt, before.State.StartedAt)
		}
	}
	// SECONDS AFTER IT STARTED, as a successor whose new binary fails at once is.
	kill(1)
	// AND AFTER MORE THAN TEN SECONDS UP, as a successor past its stability window is.
	started := p.mustInspect(t, id).State.StartedAt
	time.Sleep(time.Until(started.Add(11 * time.Second)))
	kill(2)
	p.assertHelperDecodes(t, id)
}

// assertHelperDecodes checks that the helper's own decode, dockerContainer, reads
// the fields the handover relies on exactly as the probe's decode does. Those
// fields are decode-only and their unit test runs against bodies written in the
// Engine's shape; this runs against the Engine itself.
func (p *dockerProbe) assertHelperDecodes(t *testing.T, id string) {
	t.Helper()
	probe := p.mustInspect(t, id)
	helper, err := p.engine.InspectContainer(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	var config dockerConfig
	if err := json.Unmarshal(helper.Config, &config); err != nil {
		t.Fatal(err)
	}
	if helper.ID != probe.ID || helper.RestartCount != probe.RestartCount || !helper.State.StartedAt.Equal(probe.State.StartedAt) ||
		helper.State.Running != probe.State.Running || helper.State.PID != probe.State.Pid || config.Hostname != probe.Config.Hostname {
		t.Errorf("the helper decodes %s as restarts %d, started %s, running %t, pid %d, hostname %q; the probe reads %d, %s, %t, %d, %q",
			id, helper.RestartCount, helper.State.StartedAt, helper.State.Running, helper.State.PID, config.Hostname,
			probe.RestartCount, probe.State.StartedAt, probe.State.Running, probe.State.Pid, probe.Config.Hostname)
	}
}

// A7: Compose leaves alone a container cloned through the API with every label
// copied and another image, in the state the handover's tidy leaves — the original
// removed and the clone renamed to its container_name — and `compose down` removes
// it. The clone keeps com.docker.compose.image unrewritten, which is what Compose
// compares with the tag's image to decide whether to recreate.
func (p *dockerProbe) probeComposeLeavesTheClone(t *testing.T) {
	ctx := t.Context()
	project, dir := p.prefix+"-a7", t.TempDir()
	name := project + "-probe"
	file := filepath.Join(dir, "compose.yaml")
	document := fmt.Sprintf("name: %s\nservices:\n  probe:\n    container_name: %s\n    image: %s\n    pull_policy: never\n    restart: unless-stopped\n    network_mode: none\n", project, name, p.imageA)
	if err := os.WriteFile(file, []byte(document), 0o644); err != nil {
		t.Fatal(err)
	}
	compose := func(args ...string) string {
		t.Helper()
		return p.docker(t, append([]string{"compose", "--project-directory", dir, "--file", file}, args...)...)
	}
	t.Cleanup(func() {
		_, _, _ = p.dockerOutput("compose", "--project-directory", dir, "--file", file, "down", "--remove-orphans")
	})
	compose("up", "--detach", "--pull", "never")
	original := p.mustInspect(t, name)
	for _, label := range []string{"com.docker.compose.project", "com.docker.compose.service", "com.docker.compose.config-hash", "com.docker.compose.image"} {
		if original.Config.Labels[label] == "" {
			t.Fatalf("the compose container has no %s label; what this probe models has changed", label)
		}
	}
	source, err := p.engine.InspectContainer(ctx, original.ID)
	if err != nil {
		t.Fatal(err)
	}
	image, err := p.engine.InspectImage(ctx, p.imageB)
	if err != nil {
		t.Fatal(err)
	}
	clone, err := p.engine.CreateReplacement(ctx, name+"-next", source, image, p.imageB)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.engine.StartContainer(ctx, clone); err != nil {
		t.Fatal(err)
	}
	p.waitRunning(t, clone)
	if err := p.engine.StopContainer(ctx, original.ID); err != nil {
		t.Fatal(err)
	}
	if err := p.engine.RemoveContainer(ctx, original.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := p.engine.RenameContainer(ctx, clone, name); err != nil {
		t.Fatal(err)
	}

	compose("up", "--detach", "--pull", "never")
	after := p.mustInspect(t, name)
	if after.ID != clone {
		t.Fatalf("compose up replaced the clone %s with %s", clone[:12], after.ID[:12])
	}
	if !after.State.Running || after.Image != image.ID {
		t.Fatalf("after compose up the clone runs=%t image=%s, want running %s", after.State.Running, after.Image, image.ID)
	}
	if got, want := after.Config.Labels["com.docker.compose.image"], original.Config.Labels["com.docker.compose.image"]; got != want {
		t.Fatalf("the clone's com.docker.compose.image is %q, want the original's %q", got, want)
	}
	listed := strings.Fields(compose("ps", "--all", "--quiet"))
	if len(listed) != 1 || !strings.HasPrefix(clone, listed[0]) {
		t.Fatalf("compose ps lists %q, want only the clone %s", listed, clone)
	}

	compose("down")
	if _, err := p.inspect(ctx, clone); !errors.Is(err, errDockerNotFound) {
		t.Fatalf("compose down left the clone: %v", err)
	}
}

// A8: a container created without a hostname is given its own short ID, and a
// clone carries over whatever Config.Hostname its source had — so a clone of the
// updater would answer to the predecessor's ID, unless the default is stripped
// first, in which case the clone gets its own and sees it from inside.
func (p *dockerProbe) probeHostname(t *testing.T) {
	ctx := t.Context()
	source := p.templateSource(t)
	if got := p.mustInspect(t, source.ID).Config.Hostname; got != source.ID[:12] {
		t.Fatalf("a container started without a hostname has %q, want its short ID %q", got, source.ID[:12])
	}
	image, err := p.engine.InspectImage(ctx, p.imageB)
	if err != nil {
		t.Fatal(err)
	}
	kept, err := p.engine.CreateReplacement(ctx, p.prefix+"-a8-kept", source, image, p.imageB)
	if err != nil {
		t.Fatal(err)
	}
	// IF THIS EVER FAILS, stripping the hostname has become unnecessary, not wrong.
	if got := p.mustInspect(t, kept).Config.Hostname; got != source.ID[:12] {
		t.Errorf("a clone that keeps Config.Hostname has %q, want its source's %q", got, source.ID[:12])
	}

	var config map[string]json.RawMessage
	if err := json.Unmarshal(source.Config, &config); err != nil {
		t.Fatal(err)
	}
	delete(config, "Hostname")
	stripped := source
	if stripped.Config, err = json.Marshal(config); err != nil {
		t.Fatal(err)
	}
	own, err := p.engine.CreateReplacement(ctx, p.prefix+"-a8-stripped", stripped, image, p.imageB)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.mustInspect(t, own).Config.Hostname; got != own[:12] {
		t.Fatalf("a clone without Config.Hostname has %q, want its own short ID %q", got, own[:12])
	}
	if err := p.engine.StartContainer(ctx, own); err != nil {
		t.Fatal(err)
	}
	report := p.report(t, own)
	mounted, _, err := dockerHostnameMountID(report.Mountinfo)
	if err != nil {
		t.Fatal(err)
	}
	if report.Hostname != own[:12] || mounted != own {
		t.Fatalf("inside the stripped clone the hostname is %q and /etc/hostname names %s, want %q and %s", report.Hostname, mounted, own[:12], own)
	}
}

// A9: a container's .Image is the image ID its tag resolves to in the local store,
// whichever image store the daemon uses — the equality the agent swap's readiness
// check already relies on. Checked for a container run from the CLI by tag and one
// created through the API by tag.
func (p *dockerProbe) probeImageIdentity(t *testing.T) {
	ctx := t.Context()
	imageA, err := p.engine.InspectImage(ctx, p.imageA)
	if err != nil {
		t.Fatal(err)
	}
	run := p.run(t, "a9-cli", "--network", "none", "--restart", "no", p.imageA)
	if got := p.mustInspect(t, run).Image; got != imageA.ID {
		t.Errorf("a container run from %s has Image %s, but the tag's image ID is %s", p.imageA, got, imageA.ID)
	}
	imageB, err := p.engine.InspectImage(ctx, p.imageB)
	if err != nil {
		t.Fatal(err)
	}
	created, err := p.engine.CreateReplacement(ctx, p.prefix+"-a9-api", p.templateSource(t), imageB, p.imageB)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.mustInspect(t, created).Image; got != imageB.ID {
		t.Errorf("a container created through the API from %s has Image %s, but the tag's image ID is %s", p.imageB, got, imageB.ID)
	}
	t.Logf("image IDs: %s and %s", imageA.ID, imageB.ID)
}

// A3, A5's stop half and A6, across one `systemctl restart docker`:
//   - a running container renamed through the API keeps its restart policy and
//     comes back running under the new name;
//   - a container stopped through the API is not restarted, then or after the
//     daemon restarts, because the stop marked it manually stopped;
//   - a container created and never started stays that way, though its restart
//     policy is unless-stopped.
func (p *dockerProbe) probeDaemonRestart(t *testing.T) {
	ctx := t.Context()
	renamed := p.prefix + "-a3-renamed"
	running := p.run(t, "a3", "--network", "none", "--restart", "unless-stopped", p.imageA)
	p.waitRunning(t, running)
	if err := p.engine.RenameContainer(ctx, p.prefix+"-a3", renamed); err != nil {
		t.Fatal(err)
	}
	if got := p.mustInspect(t, renamed); got.ID != running || got.Name != "/"+renamed || !got.State.Running || got.HostConfig.RestartPolicy.Name != "unless-stopped" {
		t.Fatalf("after a rename: id=%s name=%s running=%t restart=%q", got.ID, got.Name, got.State.Running, got.HostConfig.RestartPolicy.Name)
	}
	if _, err := p.inspect(ctx, p.prefix+"-a3"); !errors.Is(err, errDockerNotFound) {
		t.Fatalf("the old name still resolves after a rename: %v", err)
	}

	stopped := p.run(t, "a5-stopped", "--network", "none", "--restart", "unless-stopped", p.imageA)
	p.waitRunning(t, stopped)
	if err := p.engine.StopContainer(ctx, stopped); err != nil {
		t.Fatal(err)
	}
	before := p.mustInspect(t, stopped)
	time.Sleep(3 * time.Second)
	if after := p.mustInspect(t, stopped); after.State.Running || after.RestartCount != before.RestartCount {
		t.Fatalf("an API stop was restarted: running=%t restarts %d -> %d", after.State.Running, before.RestartCount, after.RestartCount)
	}

	image, err := p.engine.InspectImage(ctx, p.imageA)
	if err != nil {
		t.Fatal(err)
	}
	created, err := p.engine.CreateReplacement(ctx, p.prefix+"-a6", p.templateSource(t), image, p.imageA)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.mustInspect(t, created); got.State.Running || !got.State.StartedAt.IsZero() || got.HostConfig.RestartPolicy.Name != "unless-stopped" {
		t.Fatalf("a created container: running=%t started=%s restart=%q", got.State.Running, got.State.StartedAt, got.HostConfig.RestartPolicy.Name)
	}
	p.assertHelperDecodes(t, created)

	p.restartDaemon(t)

	p.wait(t, 60*time.Second, "the renamed container to come back under its new name", func() (bool, error) {
		container, err := p.inspect(ctx, renamed)
		return err == nil && container.ID == running && container.State.Running, err
	})
	// The daemon has applied its restart policies by now; give anything it still
	// meant to start a little longer before reading the two that must stay down.
	time.Sleep(3 * time.Second)
	if got := p.mustInspect(t, stopped); got.State.Running {
		t.Error("a container stopped through the API was started by a daemon restart")
	}
	if got := p.mustInspect(t, created); got.State.Running || !got.State.StartedAt.IsZero() {
		t.Errorf("a never-started container was started by a daemon restart: running=%t started=%s", got.State.Running, got.State.StartedAt)
	}
}

// restartDaemon restarts dockerd. The pull watch ends with the daemon's event
// stream, so it is read before and started again after; the new one replays from
// just before the restart.
func (p *dockerProbe) restartDaemon(t *testing.T) {
	t.Helper()
	p.stopWatch(t)
	from := time.Now()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "restart", "docker").CombinedOutput(); err != nil {
		t.Fatalf("systemctl restart docker: %v\n%s", err, output)
	}
	p.wait(t, 90*time.Second, "the Docker daemon to answer again", func() (bool, error) {
		ping, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		err := p.engine.Ping(ping)
		return err == nil, err
	})
	p.watch = p.watchPulls(t, from)
}

// assertNothingPulled ends the run's pull watch and looks for an image the local
// store gained after the probe images were built. The two are independent: the
// event stream is the daemon's account, the store is what a pull leaves behind.
func (p *dockerProbe) assertNothingPulled(t *testing.T) {
	t.Helper()
	p.stopWatch(t)
	var added []string
	for _, id := range p.imageIDs(t) {
		if !slices.Contains(p.images, id) {
			added = append(added, id)
		}
	}
	if len(added) != 0 {
		t.Errorf("the local image store gained %q during the probes", added)
	}
}

func (p *dockerProbe) stopWatch(t *testing.T) {
	t.Helper()
	if p.watch == nil {
		return
	}
	pulls, err := p.watch.stop()
	p.watch = nil
	if err != nil {
		t.Error(err)
	}
	if len(pulls) != 0 {
		t.Errorf("the probes pulled images:\n%s", strings.Join(pulls, "\n"))
	}
}

// dockerPullWatch follows the daemon's image pull events from a given moment.
type dockerPullWatch struct {
	command *exec.Cmd
	stderr  bytes.Buffer
	done    chan struct{}
	mu      sync.Mutex
	events  []string
}

func (p *dockerProbe) watchPulls(t *testing.T, since time.Time) *dockerPullWatch {
	t.Helper()
	command := exec.Command(p.cli, "events", "--since", strconv.FormatInt(since.Unix()-1, 10),
		"--filter", "type=image", "--filter", "event=pull", "--format", "{{json .}}")
	watch := &dockerPullWatch{command: command, done: make(chan struct{})}
	command.Stderr = &watch.stderr
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(watch.done)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			watch.mu.Lock()
			watch.events = append(watch.events, scanner.Text())
			watch.mu.Unlock()
		}
	}()
	return watch
}

// stop ends the watch and returns the pulls it saw. A stream that had already
// ended saw nothing after it did, so that is an error rather than a quiet pass.
func (w *dockerPullWatch) stop() ([]string, error) {
	ended := false
	select {
	case <-w.done:
		ended = true
	default:
	}
	_ = w.command.Process.Kill()
	<-w.done
	_ = w.command.Wait()
	w.mu.Lock()
	defer w.mu.Unlock()
	if ended {
		return w.events, fmt.Errorf("the pull watch ended before it was stopped: %s", strings.TrimSpace(w.stderr.String()))
	}
	return slices.Clone(w.events), nil
}

func (p *dockerProbe) cleanup(t *testing.T) {
	if p.watch != nil {
		_, _ = p.watch.stop()
		p.watch = nil
	}
	ids, stderr, err := p.dockerOutput("ps", "--all", "--quiet", "--filter", "label="+dockerProbeRunLabel+"="+p.nonce)
	if err != nil {
		t.Logf("listing probe containers: %v\n%s", err, stderr)
	}
	containers := strings.Fields(ids)
	// A RED RUN SHOWS WHAT EACH CONTAINER SAID AND HOW IT ENDED, because the
	// containers are gone once this returns.
	if t.Failed() {
		for _, id := range containers {
			state, _, _ := p.dockerOutput("inspect", "--format", "{{.Name}} {{.State.Status}} exit={{.State.ExitCode}} restarts={{.RestartCount}}", id)
			stdout, stderr, _ := p.dockerOutput("logs", "--tail", "40", id)
			t.Logf("%s %s\n%s%s", id, strings.TrimSpace(state), stdout, stderr)
		}
	}
	if len(containers) > 0 {
		if _, stderr, err := p.dockerOutput(append([]string{"rm", "--force"}, containers...)...); err != nil {
			t.Logf("removing probe containers: %v\n%s", err, stderr)
		}
	}
	if p.imageA != "" {
		_, _, _ = p.dockerOutput("image", "rm", "--force", p.imageA, p.imageB)
	}
}

// docker runs the Docker CLI and returns its trimmed standard output, failing the
// test with its standard error.
func (p *dockerProbe) docker(t *testing.T, args ...string) string {
	t.Helper()
	stdout, stderr, err := p.dockerOutput(args...)
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, stderr)
	}
	return strings.TrimSpace(stdout)
}

func (p *dockerProbe) dockerOutput(args ...string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, p.cli, args...)
	command.WaitDelay = time.Second
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	return stdout.String(), stderr.String(), err
}

// run starts a container named after this run with the CLI, never pulling, and
// returns its ID. The image is the last argument.
func (p *dockerProbe) run(t *testing.T, name string, args ...string) string {
	t.Helper()
	id := p.docker(t, append([]string{"run", "--detach", "--pull", "never", "--name", p.prefix + "-" + name}, args...)...)
	if !dockerProbeContainerID.MatchString(id) {
		t.Fatalf("docker run printed %q, not a container ID", id)
	}
	return id
}

func (p *dockerProbe) inspect(ctx context.Context, name string) (dockerProbeContainer, error) {
	var container dockerProbeContainer
	err := p.engine.call(ctx, http.MethodGet, "/"+dockerAPIVersion+"/containers/"+url.PathEscape(name)+"/json", nil, []int{http.StatusOK}, &container)
	return container, err
}

func (p *dockerProbe) mustInspect(t *testing.T, name string) dockerProbeContainer {
	t.Helper()
	container, err := p.inspect(t.Context(), name)
	if err != nil {
		t.Fatalf("inspecting %s: %v", name, err)
	}
	return container
}

func (p *dockerProbe) waitRunning(t *testing.T, name string) dockerProbeContainer {
	t.Helper()
	var running dockerProbeContainer
	p.wait(t, 30*time.Second, name+" to be running", func() (bool, error) {
		container, err := p.inspect(t.Context(), name)
		running = container
		return err == nil && container.State.Running, err
	})
	return running
}

// templateSource is the template container as the agent swap's inspect returns it,
// raw Config and HostConfig included: what CreateReplacement clones.
func (p *dockerProbe) templateSource(t *testing.T) dockerContainer {
	t.Helper()
	source, err := p.engine.InspectContainer(t.Context(), p.template)
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func (p *dockerProbe) imageIDs(t *testing.T) []string {
	t.Helper()
	var images []struct {
		ID string `json:"Id"`
	}
	if err := p.engine.call(t.Context(), http.MethodGet, "/"+dockerAPIVersion+"/images/json?all=1", nil, []int{http.StatusOK}, &images); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(images))
	for _, image := range images {
		ids = append(ids, image.ID)
	}
	slices.Sort(ids)
	return ids
}

// report returns the last report a container's idle process printed; a restarted
// container has printed one per start.
func (p *dockerProbe) report(t *testing.T, name string) dockerProbeReport {
	t.Helper()
	var report dockerProbeReport
	p.wait(t, 30*time.Second, "a report from "+name, func() (bool, error) {
		stdout, stderr, err := p.dockerOutput("logs", name)
		if err != nil {
			return false, fmt.Errorf("%v: %s", err, stderr)
		}
		found := false
		for _, line := range strings.Split(stdout, "\n") {
			if encoded, ok := strings.CutPrefix(line, dockerProbeReportPrefix); ok {
				if err := json.Unmarshal([]byte(encoded), &report); err != nil {
					return false, err
				}
				found = true
			}
		}
		return found, nil
	})
	return report
}

func (p *dockerProbe) wait(t *testing.T, within time.Duration, what string, done func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		ok, err := done()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited %s for %s (last error: %v)", within, what, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

var dockerProbeContainerID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// dockerHostnameRoot matches the root of the /etc/hostname bind mount, which Docker
// serves from <data-root>/containers/<id>/hostname. Only the tail is matched, so
// any data root — and a data root on its own filesystem, whose mount root starts at
// /containers — reads the same.
var dockerHostnameRoot = regexp.MustCompile(`/containers/([0-9a-f]{64})/hostname$`)

// dockerHostnameMountID returns the container ID named by the one /etc/hostname
// mount in a mountinfo text, and that mount's line. Field 4 of a mountinfo line is
// the mount's root within its filesystem, field 5 its mount point.
func dockerHostnameMountID(mountinfo string) (string, string, error) {
	var found []string
	for _, line := range strings.Split(mountinfo, "\n") {
		if fields := strings.Fields(line); len(fields) >= 5 && fields[4] == "/etc/hostname" {
			found = append(found, line)
		}
	}
	if len(found) != 1 {
		return "", "", fmt.Errorf("%d /etc/hostname mounts, want exactly one", len(found))
	}
	root := strings.Fields(found[0])[3]
	match := dockerHostnameRoot.FindStringSubmatch(root)
	if match == nil {
		return "", found[0], fmt.Errorf("the /etc/hostname mount root %q names no container", root)
	}
	return match[1], found[0], nil
}

// holdDockerProbeLock takes an exclusive flock on path, the way the updater's lock
// is taken, and reports through the state file: "waiting" once it has found the
// lock taken, "held" once it has it. The descriptor is never closed; only the
// process's death releases the lock.
func holdDockerProbeLock(ctx context.Context, t *testing.T, path, state string) {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatalf("opening the probe lock: %v", err)
	}
	waiting := false
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			t.Fatalf("flock: %v", err)
		}
		if !waiting {
			writeDockerProbeState(t, state, "waiting")
			waiting = true
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	writeDockerProbeState(t, state, "held")
}

func writeDockerProbeState(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path+".tmp", []byte(value), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		t.Fatal(err)
	}
}

// dockerProbeHostCanLock reports whether this process, on the host, can take the
// lock right now, and releases it if so.
func dockerProbeHostCanLock(t *testing.T, path string) bool {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("opening the probe lock on the host: %v", err)
	}
	defer unix.Close(fd)
	err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return false
	}
	if err != nil {
		t.Fatalf("flock on the host: %v", err)
	}
	return true
}

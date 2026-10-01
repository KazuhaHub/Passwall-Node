//go:build unix

package upgrade

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDockerEngine is the Engine as the helper's tests see it.
//
// IT IS SHARED BY TWO UPDATER PROCESSES in the handover tests: a predecessor and
// the successor it starts, each a controller in its own goroutine, both talking
// to one daemon. So every call takes mu, and gives it up again before anything
// that blocks — a delay, a slow stop, a hook — because the real daemon answers
// one caller while another is waiting on a stop.
//
// Hooks run without mu. A hook from the single-process tests reaches into the
// fields directly, which is safe only because nothing else is calling then; a
// hook in a two-process test has to go through the methods instead.
type fakeDockerEngine struct {
	mu sync.Mutex
	// containers is keyed by NAME, which makes it the engine's name index; an
	// ID is resolved by looking through it, as the engine accepts either. The
	// single-process tests build and read this map directly, by name.
	containers map[string]dockerContainer
	images     map[string]dockerImage
	pulled     string
	// pulls counts every PullImage call, successful or not. The handover must
	// never pull, and a count is how a test says "never".
	pulls   int
	onStart func(string)
	// onPull runs inside PullImage. A real pull takes as long as the network does,
	// and it happens while processCurrent holds the helper's main loop — which is
	// the window the heartbeat has to survive.
	onPull func()
	// fail injects an engine failure for one operation, keyed "op" or "op:target",
	// where target is the name or the ID the container was addressed by, or its
	// other identity: a failure keyed by ID finds the container however a caller
	// names it. The ops are inspect, inspect-image, pull, create, start, stop,
	// rename and remove. The rollback path's failure branches are otherwise
	// unreachable from a test, which is why they had no coverage at all.
	fail map[string]error
	// failOnce is fail for a single call: the first matching operation consumes
	// it. It models an engine that misses one request and answers the next.
	failOnce map[string]error
	// onRemove runs at the start of RemoveContainer, before the fake looks the
	// container up — so a test can make one vanish between the stop and the
	// removal, which is what a concurrent `docker rm` or `compose down` does.
	onRemove func(string)
	// slowStop names containers whose stop takes effect but whose answer arrives
	// only after the caller has given up: the call blocks until its context is
	// done. That is how one hung engine call spends a whole rollback budget.
	slowStop map[string]bool
	// delay makes an operation, keyed "op:target", take this long. Like a real
	// client it gives up when its context is done, and then the operation never
	// happens — so a few slow calls can spend a budget without any one failing.
	delay map[string]time.Duration
	// removals records every removal and whether it was forced. A forced removal
	// is a destructive capability, so tests need to see exactly when it is used.
	removals []fakeRemoval
	// createIDs are the identities CreateReplacement hands out, in order, before
	// it falls back to fresh random ones. The single-process tests name the
	// agent's replacement by a fixed identity, so their fixture queues it.
	createIDs []string
	// issued is every identity ever handed out. The engine never reuses one, and
	// neither does the fake, so a journal naming a removed container finds a 404
	// rather than whatever was created after it.
	issued map[string]bool
	// creates records each create: the name and the exact body the real client
	// would send, produced by the real client.
	creates []fakeCreate
	// ops is every container and image call, in order, as it was addressed. A
	// test asserts on it to prove what was never touched.
	ops []fakeOp
	// onCreate runs after a create took effect, with the new container's name
	// and identity, so a test can make the daemon's answer differ from the
	// request.
	onCreate func(name, id string)
	// onInspect answers an inspect in place of the fake when it reports true:
	// a container the test needs under a name it cannot know in advance.
	onInspect func(target string) (dockerContainer, bool)
	// loseCreate makes the next create take effect and then fail, as a create
	// whose answer was lost on the way back does.
	loseCreate bool
	// onStop runs after a stop took effect, with the target as it was
	// addressed.
	onStop func(string)
}

type fakeRemoval struct {
	name  string
	force bool
}

type fakeCreate struct {
	name string
	body map[string]json.RawMessage
}

// fakeOp is one engine call. target is the name or ID the caller used; arg is
// the new name of a rename.
type fakeOp struct {
	op, target, arg string
}

func (f *fakeDockerEngine) record(op, target, arg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops = append(f.ops, fakeOp{op: op, target: target, arg: arg})
}

// opLog is a copy of the op log, safe to read while other callers are active.
func (f *fakeDockerEngine) opLog() []fakeOp {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.ops)
}

// resolve finds a container by name, then by ID. Callers hold mu.
func (f *fakeDockerEngine) resolve(target string) (string, dockerContainer, bool) {
	if container, ok := f.containers[target]; ok {
		return target, container, true
	}
	for name, container := range f.containers {
		if container.ID == target {
			return name, container, true
		}
	}
	return "", dockerContainer{}, false
}

// keys are the targets a failure injection may be keyed by: the address the
// caller used, and the name and ID of the container it resolves to.
func (f *fakeDockerEngine) keys(target string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	keys := []string{target}
	if name, container, ok := f.resolve(target); ok {
		for _, key := range []string{name, container.ID} {
			if key != "" && !slices.Contains(keys, key) {
				keys = append(keys, key)
			}
		}
	}
	return keys
}

func (f *fakeDockerEngine) maybeFail(ctx context.Context, op, target string) error {
	// A REAL CLIENT FAILS ON A DONE CONTEXT without reaching the engine, so the
	// fake does too — otherwise an exhausted budget would be invisible here.
	if err := ctx.Err(); err != nil {
		return errDockerUnavailable
	}
	keys := f.keys(target)
	f.mu.Lock()
	var d time.Duration
	for _, key := range keys {
		if d = f.delay[op+":"+key]; d > 0 {
			break
		}
	}
	f.mu.Unlock()
	if d > 0 {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return errDockerUnavailable
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, key := range append(prefixed(op, keys), op) {
		if err, ok := f.failOnce[key]; ok {
			delete(f.failOnce, key)
			return err
		}
	}
	for _, key := range prefixed(op, keys) {
		if err, ok := f.fail[key]; ok {
			return err
		}
	}
	return f.fail[op]
}

func prefixed(op string, keys []string) []string {
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, op+":"+key)
	}
	return out
}

func (f *fakeDockerEngine) Ping(context.Context) error { return nil }
func (f *fakeDockerEngine) InspectContainer(ctx context.Context, target string) (dockerContainer, error) {
	f.record("inspect", target, "")
	if err := f.maybeFail(ctx, "inspect", target); err != nil {
		return dockerContainer{}, err
	}
	f.mu.Lock()
	onInspect := f.onInspect
	f.mu.Unlock()
	if onInspect != nil {
		if container, ok := onInspect(target); ok {
			return container, nil
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_, container, ok := f.resolve(target)
	if !ok {
		return dockerContainer{}, errDockerNotFound
	}
	return container, nil
}
func (f *fakeDockerEngine) PullImage(ctx context.Context, reference string) error {
	f.record("pull", reference, "")
	f.mu.Lock()
	f.pulls++
	onPull := f.onPull
	f.mu.Unlock()
	if onPull != nil {
		onPull()
	}
	if err := f.maybeFail(ctx, "pull", reference); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.images[reference]; !ok {
		return errDockerNotFound
	}
	f.pulled = reference
	return nil
}
func (f *fakeDockerEngine) InspectImage(ctx context.Context, reference string) (dockerImage, error) {
	f.record("inspect-image", reference, "")
	if err := f.maybeFail(ctx, "inspect-image", reference); err != nil {
		return dockerImage{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	image, ok := f.images[reference]
	if !ok {
		return dockerImage{}, errDockerNotFound
	}
	return image, nil
}
func (f *fakeDockerEngine) StopContainer(ctx context.Context, target string) error {
	f.record("stop", target, "")
	if err := f.maybeFail(ctx, "stop", target); err != nil {
		return err
	}
	f.mu.Lock()
	name, container, ok := f.resolve(target)
	if !ok {
		f.mu.Unlock()
		return errDockerNotFound
	}
	container.State.Running = false
	f.containers[name] = container
	slow := f.slowStop[name] || f.slowStop[container.ID]
	onStop := f.onStop
	f.mu.Unlock()
	if onStop != nil {
		onStop(target)
	}
	if slow {
		<-ctx.Done()
		return errDockerUnavailable
	}
	return nil
}
func (f *fakeDockerEngine) StartContainer(ctx context.Context, target string) error {
	f.record("start", target, "")
	if err := f.maybeFail(ctx, "start", target); err != nil {
		return err
	}
	f.mu.Lock()
	name, container, ok := f.resolve(target)
	if !ok {
		f.mu.Unlock()
		return errDockerNotFound
	}
	// A start of a running container is the engine's 304: nothing changes, and in
	// particular StartedAt does not move.
	if !container.State.Running {
		container.State.Running = true
		container.State.StartedAt = time.Now().UTC()
	}
	f.containers[name] = container
	onStart := f.onStart
	f.mu.Unlock()
	if onStart != nil {
		onStart(target)
	}
	return nil
}
func (f *fakeDockerEngine) RenameContainer(ctx context.Context, target, replacement string) error {
	f.record("rename", target, replacement)
	if err := f.maybeFail(ctx, "rename", target); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	name, container, ok := f.resolve(target)
	if !ok {
		return errDockerNotFound
	}
	if _, exists := f.containers[replacement]; exists {
		return &dockerStatusError{Code: http.StatusConflict}
	}
	delete(f.containers, name)
	container.Name = "/" + replacement
	f.containers[replacement] = container
	return nil
}

// CreateReplacement sends the request through THE REAL CLIENT, into a transport
// that captures it, so the container the fake creates is the one the body
// describes: every label the overlay sets, every key it leaves alone, HostConfig
// verbatim. A fake that built its own version of that body would agree with the
// tests and could disagree with the daemon.
func (f *fakeDockerEngine) CreateReplacement(ctx context.Context, name string, old dockerContainer, image dockerImage, reference string) (string, error) {
	f.record("create", name, "")
	if err := f.maybeFail(ctx, "create", name); err != nil {
		return "", err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.containers[name]; exists {
		return "", &dockerStatusError{Code: http.StatusConflict}
	}
	id := f.nextID()
	var body map[string]json.RawMessage
	capture := &dockerHTTP{client: &http.Client{Transport: dockerRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		data, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &body); err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusCreated, Header: http.Header{},
			Body: io.NopCloser(strings.NewReader(`{"Id":"` + id + `"}`))}, nil
	})}}
	if _, err := capture.CreateReplacement(ctx, name, old, image, reference); err != nil {
		return "", err
	}
	config := make(map[string]json.RawMessage, len(body))
	for key, value := range body {
		if key != "HostConfig" {
			config[key] = value
		}
	}
	// A container created without a hostname gets the daemon's default, its own
	// short ID, and an inspect reports it.
	var hostname string
	_ = json.Unmarshal(config["Hostname"], &hostname)
	if hostname == "" {
		config["Hostname"], _ = json.Marshal(id[:12])
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	created := old
	created.ID = id
	created.Image = image.ID
	created.Name = "/" + name
	created.Config = encoded
	created.HostConfig = bytes.Clone(body["HostConfig"])
	created.Mounts = slices.Clone(old.Mounts)
	created.State = dockerContainer{}.State
	f.containers[name] = created
	f.creates = append(f.creates, fakeCreate{name: name, body: body})
	lost := f.loseCreate
	f.loseCreate = false
	onCreate := f.onCreate
	f.mu.Unlock()
	if onCreate != nil {
		onCreate(name, id)
	}
	f.mu.Lock()
	if lost {
		return "", errDockerUnavailable
	}
	return id, nil
}

// edit changes a container in place, by name or ID, safely beside other
// callers.
func (f *fakeDockerEngine) edit(target string, change func(*dockerContainer)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name, container, ok := f.resolve(target)
	if !ok {
		return
	}
	change(&container)
	f.containers[name] = container
}

// crash is the engine's side of a process exit nobody asked for: the restart
// policy brings the container straight back, so it is Running again, with a new
// StartedAt and one more RestartCount. That is the only trace a crash leaves in
// an inspect, which is why the handover reads exactly those two fields.
func (f *fakeDockerEngine) crash(target string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	name, container, ok := f.resolve(target)
	if !ok || !container.State.Running {
		return errDockerNotFound
	}
	container.RestartCount++
	container.State.StartedAt = time.Now().UTC()
	f.containers[name] = container
	return nil
}

// nextID is a fresh identity the engine has never handed out. Callers hold mu.
func (f *fakeDockerEngine) nextID() string {
	if f.issued == nil {
		f.issued = map[string]bool{}
	}
	for {
		var id string
		if len(f.createIDs) > 0 {
			id, f.createIDs = f.createIDs[0], f.createIDs[1:]
		} else {
			raw := make([]byte, 32)
			_, _ = rand.Read(raw)
			id = hex.EncodeToString(raw)
		}
		if _, _, inUse := f.resolve(id); !f.issued[id] && !inUse {
			f.issued[id] = true
			return id
		}
	}
}

func (f *fakeDockerEngine) RemoveContainer(ctx context.Context, target string, force bool) error {
	f.record("remove", target, "")
	f.mu.Lock()
	f.removals = append(f.removals, fakeRemoval{name: target, force: force})
	onRemove := f.onRemove
	f.mu.Unlock()
	if onRemove != nil {
		onRemove(target)
	}
	if err := f.maybeFail(ctx, "remove", target); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	name, container, ok := f.resolve(target)
	if !ok {
		return errDockerNotFound
	}
	// THE REAL ENGINE REFUSES TO REMOVE A RUNNING CONTAINER without force. This
	// fake used to delete it silently, which made the whole 409 family invisible:
	// a rollback whose stop had failed looked, to the test suite, exactly like one
	// whose stop had succeeded.
	if container.State.Running && !force {
		return &dockerStatusError{Code: http.StatusConflict}
	}
	delete(f.containers, name)
	return nil
}

// The updater beside the agent, as a PSP-generated installation runs it.
const (
	updaterFixtureID      = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	updaterFixtureImageID = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
)

// dockerUpdaterFixture is dockerControllerFixture with the updater container
// beside the agent, profiled as PSP generates it: the helper command, the socket
// and the agent's own control directory bound in, no network, Docker's default
// hostname (its own short ID), the target and agent identity in its environment,
// and the compose labels a project gives it. The target image is the one an
// agent upgrade installs, labelled for the handover and built for this host.
func dockerUpdaterFixture(t *testing.T) (*dockerHelperController, *fakeDockerEngine, dockerContainer) {
	t.Helper()
	controller, engine, request := dockerControllerFixture(t)
	agent := engine.containers[controller.options.TargetName]
	control := ""
	for _, mount := range agent.Mounts {
		if mount.Destination == DockerControlDir {
			control = mount.Source
		}
	}
	config, err := json.Marshal(map[string]any{
		"Hostname":   updaterFixtureID[:12],
		"Image":      DockerImageRepository + ":4.1.0",
		"Entrypoint": []string{"/usr/local/bin/docker-entrypoint.sh"},
		"Cmd":        []string{"--run-docker-upgrade-helper"},
		"Env": []string{
			"PSP_NODE_UPGRADE_TARGET_CONTAINER=" + controller.options.TargetName,
			"PSP_NODE_UPGRADE_TARGET_AGENT_ID=" + controller.options.AgentID,
			"PUID=10001", "PGID=10001",
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		},
		"Labels": map[string]string{
			"com.docker.compose.project":          "passwall-node-server-7",
			"com.docker.compose.service":          "passwall-node-updater",
			"com.docker.compose.container-number": "1",
			"com.docker.compose.config-hash":      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"com.docker.compose.image":            updaterFixtureImageID,
			"org.opencontainers.image.version":    "4.1.0",
			DockerLabelStateSchema:                "9",
			DockerLabelUpgradeContract:            "1",
			DockerLabelUpdaterHandover:            "1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	host, err := json.Marshal(map[string]any{
		"Binds":          []string{dockerSocket + ":" + dockerSocket, control + ":" + DockerControlDir},
		"NetworkMode":    "none",
		"RestartPolicy":  map[string]any{"Name": "unless-stopped", "MaximumRetryCount": 0},
		"Privileged":     false,
		"ReadonlyRootfs": false,
		"CapAdd":         nil,
		"CapDrop":        nil,
		"SecurityOpt":    nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	updater := dockerContainer{
		ID: updaterFixtureID, Image: updaterFixtureImageID, Name: "/node-updater", Config: config, HostConfig: host,
		Mounts: []dockerMount{
			{Type: "bind", Source: dockerSocket, Destination: dockerSocket, RW: true},
			{Type: "bind", Source: control, Destination: DockerControlDir, RW: true},
		},
	}
	updater.State.Running, updater.State.PID = true, 4242
	engine.containers["node-updater"] = updater
	reference := DockerImageRepository + ":" + request.Args.Version
	image := engine.images[reference]
	image.Architecture = runtime.GOARCH
	image.Config.Labels[DockerLabelUpdaterHandover] = "1"
	engine.images[reference] = image
	return controller, engine, updater
}

// THE FAKE HAS TO ADDRESS A CONTAINER THE WAY THE ENGINE DOES once two updater
// processes share it. The agent swap names every container by name, but the
// handover names its successor by the ID the create returned and its predecessor
// by the ID the journal recorded. A fake that knows only names cannot follow a
// container across a rename, and one that hands out the same ID twice cannot tell
// a removed successor from a live one — which is exactly the question the journal
// asks before it lets a second handover start.
func TestFakeEngineAddressesContainersByIDAndName(t *testing.T) {
	ctx := t.Context()
	_, engine, updater := dockerUpdaterFixture(t)
	reference := DockerImageRepository + ":4.1.3"
	image := engine.images[reference]

	t.Run("inspect by name and by ID", func(t *testing.T) {
		byName, err := engine.InspectContainer(ctx, "node-updater")
		if err != nil {
			t.Fatal(err)
		}
		byID, err := engine.InspectContainer(ctx, updater.ID)
		if err != nil {
			t.Fatal(err)
		}
		if byName.ID != updater.ID || byID.ID != updater.ID || byID.Name != "/node-updater" {
			t.Fatalf("by name %s %s, by ID %s %s; want %s /node-updater", byName.ID, byName.Name, byID.ID, byID.Name, updater.ID)
		}
		var config dockerConfig
		if err := json.Unmarshal(byID.Config, &config); err != nil || config.Image != DockerImageRepository+":4.1.0" {
			t.Fatalf("updater fixture config = %s (%v)", byID.Config, err)
		}
	})

	t.Run("every create gets an identity of its own", func(t *testing.T) {
		first, err := engine.CreateReplacement(ctx, "node-updater-next-1", updater, image, reference)
		if err != nil {
			t.Fatal(err)
		}
		second, err := engine.CreateReplacement(ctx, "node-updater-next-2", updater, image, reference)
		if err != nil {
			t.Fatal(err)
		}
		// A full container ID has the shape of a SHA-256 digest.
		if first == second || !validSHA256(first) || !validSHA256(second) {
			t.Fatalf("create returned %q and %q, want two distinct 64-hex IDs", first, second)
		}
		created, err := engine.InspectContainer(ctx, second)
		if err != nil {
			t.Fatal(err)
		}
		if created.Image != image.ID || created.Name != "/node-updater-next-2" || created.State.Running {
			t.Fatalf("created = image %s name %s running %v", created.Image, created.Name, created.State.Running)
		}
		if err := engine.RemoveContainer(ctx, second, false); err != nil {
			t.Fatal(err)
		}
		if _, err := engine.InspectContainer(ctx, "node-updater-next-2"); !errors.Is(err, errDockerNotFound) {
			t.Fatalf("removed by ID, still found by name: %v", err)
		}
		// An identity is never handed out again, even once its container is gone.
		third, err := engine.CreateReplacement(ctx, "node-updater-next-2", updater, image, reference)
		if err != nil {
			t.Fatal(err)
		}
		if third == second || third == first {
			t.Fatalf("an identity was reused: %s", third)
		}
		// A taken name is refused the way the engine refuses it, and nothing is created.
		before := len(engine.containers)
		_, err = engine.CreateReplacement(ctx, "node-updater-next-2", updater, image, reference)
		var status *dockerStatusError
		if !errors.As(err, &status) || status.Code != http.StatusConflict || len(engine.containers) != before {
			t.Fatalf("a create onto a taken name = %v, %d containers (was %d)", err, len(engine.containers), before)
		}
	})

	t.Run("the create records the body the engine would receive", func(t *testing.T) {
		engine.creates = nil
		id, err := engine.CreateReplacement(ctx, "node-updater-next-body", updater, image, reference)
		if err != nil {
			t.Fatal(err)
		}
		if len(engine.creates) != 1 || engine.creates[0].name != "node-updater-next-body" {
			t.Fatalf("creates = %+v", engine.creates)
		}
		body := engine.creates[0].body
		var sent string
		if json.Unmarshal(body["Image"], &sent) != nil || sent != reference {
			t.Fatalf("body Image = %s, want %q", body["Image"], reference)
		}
		if string(body["HostConfig"]) != string(updater.HostConfig) {
			t.Fatalf("body HostConfig = %s, want the source's %s", body["HostConfig"], updater.HostConfig)
		}
		// The container the fake holds is what that body describes.
		created, err := engine.InspectContainer(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		var config map[string]json.RawMessage
		if err := json.Unmarshal(created.Config, &config); err != nil {
			t.Fatal(err)
		}
		if _, nested := config["HostConfig"]; nested || string(config["Cmd"]) != string(body["Cmd"]) || string(created.HostConfig) != string(body["HostConfig"]) {
			t.Fatalf("created config %s, host config %s; body %v", created.Config, created.HostConfig, body)
		}
	})

	t.Run("rename, start, stop and remove accept an ID and keep the name index", func(t *testing.T) {
		id, err := engine.CreateReplacement(ctx, "node-updater-next-x", updater, image, reference)
		if err != nil {
			t.Fatal(err)
		}
		if err := engine.RenameContainer(ctx, id, "node-updater-renamed"); err != nil {
			t.Fatal(err)
		}
		if _, err := engine.InspectContainer(ctx, "node-updater-next-x"); !errors.Is(err, errDockerNotFound) {
			t.Fatalf("the old name still resolves after a rename by ID: %v", err)
		}
		renamed, err := engine.InspectContainer(ctx, "node-updater-renamed")
		if err != nil || renamed.ID != id {
			t.Fatalf("the new name resolves to %s (%v), want %s", renamed.ID, err, id)
		}
		var status *dockerStatusError
		if err := engine.RenameContainer(ctx, id, "node-updater"); !errors.As(err, &status) || status.Code != http.StatusConflict {
			t.Fatalf("a rename onto a taken name = %v, want 409", err)
		}
		if err := engine.StartContainer(ctx, id); err != nil {
			t.Fatal(err)
		}
		if running, _ := engine.InspectContainer(ctx, "node-updater-renamed"); !running.State.Running {
			t.Fatal("a start by ID did not start the container")
		}
		if err := engine.RemoveContainer(ctx, id, false); !errors.As(err, &status) || status.Code != http.StatusConflict {
			t.Fatalf("an unforced removal of a running container = %v, want 409", err)
		}
		if err := engine.StopContainer(ctx, id); err != nil {
			t.Fatal(err)
		}
		if err := engine.RemoveContainer(ctx, id, false); err != nil {
			t.Fatal(err)
		}
		if _, err := engine.InspectContainer(ctx, id); !errors.Is(err, errDockerNotFound) {
			t.Fatalf("a removed container is still found by ID: %v", err)
		}
	})

	t.Run("failures are injected by operation, by name and by ID", func(t *testing.T) {
		engine.failOnce = map[string]error{"create": errDockerUnavailable}
		if _, err := engine.CreateReplacement(ctx, "node-updater-next-f", updater, image, reference); !errors.Is(err, errDockerUnavailable) {
			t.Fatalf("an injected create failure = %v", err)
		}
		if _, err := engine.InspectContainer(ctx, "node-updater-next-f"); !errors.Is(err, errDockerNotFound) {
			t.Fatalf("a failed create left a container: %v", err)
		}
		id, err := engine.CreateReplacement(ctx, "node-updater-next-f", updater, image, reference)
		if err != nil {
			t.Fatalf("a failOnce outlived its one call: %v", err)
		}
		// Keyed by ID, the failure finds the container however it is addressed.
		engine.fail = map[string]error{"start:" + id: &dockerStatusError{Code: http.StatusInternalServerError}}
		if err := engine.StartContainer(ctx, "node-updater-next-f"); err == nil {
			t.Fatal("a start keyed by ID succeeded when addressed by name")
		}
		engine.fail = map[string]error{"inspect-image:" + reference: errDockerUnavailable, "pull": errDockerUnavailable}
		if _, err := engine.InspectImage(ctx, reference); !errors.Is(err, errDockerUnavailable) {
			t.Fatalf("an injected image inspect failure = %v", err)
		}
		pulls := engine.pulls
		if err := engine.PullImage(ctx, reference); !errors.Is(err, errDockerUnavailable) {
			t.Fatalf("an injected pull failure = %v", err)
		}
		if engine.pulls != pulls+1 {
			t.Fatalf("pulls = %d, want %d: a failed pull is still a pull", engine.pulls, pulls+1)
		}
		engine.fail = nil
	})

	t.Run("every call is logged in order, as it was addressed", func(t *testing.T) {
		_, engine, updater := dockerUpdaterFixture(t)
		id, err := engine.CreateReplacement(ctx, "node-updater-next-log", updater, image, reference)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = engine.InspectContainer(ctx, id)
		_ = engine.StartContainer(ctx, id)
		_ = engine.StopContainer(ctx, "node-updater-next-log")
		_ = engine.RenameContainer(ctx, id, "node-updater-moved")
		_ = engine.RemoveContainer(ctx, "node-updater-moved", true)
		_, _ = engine.InspectImage(ctx, reference)
		_ = engine.PullImage(ctx, reference)
		want := []fakeOp{
			{"create", "node-updater-next-log", ""}, {"inspect", id, ""}, {"start", id, ""},
			{"stop", "node-updater-next-log", ""}, {"rename", id, "node-updater-moved"},
			{"remove", "node-updater-moved", ""}, {"inspect-image", reference, ""}, {"pull", reference, ""},
		}
		if got := engine.opLog(); !slices.Equal(got, want) {
			t.Fatalf("op log = %+v\nwant %+v", got, want)
		}
	})
}

// The two inspect fields that betray a crash have to move in the fake the way
// they move in the engine, or a test of "the successor stayed up" proves nothing.
func TestFakeEngineTracksStartsAndCrashes(t *testing.T) {
	ctx := t.Context()
	_, engine, updater := dockerUpdaterFixture(t)
	reference := DockerImageRepository + ":4.1.3"
	id, err := engine.CreateReplacement(ctx, "node-updater-next-c", updater, engine.images[reference], reference)
	if err != nil {
		t.Fatal(err)
	}
	created, _ := engine.InspectContainer(ctx, id)
	if !created.State.StartedAt.IsZero() || created.RestartCount != 0 {
		t.Fatalf("a created container has StartedAt %s and RestartCount %d", created.State.StartedAt, created.RestartCount)
	}
	if err := engine.StartContainer(ctx, id); err != nil {
		t.Fatal(err)
	}
	started, _ := engine.InspectContainer(ctx, id)
	if started.State.StartedAt.IsZero() {
		t.Fatal("a start did not set StartedAt")
	}
	if err := engine.StartContainer(ctx, id); err != nil {
		t.Fatal(err)
	}
	if again, _ := engine.InspectContainer(ctx, id); !again.State.StartedAt.Equal(started.State.StartedAt) {
		t.Fatal("starting a running container moved StartedAt")
	}
	time.Sleep(time.Millisecond)
	if err := engine.crash(id); err != nil {
		t.Fatal(err)
	}
	crashed, _ := engine.InspectContainer(ctx, id)
	if !crashed.State.Running || crashed.RestartCount != 1 || !crashed.State.StartedAt.After(started.State.StartedAt) {
		t.Fatalf("after a crash: running %v, RestartCount %d, StartedAt %s (was %s)", crashed.State.Running,
			crashed.RestartCount, crashed.State.StartedAt, started.State.StartedAt)
	}
}

//go:build unix

package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

type fakeDockerEngine struct {
	containers map[string]dockerContainer
	images     map[string]dockerImage
	pulled     string
	onStart    func(string)
}

func (f *fakeDockerEngine) Ping(context.Context) error { return nil }
func (f *fakeDockerEngine) InspectContainer(_ context.Context, name string) (dockerContainer, error) {
	container, ok := f.containers[name]
	if !ok {
		return dockerContainer{}, errDockerNotFound
	}
	return container, nil
}
func (f *fakeDockerEngine) PullImage(_ context.Context, reference string) error {
	if _, ok := f.images[reference]; !ok {
		return errDockerNotFound
	}
	f.pulled = reference
	return nil
}
func (f *fakeDockerEngine) InspectImage(_ context.Context, reference string) (dockerImage, error) {
	image, ok := f.images[reference]
	if !ok {
		return dockerImage{}, errDockerNotFound
	}
	return image, nil
}
func (f *fakeDockerEngine) StopContainer(_ context.Context, name string) error {
	container, ok := f.containers[name]
	if !ok {
		return errDockerNotFound
	}
	container.State.Running = false
	f.containers[name] = container
	return nil
}
func (f *fakeDockerEngine) StartContainer(_ context.Context, name string) error {
	container, ok := f.containers[name]
	if !ok {
		return errDockerNotFound
	}
	container.State.Running = true
	f.containers[name] = container
	if f.onStart != nil {
		f.onStart(name)
	}
	return nil
}
func (f *fakeDockerEngine) RenameContainer(_ context.Context, name, replacement string) error {
	container, ok := f.containers[name]
	if !ok {
		return errDockerNotFound
	}
	if _, exists := f.containers[replacement]; exists {
		return errors.New("name exists")
	}
	delete(f.containers, name)
	container.Name = "/" + replacement
	f.containers[replacement] = container
	return nil
}
func (f *fakeDockerEngine) CreateReplacement(_ context.Context, name string, old dockerContainer, image dockerImage, reference string) (string, error) {
	if _, exists := f.containers[name]; exists {
		return "", errors.New("name exists")
	}
	var config dockerConfig
	_ = json.Unmarshal(old.Config, &config)
	config.Image = reference
	config.Labels["org.opencontainers.image.version"] = image.Config.Labels["org.opencontainers.image.version"]
	encoded, _ := json.Marshal(config)
	created := old
	created.ID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	created.Image = image.ID
	created.Name = "/" + name
	created.Config = encoded
	created.State.Running = false
	f.containers[name] = created
	return created.ID, nil
}
func (f *fakeDockerEngine) RemoveContainer(_ context.Context, name string) error {
	if _, ok := f.containers[name]; !ok {
		return errDockerNotFound
	}
	delete(f.containers, name)
	return nil
}

func TestDockerUpgradeRequiresReadinessBeforeCommitting(t *testing.T) {
	controller, engine, request := dockerControllerFixture(t)
	engine.onStart = func(name string) {
		if name != controller.options.TargetName {
			return
		}
		var receipt Receipt
		if err := ReadDocument(controller.receiptsDir(), request.Task.ID+".json", &receipt); err != nil {
			t.Fatal(err)
		}
		ready := Ready{
			TaskID: request.Task.ID, InputSHA256: request.Task.InputSHA256,
			Version:         request.Args.Version,
			ActivationNonce: receipt.ActivationNonce, PID: 1,
		}
		ready.BinarySHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		if err := AtomicDocument(controller.requestsDir(), request.Task.ID+".ready.json", ready, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := controller.processCurrent(t.Context()); err != nil {
		t.Fatalf("processCurrent: %v", err)
	}
	active, err := engine.InspectContainer(t.Context(), controller.options.TargetName)
	if err != nil || active.ID == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || !active.State.Running {
		t.Fatalf("replacement not active: id=%s running=%v err=%v", active.ID, active.State.Running, err)
	}
	if _, err := engine.InspectContainer(t.Context(), controller.options.TargetName+"-upgrade-"+shortTaskID(request.Task.ID)); !errors.Is(err, errDockerNotFound) {
		t.Fatalf("rollback container retained after success: %v", err)
	}
	var receipt Receipt
	if err := ReadDocument(controller.receiptsDir(), request.Task.ID+".json", &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Phase != "succeeded" || receipt.Result == nil || !receipt.Result.Restarted || !validSHA256(receipt.Result.BinarySHA256) {
		t.Fatalf("success receipt = %+v", receipt)
	}
}

func TestDockerUpgradeRollsBackWhenReplacementDoesNotConverge(t *testing.T) {
	controller, engine, request := dockerControllerFixture(t)
	controller.options.ReadyWait = 5 * time.Millisecond
	controller.options.Poll = time.Millisecond
	if err := controller.processCurrent(t.Context()); err == nil {
		t.Fatal("upgrade without readiness succeeded")
	}
	active, err := engine.InspectContainer(t.Context(), controller.options.TargetName)
	if err != nil || active.ID != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || !active.State.Running {
		t.Fatalf("previous container not restored: id=%s running=%v err=%v", active.ID, active.State.Running, err)
	}
	var receipt Receipt
	if err := ReadDocument(controller.receiptsDir(), request.Task.ID+".json", &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Phase != "failed" || receipt.Result != nil {
		t.Fatalf("rollback receipt = %+v", receipt)
	}
}

func TestDockerUpgradeRecoveryKeepsOriginalContainerBeforeRename(t *testing.T) {
	for _, running := range []bool{true, false} {
		t.Run(map[bool]string{true: "running", false: "stopped"}[running], func(t *testing.T) {
			controller, engine, request := dockerControllerFixture(t)
			old := engine.containers[controller.options.TargetName]
			old.State.Running = running
			engine.containers[controller.options.TargetName] = old
			transaction := dockerTransaction{
				OldContainerID: old.ID, OldImage: DockerImageRepository + ":beta",
				BackupName: controller.options.TargetName + "-upgrade-" + shortTaskID(request.Task.ID),
				NewImageID: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
				NewImage:   DockerImageRepository + ":" + request.Args.Version,
			}
			receipt := Receipt{Request: request, Phase: "activating", Result: &Result{Version: request.Args.Version, PreviousVersion: request.Args.ExpectedVersion}}
			if err := controller.writeTransaction(request.Task.ID, transaction); err != nil {
				t.Fatal(err)
			}
			if err := controller.writeReceipt(receipt); err != nil {
				t.Fatal(err)
			}
			if err := controller.recover(t.Context(), receipt); err == nil {
				t.Fatal("interrupted activation reported success")
			}
			active, err := engine.InspectContainer(t.Context(), controller.options.TargetName)
			if err != nil || active.ID != old.ID || !active.State.Running {
				t.Fatalf("original container not kept active: id=%s running=%v err=%v", active.ID, active.State.Running, err)
			}
			var final Receipt
			if err := ReadDocument(controller.receiptsDir(), request.Task.ID+".json", &final); err != nil {
				t.Fatal(err)
			}
			if final.Phase != "failed" || final.Result != nil || final.ErrorCode != "agent_upgrade_failed" {
				t.Fatalf("recovery receipt = %+v", final)
			}
		})
	}
}

func dockerControllerFixture(t *testing.T) (*dockerHelperController, *fakeDockerEngine, Request) {
	t.Helper()
	control := t.TempDir()
	for _, name := range []string{"requests", "receipts"} {
		if err := os.Mkdir(filepath.Join(control, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	agentID := "agt_docker_upgrade_test"
	currentVersion, targetVersion := "4.1.0", "4.1.3"
	labels := map[string]string{
		DockerLabelManaged: "true", DockerLabelRole: "agent", DockerLabelAgentID: agentID,
		DockerLabelStateSchema: "9", DockerLabelUpgradeContract: "1",
		"org.opencontainers.image.version": currentVersion,
	}
	config, _ := json.Marshal(dockerConfig{
		Image:  DockerImageRepository + ":beta",
		Env:    []string{"PSP_NODE_AGENT_ID=" + agentID, "PSP_NODE_DOCKER_REMOTE_UPGRADE=true"},
		Labels: labels,
	})
	host, _ := json.Marshal(dockerHostConfig{NetworkMode: "host", ReadonlyRootfs: true})
	old := dockerContainer{
		ID:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Name: "/node-agent", Config: config, HostConfig: host,
		Mounts: []dockerMount{
			{Type: "volume", Name: "data", Destination: DockerDataDir, RW: true},
			{Type: "volume", Name: "control", Destination: DockerControlDir, RW: true},
		},
	}
	old.State.Running = true
	image := dockerImage{ID: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", OS: "linux", Architecture: "amd64"}
	image.Config.Labels = map[string]string{
		"org.opencontainers.image.version": targetVersion,
		DockerLabelStateSchema:             "9", DockerLabelUpgradeContract: "1",
	}
	engine := &fakeDockerEngine{
		containers: map[string]dockerContainer{"node-agent": old},
		images:     map[string]dockerImage{DockerImageRepository + ":" + targetVersion: image},
	}
	args, _ := json.Marshal(protocol.AgentUpgradeArgs{Version: targetVersion, ExpectedVersion: currentVersion})
	task := protocol.Task{ID: "tsk_docker_upgrade_001", Kind: TaskKind, Args: args, NotAfterMS: 2000}
	task.InputSHA256 = protocol.ComputeTaskInputSHA256(task.Kind, task.Args)
	request := Request{Task: task, Args: protocol.AgentUpgradeArgs{Version: targetVersion, ExpectedVersion: currentVersion}, BootID: "boot", AuthorizedUntilBoottimeNS: int64(time.Minute)}
	if err := AtomicDocument(filepath.Join(control, "requests"), "request.json", request, 0600); err != nil {
		t.Fatal(err)
	}
	controller := &dockerHelperController{options: dockerHelperOptions{
		ControlDir: control, TargetName: "node-agent", AgentID: agentID,
		NodeUID: uint32(os.Geteuid()), NodeGID: uint32(os.Getegid()), Schema: 9,
		Engine: engine, Clock: func() (string, int64, error) { return "boot", int64(time.Second), nil },
		Poll: time.Millisecond, ReadyWait: time.Second, Logger: log.New(io.Discard, "", 0),
	}}
	return controller, engine, request
}

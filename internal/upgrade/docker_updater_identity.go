package upgrade

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// The updater's command and the two environment variables that bind it to its
// agent. They are permanent across releases: a successor is created from its
// predecessor's configuration, and the agent swap creates the agent from its
// own, so a release that renamed any of them would break the very upgrade that
// installs it.
const (
	dockerHelperCommand      = "--run-docker-upgrade-helper"
	dockerTargetContainerEnv = "PSP_NODE_UPGRADE_TARGET_CONTAINER"
	dockerTargetAgentIDEnv   = "PSP_NODE_UPGRADE_TARGET_AGENT_ID"
)

// errUpdaterMutationRefused is mutateUpdater declining to act. Nothing reached
// the engine.
var errUpdaterMutationRefused = errors.New("updater mutation refused")

// isUpdaterContainer reports why container is not an updater of this agent, or
// nil when it is one.
//
// AN UPDATER IS RECOGNISED BY WHAT IT IS, NOT BY ITS NAME. It runs the helper
// command, carries this agent's identity in its environment, holds the Docker
// socket, and binds the agent's own control directory — the last is what proves
// it is this agent's pair and not another node's on the same host. Then it must
// stay what an updater is allowed to be:
//
//   - not privileged and not on the host network, so the handover never creates
//     a root container with more reach than the one it replaces;
//   - an official image;
//   - sharing no other source with the agent, by path, so the socket holder
//     never receives the node's data or its credential. A bind of a directory
//     that contains one of the agent's sources counts as sharing it.
//
// The agent can never pass: it never holds the socket (validateContainer
// refuses one that does), and it is refused here by name and identity as well.
func (c *dockerHelperController) isUpdaterContainer(container, agent dockerContainer) error {
	var config dockerConfig
	var host dockerHostConfig
	if json.Unmarshal(container.Config, &config) != nil || json.Unmarshal(container.HostConfig, &host) != nil {
		return errors.New("its metadata is invalid")
	}
	if container.ID == "" || container.ID == agent.ID || container.Name == "/"+c.options.TargetName {
		return errors.New("it is the agent")
	}
	if !slices.Equal(config.Cmd, []string{dockerHelperCommand}) {
		return errors.New("it does not run the updater command")
	}
	if !containsEnv(config.Env, dockerTargetContainerEnv, c.options.TargetName) || !containsEnv(config.Env, dockerTargetAgentIDEnv, c.options.AgentID) {
		return errors.New("it does not name this agent")
	}
	if host.Privileged || host.NetworkMode == "host" {
		return errors.New("it is privileged or on the host network")
	}
	if !officialNodeImage(config.Image) {
		return errors.New("it does not run the official image")
	}
	agentControl := ""
	for _, mount := range agent.Mounts {
		if mount.Destination == DockerControlDir {
			agentControl = mount.Source
		}
	}
	if agentControl == "" {
		return errors.New("the agent has no control directory to compare with")
	}
	socket, control := false, false
	for _, mount := range container.Mounts {
		switch mount.Destination {
		case dockerSocket:
			socket = mount.Type == "bind"
		case DockerControlDir:
			control = (mount.Type == "bind" || mount.Type == "volume") && mount.RW && mount.Source == agentControl
		}
		for _, theirs := range agent.Mounts {
			if theirs.Destination != DockerControlDir && pathsOverlap(mount.Source, theirs.Source) {
				return fmt.Errorf("it shares the agent's %s", theirs.Destination)
			}
		}
	}
	if !socket {
		return errors.New("it does not hold the Docker socket")
	}
	if !control {
		return errors.New("it does not bind this agent's control directory, writable")
	}
	return nil
}

// pathsOverlap reports whether one host path is, or contains, the other. An
// empty source — a tmpfs, say — overlaps nothing.
func pathsOverlap(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	a, b = filepath.Clean(a), filepath.Clean(b)
	within := func(inner, outer string) bool {
		return inner == outer || outer == "/" || strings.HasPrefix(inner, outer+"/")
	}
	return within(a, b) || within(b, a)
}

// successorSource is the predecessor's own inspect, as the successor's create
// will clone it: unchanged, except that Docker's default hostname is removed.
//
// THE CLONE MUST ANSWER TO ITS OWN NAME. CreateReplacement copies Config
// verbatim, and a container Docker named carries Config.Hostname = its own short
// ID, so the clone would answer to its predecessor's. Removing it lets the
// daemon give the clone its own. Only that default goes; a hostname an operator
// set is the operator's and is kept. The container passed in is not modified.
func successorSource(self dockerContainer) (dockerContainer, error) {
	var config map[string]json.RawMessage
	if err := json.Unmarshal(self.Config, &config); err != nil || config == nil {
		return dockerContainer{}, errors.New("own container configuration is invalid")
	}
	var hostname string
	if raw, ok := config["Hostname"]; !ok || json.Unmarshal(raw, &hostname) != nil || len(self.ID) < 12 || hostname != self.ID[:12] {
		return self, nil
	}
	delete(config, "Hostname")
	encoded, err := json.Marshal(config)
	if err != nil {
		return dockerContainer{}, err
	}
	source := self
	source.Config = encoded
	return source, nil
}

// dockerSecuritySubset is every HostConfig field that decides what a container
// can reach: privilege, capabilities, namespaces, devices, mounts, the network,
// and the restart policy that decides whether it comes back.
var dockerSecuritySubset = []string{
	"Privileged", "NetworkMode", "CapAdd", "CapDrop", "SecurityOpt", "ReadonlyRootfs",
	"PidMode", "IpcMode", "UTSMode", "UsernsMode", "CgroupnsMode",
	"Devices", "DeviceRequests", "Binds", "Mounts", "Tmpfs", "GroupAdd", "RestartPolicy",
}

// securitySubsetEqual reports the first security field in which b's HostConfig
// differs from a's, or nil when none does.
//
// THE SUCCESSOR'S PROFILE IS ITS PREDECESSOR'S, EXACTLY. Both sides are read
// back from the daemon, so both are normalised the same way, and the comparison
// is of the raw values — a field present on one side and absent on the other is
// a difference too. Only the layout of the JSON is ignored.
func securitySubsetEqual(a, b dockerContainer) error {
	var left, right map[string]json.RawMessage
	if json.Unmarshal(a.HostConfig, &left) != nil || json.Unmarshal(b.HostConfig, &right) != nil {
		return errors.New("HostConfig is invalid")
	}
	for _, key := range dockerSecuritySubset {
		l, inLeft := left[key]
		r, inRight := right[key]
		if inLeft != inRight || !sameJSON(l, r) {
			return fmt.Errorf("HostConfig.%s differs", key)
		}
	}
	return nil
}

func sameJSON(a, b json.RawMessage) bool {
	var left, right bytes.Buffer
	if json.Compact(&left, a) != nil || json.Compact(&right, b) != nil {
		return bytes.Equal(a, b)
	}
	return bytes.Equal(left.Bytes(), right.Bytes())
}

// updaterMutation is one engine call that changes something, as the handover
// asks mutateUpdater to make it.
type updaterMutation struct {
	// op is "create", "start", "stop", "rename" or "remove".
	op string
	// target is the container's ID or name; for "create", the new container's
	// name.
	target string
	// rename is the new name of a "rename".
	rename string
	// force removes a running container; "remove" only.
	force bool
	// source, image and reference are the clone, its image and the exact tag
	// of a "create".
	source    dockerContainer
	image     dockerImage
	reference string
}

// mutateUpdater is the ONLY way handover code changes anything in the engine.
//
// THE AGENT IS UNTOUCHABLE HERE, BY CONSTRUCTION, not by the care of each caller.
// The guard reads the live agent first and refuses to act if it cannot. It then
// refuses the agent by name and by live identity, refuses the agent's name as
// the name of anything created or renamed, and acts only on one of this agent's
// updaters (isUpdaterContainer): a create must clone one, and anything else must
// inspect as one. A refusal makes no mutating call at all.
//
// IT ACTS ON THE IDENTITY IT CHECKED. A container addressed by name is inspected,
// checked, and then started, stopped, renamed or removed by the ID that inspect
// returned, so a name that changed hands between the check and the call cannot
// redirect it. A container that is gone is reported as errDockerNotFound, which a
// caller may count as done.
func (c *dockerHelperController) mutateUpdater(ctx context.Context, m updaterMutation) (string, error) {
	refuse := func(why string) (string, error) {
		return "", fmt.Errorf("%w: %s %s: %s", errUpdaterMutationRefused, m.op, m.target, why)
	}
	agent, err := c.options.Engine.InspectContainer(ctx, c.options.TargetName)
	if err != nil {
		return refuse("the agent cannot be identified")
	}
	if m.target == c.options.TargetName || m.target == agent.ID {
		return refuse("it is the agent")
	}
	switch m.op {
	case "create":
		if !dockerObjectName.MatchString(m.target) {
			return refuse("the name is invalid")
		}
		if !officialNodeImage(m.reference) {
			return refuse("the image is not an official release")
		}
		if err := c.isUpdaterContainer(m.source, agent); err != nil {
			return refuse("the clone's source is not an updater: " + err.Error())
		}
		return c.options.Engine.CreateReplacement(ctx, m.target, m.source, m.image, m.reference)
	case "start", "stop", "rename", "remove":
	default:
		return refuse("the operation is unknown")
	}
	if m.op == "rename" && (!dockerObjectName.MatchString(m.rename) || m.rename == c.options.TargetName) {
		return refuse("the new name is invalid or the agent's")
	}
	current, err := c.options.Engine.InspectContainer(ctx, m.target)
	if err != nil {
		return "", err
	}
	if err := c.isUpdaterContainer(current, agent); err != nil {
		return refuse("not an updater; left alone: " + err.Error())
	}
	switch m.op {
	case "start":
		err = c.options.Engine.StartContainer(ctx, current.ID)
	case "stop":
		err = c.options.Engine.StopContainer(ctx, current.ID)
	case "rename":
		err = c.options.Engine.RenameContainer(ctx, current.ID, m.rename)
	case "remove":
		err = c.options.Engine.RemoveContainer(ctx, current.ID, m.force)
	}
	return "", err
}

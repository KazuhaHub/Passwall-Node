package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// dockerHandoverCallBudget is how long one engine call of the handover may take.
const dockerHandoverCallBudget = 30 * time.Second

// dockerHostnameRoot matches the root of a container's /etc/hostname bind mount,
// which Docker serves from <data-root>/containers/<id>/hostname.
//
// ONLY THE TAIL IS MATCHED, because the data root is wherever the host put it.
// On the root filesystem the mountinfo root reads /var/lib/docker/containers/…;
// on a NAS whose volume is a filesystem of its own (UGOS, Synology) it reads
// /@docker/containers/…; on a dedicated disk mounted at the data root it starts
// at /containers/…; under a rootless daemon it is in the user's home. All of
// them end the same way, and nothing else that mounts /etc/hostname does —
// Podman keeps the file under a userdata directory, for one.
var dockerHostnameRoot = regexp.MustCompile(`/containers/([0-9a-f]{64})/hostname$`)

// parseMountinfoSelfID returns the container ID named by the single
// /etc/hostname mount in a /proc/self/mountinfo text. Field 4 of a mountinfo
// line is the mount's root within its filesystem and field 5 its mount point;
// optional fields come after those, so the positions are fixed.
//
// EXACTLY ONE such mount, or nothing. Two would mean something other than the
// runtime arranged this process's view, and choosing between them would be a
// guess about which container this is — the one question a socket holder must
// not guess.
func parseMountinfoSelfID(mountinfo string) (string, error) {
	var roots []string
	for _, line := range strings.Split(mountinfo, "\n") {
		if fields := strings.Fields(line); len(fields) >= 5 && fields[4] == "/etc/hostname" {
			roots = append(roots, fields[3])
		}
	}
	if len(roots) != 1 {
		return "", fmt.Errorf("own mountinfo has %d /etc/hostname mounts, want exactly one", len(roots))
	}
	match := dockerHostnameRoot.FindStringSubmatch(roots[0])
	if match == nil {
		return "", fmt.Errorf("own /etc/hostname mount root %q names no Docker container", roots[0])
	}
	return match[1], nil
}

// resolveSelf finds the container this process runs in, and proves it.
//
// MOUNTINFO IS THE CLAIM; THE ENGINE AND THE HOSTNAME CONFIRM IT. The ID it names
// has to inspect as exactly that container, running, and when the container has
// a hostname this process has to answer to it. That rejects a mountinfo line
// that points at some other container. The hostname is never the evidence on its
// own, because a clone copies Config.Hostname from its source: the updater's
// successor would otherwise answer to its predecessor's short ID. That is also
// why the handover strips a Docker-default hostname from the clone.
//
// Any failure resolves nothing. The caller then runs with the handover disabled,
// which is today's updater, and says why once.
func (c *dockerHelperController) resolveSelf(ctx context.Context) (dockerContainer, error) {
	readMountinfo := c.options.Mountinfo
	if readMountinfo == nil {
		readMountinfo = readSelfMountinfo
	}
	mountinfo, err := readMountinfo()
	if err != nil {
		return dockerContainer{}, fmt.Errorf("own mountinfo is unreadable: %w", err)
	}
	id, err := parseMountinfoSelfID(mountinfo)
	if err != nil {
		return dockerContainer{}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, c.handoverCallBudget())
	defer cancel()
	self, err := c.options.Engine.InspectContainer(callCtx, id)
	if err != nil {
		return dockerContainer{}, fmt.Errorf("own container %s cannot be inspected: %w", id[:12], err)
	}
	if self.ID != id || !self.State.Running {
		return dockerContainer{}, fmt.Errorf("own container %s does not inspect as itself, running", id[:12])
	}
	var config dockerConfig
	if err := json.Unmarshal(self.Config, &config); err != nil {
		return dockerContainer{}, errors.New("own container configuration is invalid")
	}
	if config.Hostname != "" {
		readHostname := c.options.Hostname
		if readHostname == nil {
			readHostname = os.Hostname
		}
		if hostname, err := readHostname(); err != nil || hostname != config.Hostname {
			return dockerContainer{}, fmt.Errorf("own hostname does not match container %s's %q", id[:12], config.Hostname)
		}
	}
	return self, nil
}

func (c *dockerHelperController) handoverCallBudget() time.Duration {
	if c.options.HandoverCallBudget > 0 {
		return c.options.HandoverCallBudget
	}
	return dockerHandoverCallBudget
}

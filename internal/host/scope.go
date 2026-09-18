package host

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path"
	"strings"

	"github.com/KazuhaHub/passwall-node/protocol"
)

// mintSampleID produces the per-collection identity the panel is idempotent on.
//
// Sixteen random bytes rather than a counter or a timestamp: the panel keys
// "have I already stored this sample" on it, and a value that repeated across a
// restart would make a new observation look like a duplicate of an old one and
// be silently dropped.
func mintSampleID() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		// Unreachable on any supported platform. Returning a fixed value would
		// collide deterministically, so this returns something at least shaped
		// correctly and lets the panel's own identity check be the backstop.
		return strings.Repeat("0", protocol.SampleIDBytes)
	}
	return hex.EncodeToString(buffer)
}

// containerMarkers identify a container runtime in a cgroup path.
//
// Checked as substrings because the same runtime spells its cgroup path
// differently on v1 and v2, and the alternatives are a per-runtime table that
// goes stale against every new orchestrator.
var containerMarkers = []string{"docker", "containerd", "kubepods", "libpod", "podman", "lxc"}

// detectScope classifies what this sample's numbers describe.
func (c *collector) detectScope() protocol.HostScope {
	cgroupVersion := c.detectCgroupVersion()
	markers := c.detectContainerMarkers()
	return protocol.HostScope{
		Deployment:          c.detectDeployment(markers),
		ResourceScope:       c.detectResourceScope(markers),
		CgroupVersion:       cgroupVersion,
		DataFilesystemScope: c.detectDataFilesystemScope(),
	}
}

// detectCgroupVersion distinguishes the two generations by their marker files.
//
// cgroup.controllers exists only in the v2 unified hierarchy; a bare controller
// directory at the root only in v1. Zero means neither could be read, which is
// an honest "I cannot tell" rather than a default of v2.
func (c *collector) detectCgroupVersion() int {
	if c.sysEntryExists("fs/cgroup/cgroup.controllers") {
		return 2
	}
	for _, controller := range []string{"fs/cgroup/memory", "fs/cgroup/cpu", "fs/cgroup/cpuacct"} {
		if c.sysEntryExists(controller) {
			return 1
		}
	}
	return 0
}

func (c *collector) sysEntryExists(relative string) bool {
	location, err := resolve(c.options.SysRoot, relative)
	if err != nil {
		return false
	}
	_, err = os.Stat(location)
	return err == nil
}

func (c *collector) procEntryExists(relative string) bool {
	location, err := resolve(c.options.ProcRoot, relative)
	if err != nil {
		return false
	}
	_, err = os.Stat(location)
	return err == nil
}

// detectContainerMarkers reports the markers found in this process's cgroup
// path AND in PID 1's.
//
// Both are read because they disagree in the cases that matter: a container with
// its own cgroup namespace shows "/" for itself while PID 1 still records the
// runtime's path, and a host running containerised workloads shows markers in
// neither. Reading only one of them is how a container gets reported as a host.
func (c *collector) detectContainerMarkers() []string {
	var found []string
	for _, relative := range []string{"self/cgroup", "1/cgroup"} {
		raw, err := c.readProc(relative)
		if err != nil {
			continue
		}
		content := strings.ToLower(string(raw))
		for _, marker := range containerMarkers {
			if strings.Contains(content, marker) {
				found = append(found, marker)
			}
		}
	}
	return found
}

func (c *collector) detectDeployment(markers []string) protocol.Deployment {
	// A container is reported before systemd, because a container commonly runs
	// systemd as PID 1 — checking systemd first would label every such
	// container a plain systemd host.
	if len(markers) > 0 {
		return protocol.DeploymentDocker
	}
	if raw, err := c.readProc("1/comm"); err == nil && strings.TrimSpace(string(raw)) == "systemd" {
		return protocol.DeploymentSystemd
	}
	if c.procEntryExists("self/status") {
		return protocol.DeploymentManual
	}
	// Without a readable proc there is nothing to base a claim on.
	return protocol.DeploymentUnknown
}

// detectResourceScope says whether the sections describe the host or a
// container.
//
// It reports MIXED for a container rather than CONTAINER, and that is the honest
// answer rather than a hedge: the CPU and network sections come from the host's
// own /proc, while the cgroup sections describe the container's limit. A panel
// that rounds this down to "host" draws a 512 MiB container against the host's
// RAM; one that rounds it up to "container" presents host-wide CPU as the
// container's usage. Neither is recoverable once the label is lost.
func (c *collector) detectResourceScope(markers []string) protocol.ResourceScope {
	if len(markers) > 0 {
		return protocol.ScopeMixed
	}
	if !c.procEntryExists("self/status") {
		return protocol.ScopeUnknown
	}
	return protocol.ScopeHost
}

// detectDataFilesystemScope classifies the filesystem the data directory lives
// on.
//
// It is resolved from the mount table rather than assumed from the deployment
// type: a container with a host bind mount genuinely reports the host's disk,
// and calling that container-local would understate the capacity the operator is
// watching. The longest matching mount point wins, so a bind mount nested inside
// a larger one is classified by its own entry.
func (c *collector) detectDataFilesystemScope() protocol.DataFilesystemScope {
	if c.options.DataDir == "" {
		return protocol.FilesystemScopeUnknown
	}
	raw, err := c.readProc("self/mountinfo")
	if err != nil {
		return protocol.FilesystemScopeUnknown
	}
	filesystem, ok := filesystemTypeFor(string(raw), path.Clean(c.options.DataDir))
	if !ok {
		return protocol.FilesystemScopeUnknown
	}
	switch {
	case filesystem == "overlay", filesystem == "tmpfs", filesystem == "ramfs":
		// A writable layer or an in-memory filesystem: the capacity is not the
		// host's disk, and reporting it as one is what makes a panel claim a
		// node has terabytes free when the container has a 10 GiB layer.
		return protocol.FilesystemScopeContainerMount
	case strings.HasPrefix(filesystem, "fuse"), strings.HasPrefix(filesystem, "nfs"), strings.HasPrefix(filesystem, "cifs"):
		// A network or FUSE mount is a host-level mount even when a container
		// uses it: its capacity belongs to whatever serves it, not to the
		// container's writable layer.
		return protocol.FilesystemScopeHostMount
	default:
		return protocol.FilesystemScopeHostMount
	}
}

// parseMountInfo extracts the mount point and filesystem type of each entry.
//
// The separator is the "-" field, and everything after the mount options in the
// first half is optional and variable length, so the fields are located from
// that separator rather than by counting from the start.
func parseMountInfo(raw string) map[string]string {
	mounts := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		separator := -1
		for index, field := range fields {
			if field == "-" {
				separator = index
				break
			}
		}
		if separator < 0 || separator+1 >= len(fields) {
			continue
		}
		mounts[fields[4]] = fields[separator+1]
	}
	return mounts
}

// filesystemTypeFor returns the type of the longest mount point containing the
// given path.
func filesystemTypeFor(raw, target string) (string, bool) {
	mounts := parseMountInfo(raw)
	best, bestLength := "", -1
	for mountPoint, filesystem := range mounts {
		if !mountContains(mountPoint, target) {
			continue
		}
		if len(mountPoint) > bestLength {
			best, bestLength = filesystem, len(mountPoint)
		}
	}
	if bestLength < 0 {
		return "", false
	}
	return best, true
}

// mountContains reports whether a mount point contains a path, comparing whole
// path segments.
//
// A plain prefix test would put "/var/lib/passwall-node-backup" inside
// "/var/lib/passwall-node", and with the longest-match rule that mislabelling
// would win over the correct, shorter entry.
func mountContains(mountPoint, target string) bool {
	if mountPoint == "/" {
		return true
	}
	return target == mountPoint || strings.HasPrefix(target, strings.TrimSuffix(mountPoint, "/")+"/")
}

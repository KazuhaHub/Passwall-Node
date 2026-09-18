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

// detectContainer reports whether this process is running inside a container.
//
// TWO SIGNALS, BECAUSE ONE IS NOT ENOUGH, and a real container proved it. The
// cgroup path carries the runtime's name only when the cgroup namespace is
// SHARED — with a private one, which is now the default in several runtimes,
// /proc/self/cgroup reads "0::/" and names nothing at all. An agent in that
// container was reporting itself as a plain manual host with HOST resource
// scope, which is exactly the confusion this field exists to prevent.
//
// So the root filesystem is checked too: a container's root is an overlay in
// almost every runtime, and that survives a private namespace.
func (c *collector) detectContainer() bool {
	if len(c.containerPathMarkers()) > 0 {
		return true
	}
	return c.rootFilesystemType() == "overlay"
}

// containerPathMarkers reports the runtime names found in this process's cgroup
// path AND PID 1's.
//
// Both are read because they disagree in the cases that matter: a container with
// its own cgroup namespace shows "/" for itself while PID 1 still records the
// runtime's path, and a host running containerised workloads shows markers in
// neither. Reading only one of them is how a container gets reported as a host.
func (c *collector) containerPathMarkers() []string {
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

func (c *collector) rootFilesystemType() string {
	raw, err := c.readProc("self/mountinfo")
	if err != nil {
		return ""
	}
	return parseMountInfo(string(raw))["/"]
}

// detectScope classifies what this sample's numbers describe.
func (c *collector) detectScope() protocol.HostScope {
	// Resolved once and passed down: the same answer decides the deployment, the
	// resource scope and what a memory-backed data filesystem means, and
	// re-deriving it three times would let the three disagree.
	inContainer := c.detectContainer()
	return protocol.HostScope{
		Deployment:          c.detectDeployment(inContainer),
		ResourceScope:       c.detectResourceScope(inContainer),
		CgroupVersion:       c.cgroupVersion,
		DataFilesystemScope: c.detectDataFilesystemScope(inContainer),
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

func (c *collector) detectDeployment(inContainer bool) protocol.Deployment {
	// A container is reported before systemd, because a container commonly runs
	// systemd as PID 1 — checking systemd first would label every such
	// container a plain systemd host. The protocol's enumeration has no separate
	// value for a non-Docker runtime, so any container is reported as the one it
	// does have.
	if inContainer {
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
func (c *collector) detectResourceScope(inContainer bool) protocol.ResourceScope {
	if inContainer {
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
//
// THE FILESYSTEM TYPE ALONE IS NOT THE ANSWER, which a real host makes obvious:
// /tmp and /run are tmpfs on a bare machine, so mapping tmpfs to
// "container_mount" would tell the panel that a plain host's figures describe
// somewhere else entirely. An overlay is a container layer wherever it is found;
// a memory-backed filesystem is a container's only when the agent is IN one.
func (c *collector) detectDataFilesystemScope(inContainer bool) protocol.DataFilesystemScope {
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
	case filesystem == "overlay":
		// Nothing runs an overlay as its own root filesystem except a container
		// runtime building a writable layer.
		return protocol.FilesystemScopeContainerMount
	case filesystem == "tmpfs", filesystem == "ramfs":
		if inContainer {
			return protocol.FilesystemScopeContainerMount
		}
		return protocol.FilesystemScopeHostMount
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

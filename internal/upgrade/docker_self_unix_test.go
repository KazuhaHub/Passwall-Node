//go:build unix

package upgrade

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// MOUNTINFO IS ONLY THE CLAIM; THE ENGINE AND THE HOSTNAME CONFIRM IT. The ID
// read from /proc/self/mountinfo has to inspect as exactly that container, and
// running, and when the container has a hostname this process has to be the one
// answering to it — so a mountinfo line that names some other container cannot
// make this process act as that container. Hostname alone is never the evidence,
// because a clone copies Config.Hostname from the container it was made from.
func TestResolveSelfCrossChecksInspectAndHostname(t *testing.T) {
	template, err := os.ReadFile(filepath.Join("testdata", "mountinfo", "overlay2-var-lib-docker.txt"))
	if err != nil {
		t.Fatal(err)
	}
	const fixtureID = "6b1f4e0c9d2a87b3e5f40c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5"
	naming := func(id string) func() (string, error) {
		return func() (string, error) { return strings.ReplaceAll(string(template), fixtureID, id), nil }
	}
	hostname := func(name string) func() (string, error) {
		return func() (string, error) { return name, nil }
	}
	broken := func() (string, error) { return "", errors.New("unreadable") }

	for _, tc := range []struct {
		name  string
		setup func(*dockerHelperController, *fakeDockerEngine, dockerContainer)
		ok    bool
	}{
		{
			name: "the container the mountinfo names, running, answering to its hostname",
			ok:   true,
		},
		{
			name:  "mountinfo cannot be read",
			setup: func(c *dockerHelperController, _ *fakeDockerEngine, _ dockerContainer) { c.options.Mountinfo = broken },
		},
		{
			name: "mountinfo names no container",
			setup: func(c *dockerHelperController, _ *fakeDockerEngine, _ dockerContainer) {
				c.options.Mountinfo = func() (string, error) { return "22 1 259:2 / / rw - ext4 /dev/sda1 rw\n", nil }
			},
		},
		{
			name: "the named container does not exist",
			setup: func(c *dockerHelperController, _ *fakeDockerEngine, _ dockerContainer) {
				c.options.Mountinfo = naming(strings.Repeat("c", 64))
			},
		},
		{
			name: "the engine answers with a different container",
			setup: func(_ *dockerHelperController, e *fakeDockerEngine, self dockerContainer) {
				// The fake resolves a name before an ID, so a container NAMED with
				// self's ID is what an inspect by that string returns: an engine
				// answering for some other container.
				other := self
				other.ID = strings.Repeat("f", 64)
				e.containers[self.ID] = other
			},
		},
		{
			name: "the named container is not running",
			setup: func(_ *dockerHelperController, e *fakeDockerEngine, self dockerContainer) {
				self.State.Running = false
				e.containers["node-updater"] = self
			},
		},
		{
			name: "this process answers to another hostname",
			setup: func(c *dockerHelperController, _ *fakeDockerEngine, _ dockerContainer) {
				c.options.Hostname = hostname("0f9e8d7c6b5a")
			},
		},
		{
			name:  "this process cannot read its hostname",
			setup: func(c *dockerHelperController, _ *fakeDockerEngine, _ dockerContainer) { c.options.Hostname = broken },
		},
		{
			// An operator who removed the hostname leaves nothing to compare, and
			// the inspect alone has to carry it.
			name: "a container without a hostname needs no hostname check",
			setup: func(c *dockerHelperController, e *fakeDockerEngine, self dockerContainer) {
				var config map[string]any
				if err := json.Unmarshal(self.Config, &config); err != nil {
					t.Fatal(err)
				}
				delete(config, "Hostname")
				self.Config, _ = json.Marshal(config)
				e.containers["node-updater"] = self
				c.options.Hostname = broken
			},
			ok: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controller, engine, updater := dockerUpdaterFixture(t)
			controller.options.Mountinfo = naming(updater.ID)
			controller.options.Hostname = hostname(updater.ID[:12])
			if tc.setup != nil {
				tc.setup(controller, engine, updater)
			}
			self, err := controller.resolveSelf(t.Context())
			if !tc.ok {
				if err == nil {
					t.Fatalf("resolveSelf accepted %s", self.ID)
				}
				return
			}
			if err != nil || self.ID != updater.ID {
				t.Fatalf("resolveSelf = (%s, %v), want %s", self.ID, err, updater.ID)
			}
		})
	}
}

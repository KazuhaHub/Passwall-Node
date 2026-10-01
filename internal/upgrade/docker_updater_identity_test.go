package upgrade

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const (
	identityAgentID   = "9c2e4a6b8d0f1e3c5a7b9d1f3e5c7a9b1d3f5e7c9a1b3d5f7e9c1a3b5d7f9e1c"
	identityUpdaterID = "6b1f4e0c9d2a87b3e5f40c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5"
)

// identityFixture is an agent and its updater as one of the two supported
// installations creates them: PSP's generated compose (example false), or the
// project's compose.example.yaml (example true), both seen through an inspect.
func identityFixture(t *testing.T, example bool) (*dockerHelperController, dockerContainer, dockerContainer) {
	t.Helper()
	target, updaterName, project := "passwall-node-server-7-agent", "passwall-node-server-7-updater", "/volume1/docker/passwall-node"
	host := map[string]any{
		"Binds":         []string{dockerSocket + ":" + dockerSocket, project + "/upgrades:" + DockerControlDir},
		"NetworkMode":   "none",
		"Privileged":    false,
		"RestartPolicy": map[string]any{"Name": "unless-stopped", "MaximumRetryCount": 0},
	}
	if example {
		target, updaterName, project = "passwall-node-agent", "passwall-node-updater", "/srv/passwall-node"
		host = map[string]any{
			"Binds":          []string{dockerSocket + ":" + dockerSocket, project + "/upgrades:" + DockerControlDir},
			"NetworkMode":    "none",
			"Privileged":     false,
			"ReadonlyRootfs": true,
			"CapDrop":        []string{"ALL"},
			"CapAdd":         []string{"CHOWN", "DAC_READ_SEARCH", "FOWNER"},
			"SecurityOpt":    []string{"no-new-privileges:true"},
			"Tmpfs":          map[string]string{"/tmp": "size=4m,mode=1777"},
			"RestartPolicy":  map[string]any{"Name": "unless-stopped", "MaximumRetryCount": 0},
		}
	}
	controller := &dockerHelperController{options: dockerHelperOptions{TargetName: target, AgentID: "agt_7f3a9c2e5b1d", Schema: 9}}
	agent := dockerContainer{
		ID: identityAgentID, Name: "/" + target,
		Mounts: []dockerMount{
			{Type: "bind", Source: project + "/config", Destination: "/run/secrets/passwall-node"},
			{Type: "bind", Source: project + "/data", Destination: DockerDataDir, RW: true},
			{Type: "bind", Source: project + "/upgrades", Destination: DockerControlDir, RW: true},
		},
	}
	updater := dockerContainer{
		ID: identityUpdaterID, Name: "/" + updaterName, Image: "sha256:" + strings.Repeat("7", 64),
		Config: mustJSON(t, map[string]any{
			"Hostname":   identityUpdaterID[:12],
			"Image":      DockerImageRepository + ":beta",
			"Entrypoint": []string{"/usr/local/bin/docker-entrypoint.sh"},
			"Cmd":        []string{dockerHelperCommand},
			"Env": []string{
				dockerTargetContainerEnv + "=" + target, dockerTargetAgentIDEnv + "=agt_7f3a9c2e5b1d",
				"PUID=10001", "PGID=10001", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TZ=UTC",
			},
			"Labels": map[string]string{
				"com.docker.compose.project":       "passwall-node-server-7",
				"com.docker.compose.service":       "passwall-node-updater",
				"com.docker.compose.image":         "sha256:" + strings.Repeat("7", 64),
				"com.docker.compose.config-hash":   strings.Repeat("3c", 32),
				"org.opencontainers.image.version": "4.0.1.7",
				"org.opencontainers.image.created": "2026-09-27T11:40:03.000Z",
				DockerLabelStateSchema:             "9",
				DockerLabelUpgradeContract:         "1",
				DockerLabelUpdaterHandover:         "1",
			},
			"StopTimeout": 15,
		}),
		HostConfig: mustJSON(t, host),
		Mounts: []dockerMount{
			{Type: "bind", Source: dockerSocket, Destination: dockerSocket, RW: true},
			{Type: "bind", Source: project + "/upgrades", Destination: DockerControlDir, RW: true},
		},
	}
	updater.State.Running = true
	return controller, updater, agent
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// editJSON decodes a raw object, lets edit change it, and encodes it again.
func editJSON(t *testing.T, raw json.RawMessage, edit func(map[string]any)) json.RawMessage {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	edit(value)
	return mustJSON(t, value)
}

// AN UPDATER IS RECOGNISED BY WHAT IT IS, NOT BY WHAT IT IS CALLED. Every
// container the handover creates, and every one it stops or removes other than
// itself, has to be an updater of THIS agent: the helper command, the agent's
// identity in its environment, the Docker socket, and the agent's own control
// directory — which is what proves it is this agent's pair and not another
// node's on the same host. And it must stay what an updater is allowed to be: not
// privileged, not on the host network, an official image, and sharing nothing
// else with the agent, so the socket holder still never sees the node's data or
// its credential. The agent can never pass, because it never holds the socket.
func TestIsUpdaterContainer(t *testing.T) {
	type mutation func(t *testing.T, updater, agent *dockerContainer)
	config := func(edit func(map[string]any)) mutation {
		return func(t *testing.T, updater, _ *dockerContainer) { updater.Config = editJSON(t, updater.Config, edit) }
	}
	hostConfig := func(edit func(map[string]any)) mutation {
		return func(t *testing.T, updater, _ *dockerContainer) {
			updater.HostConfig = editJSON(t, updater.HostConfig, edit)
		}
	}
	mounts := func(edit func([]dockerMount) []dockerMount) mutation {
		return func(_ *testing.T, updater, _ *dockerContainer) { updater.Mounts = edit(updater.Mounts) }
	}
	withoutDestination := func(destination string) func([]dockerMount) []dockerMount {
		return func(in []dockerMount) []dockerMount {
			var out []dockerMount
			for _, m := range in {
				if m.Destination != destination {
					out = append(out, m)
				}
			}
			return out
		}
	}
	replaceControl := func(edit func(*dockerMount)) func([]dockerMount) []dockerMount {
		return func(in []dockerMount) []dockerMount {
			out := append([]dockerMount(nil), in...)
			for i := range out {
				if out[i].Destination == DockerControlDir {
					edit(&out[i])
				}
			}
			return out
		}
	}
	adding := func(m dockerMount) func([]dockerMount) []dockerMount {
		return func(in []dockerMount) []dockerMount { return append(append([]dockerMount(nil), in...), m) }
	}
	env := func(values ...string) mutation {
		return config(func(c map[string]any) { c["Env"] = values })
	}

	for _, example := range []bool{false, true} {
		profile := map[bool]string{false: "PSP profile", true: "example profile"}[example]
		project := map[bool]string{false: "/volume1/docker/passwall-node", true: "/srv/passwall-node"}[example]
		t.Run(profile, func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				mutate mutation
				ok     bool
			}{
				{name: "as installed", ok: true},
				{name: "another command", mutate: config(func(c map[string]any) { c["Cmd"] = []string{"--run-upgrade-helper"} })},
				{name: "no command", mutate: config(func(c map[string]any) { delete(c, "Cmd") })},
				{name: "the helper command with more arguments", mutate: config(func(c map[string]any) { c["Cmd"] = []string{dockerHelperCommand, "--debug"} })},
				{name: "no target in its environment", mutate: env(dockerTargetAgentIDEnv + "=agt_7f3a9c2e5b1d")},
				{name: "another target", mutate: func(t *testing.T, u, a *dockerContainer) {
					config(func(c map[string]any) {
						c["Env"] = []string{dockerTargetContainerEnv + "=someone-else", dockerTargetAgentIDEnv + "=agt_7f3a9c2e5b1d"}
					})(t, u, a)
				}},
				{name: "another agent identity", mutate: func(t *testing.T, u, a *dockerContainer) {
					target := strings.TrimPrefix(a.Name, "/")
					config(func(c map[string]any) {
						c["Env"] = []string{dockerTargetContainerEnv + "=" + target, dockerTargetAgentIDEnv + "=agt_other"}
					})(t, u, a)
				}},
				{name: "no Docker socket", mutate: mounts(withoutDestination(dockerSocket))},
				{name: "the socket from a volume", mutate: mounts(func(in []dockerMount) []dockerMount {
					out := withoutDestination(dockerSocket)(in)
					return append(out, dockerMount{Type: "volume", Name: "sock", Source: "/var/lib/docker/volumes/sock/_data", Destination: dockerSocket, RW: true})
				})},
				{name: "no control directory", mutate: mounts(withoutDestination(DockerControlDir))},
				{name: "another node's control directory", mutate: mounts(replaceControl(func(m *dockerMount) { m.Source = "/volume1/docker/other-node/upgrades" }))},
				{name: "a read-only control directory", mutate: mounts(replaceControl(func(m *dockerMount) { m.RW = false }))},
				{name: "the agent's data", mutate: mounts(adding(dockerMount{Type: "bind", Source: project + "/data", Destination: "/data", RW: true}))},
				{name: "the agent's credential", mutate: mounts(adding(dockerMount{Type: "bind", Source: project + "/config", Destination: "/cfg"}))},
				{name: "a directory holding the agent's data", mutate: mounts(adding(dockerMount{Type: "bind", Source: project, Destination: "/project"}))},
				{name: "privileged", mutate: hostConfig(func(h map[string]any) { h["Privileged"] = true })},
				{name: "host network", mutate: hostConfig(func(h map[string]any) { h["NetworkMode"] = "host" })},
				{name: "an unofficial image", mutate: config(func(c map[string]any) { c["Image"] = "docker.io/someone/passwall-node:4.0.1.7" })},
				{name: "the agent's name", mutate: func(_ *testing.T, u, a *dockerContainer) { u.Name = a.Name }},
				{name: "the agent's identity", mutate: func(_ *testing.T, u, a *dockerContainer) { u.ID = a.ID }},
			} {
				t.Run(tc.name, func(t *testing.T) {
					controller, updater, agent := identityFixture(t, example)
					if tc.mutate != nil {
						tc.mutate(t, &updater, &agent)
					}
					err := controller.isUpdaterContainer(updater, agent)
					if tc.ok != (err == nil) {
						t.Fatalf("isUpdaterContainer = %v, want ok=%v", err, tc.ok)
					}
				})
			}
			t.Run("the agent itself", func(t *testing.T) {
				controller, _, agent := identityFixture(t, example)
				agent.Config = mustJSON(t, map[string]any{"Image": DockerImageRepository + ":beta"})
				agent.HostConfig = mustJSON(t, map[string]any{"NetworkMode": "host"})
				if err := controller.isUpdaterContainer(agent, agent); err == nil {
					t.Fatal("the agent passed as an updater")
				}
			})
		})
	}
}

// THE CLONE ANSWERS TO ITS OWN NAME. The create copies Config verbatim, and a
// container Docker named has Config.Hostname set to its own short ID, so a clone
// would answer to its predecessor's — and resolve itself as the wrong container.
// Only that default is removed, letting the daemon give the clone its own; a
// hostname an operator chose is the operator's, and is kept. Nothing else in the
// configuration changes.
func TestSuccessorSourceStripsOnlyDefaultHostname(t *testing.T) {
	_, self, _ := identityFixture(t, false)
	for _, tc := range []struct {
		name     string
		hostname any // nil removes the key
		stripped bool
	}{
		{"Docker's default, the container's own short ID", identityUpdaterID[:12], true},
		{"a hostname the operator chose", "nas-updater", false},
		{"another container's short ID", identityAgentID[:12], false},
		{"no hostname at all", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := self
			source.Config = editJSON(t, self.Config, func(c map[string]any) {
				if tc.hostname == nil {
					delete(c, "Hostname")
				} else {
					c["Hostname"] = tc.hostname
				}
			})
			before := bytes.Clone(source.Config)
			got, err := successorSource(source)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(source.Config, before) {
				t.Fatal("successorSource changed the container it was given")
			}
			if !tc.stripped {
				if !bytes.Equal(got.Config, source.Config) {
					t.Fatalf("a configuration that keeps its hostname changed:\n%s\n->\n%s", source.Config, got.Config)
				}
				return
			}
			var in, out map[string]json.RawMessage
			if json.Unmarshal(source.Config, &in) != nil || json.Unmarshal(got.Config, &out) != nil {
				t.Fatal("invalid configuration")
			}
			if _, kept := out["Hostname"]; kept {
				t.Fatal("Docker's default hostname was kept")
			}
			delete(in, "Hostname")
			if len(in) != len(out) {
				t.Fatalf("keys %d -> %d", len(in), len(out))
			}
			for key, value := range in {
				if !bytes.Equal(out[key], value) {
					t.Fatalf("%s changed: %s -> %s", key, value, out[key])
				}
			}
			if got.ID != source.ID || got.Name != source.Name || !bytes.Equal(got.HostConfig, source.HostConfig) || len(got.Mounts) != len(source.Mounts) {
				t.Fatal("successorSource changed more than the configuration")
			}
		})
	}
	if _, err := successorSource(dockerContainer{ID: identityUpdaterID, Config: json.RawMessage(`[]`)}); err == nil {
		t.Fatal("an unreadable configuration was cloned")
	}
}

// THE SUCCESSOR'S SECURITY PROFILE IS ITS PREDECESSOR'S, EXACTLY. The create
// sends HostConfig back verbatim, so after the daemon has normalised both, every
// field that decides what the container can reach must read the same. A daemon
// that changed one on the way — a capability, a bind, the network, the restart
// policy — is caught before the successor ever starts.
func TestSecuritySubsetEqual(t *testing.T) {
	_, self, _ := identityFixture(t, true)
	if err := securitySubsetEqual(self, self); err != nil {
		t.Fatalf("a container differs from itself: %v", err)
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, self.HostConfig, "", "  "); err != nil {
		t.Fatal(err)
	}
	reformatted := self
	reformatted.HostConfig = indented.Bytes()
	if err := securitySubsetEqual(self, reformatted); err != nil {
		t.Fatalf("layout alone made a difference: %v", err)
	}
	outside := self
	outside.HostConfig = editJSON(t, self.HostConfig, func(h map[string]any) { h["LogConfig"] = map[string]any{"Type": "local"} })
	if err := securitySubsetEqual(self, outside); err != nil {
		t.Fatalf("a field outside the subset made a difference: %v", err)
	}
	for _, key := range dockerSecuritySubset {
		t.Run(key, func(t *testing.T) {
			changed := self
			changed.HostConfig = editJSON(t, self.HostConfig, func(h map[string]any) { h[key] = "changed" })
			if err := securitySubsetEqual(self, changed); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("a changed %s = %v", key, err)
			}
			removed := self
			removed.HostConfig = editJSON(t, self.HostConfig, func(h map[string]any) { delete(h, key) })
			present := self
			present.HostConfig = editJSON(t, self.HostConfig, func(h map[string]any) { h[key] = nil })
			if err := securitySubsetEqual(present, removed); err == nil {
				t.Fatalf("%s present on one side and absent on the other made no difference", key)
			}
		})
	}
	if err := securitySubsetEqual(self, dockerContainer{HostConfig: json.RawMessage(`[]`)}); err == nil {
		t.Fatal("an unreadable HostConfig compared equal")
	}
}

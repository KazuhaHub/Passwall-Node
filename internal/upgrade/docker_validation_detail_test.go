//go:build unix

package upgrade

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// A REFUSAL HAS TO SAY WHAT IT REFUSED. The updater runs where the operator may
// have no shell — a NAS that offers only a Docker UI — so its message, carried in
// the receipt to the agent and from there to PSP, is the whole of what anyone
// sees. One sentence for six label checks sent the owner of such a node hunting
// through container metadata by hand. Each case below pins the old sentence as the
// prefix, which log searches rely on, and then the named check with what was
// found and what was wanted.

// withConfig and withHost rewrite the fixture's raw Config and HostConfig, which
// the validator decodes itself, the way a real inspect would carry a difference.
func withConfig(t *testing.T, container *dockerContainer, change func(*dockerConfig)) {
	t.Helper()
	var config dockerConfig
	if err := json.Unmarshal(container.Config, &config); err != nil {
		t.Fatal(err)
	}
	labels := make(map[string]string, len(config.Labels))
	for key, value := range config.Labels {
		labels[key] = value
	}
	config.Labels = labels
	config.Env = append([]string(nil), config.Env...)
	change(&config)
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	container.Config = raw
}

func withHost(t *testing.T, container *dockerContainer, change func(*dockerHostConfig)) {
	t.Helper()
	var host dockerHostConfig
	if err := json.Unmarshal(container.HostConfig, &host); err != nil {
		t.Fatal(err)
	}
	change(&host)
	raw, err := json.Marshal(host)
	if err != nil {
		t.Fatal(err)
	}
	container.HostConfig = raw
}

func TestDockerContainerRefusalNamesTheCheckAndBothValues(t *testing.T) {
	const (
		metadata = "managed Docker container metadata is invalid: "
		security = "managed Docker container security profile differs from the supported installation: "
		labels   = "managed Docker container labels do not bind the expected agent and contract: "
		env      = "managed Docker container environment is not upgrade-enabled: "
		mounts   = "managed Docker data and upgrade-control mounts are missing or not persistent: "
	)
	bind := func(destination string) dockerMount {
		return dockerMount{Type: "bind", Source: "/srv/passwall-node/x", Destination: destination, RW: true}
	}
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *dockerContainer)
		prefix string
		want   []string
	}{
		{
			name:   "a short container ID",
			change: func(_ *testing.T, c *dockerContainer) { c.ID = "abc" },
			prefix: metadata,
			want:   []string{"container ID is 3 characters (want at least 12)"},
		},
		{
			name:   "an undecodable Config",
			change: func(_ *testing.T, c *dockerContainer) { c.Config = json.RawMessage(`[1]`) },
			prefix: metadata,
			want:   []string{"Config cannot be decoded"},
		},
		{
			name:   "an undecodable HostConfig",
			change: func(_ *testing.T, c *dockerContainer) { c.HostConfig = json.RawMessage(`"bridge"`) },
			prefix: metadata,
			want:   []string{"HostConfig cannot be decoded"},
		},
		{
			name: "a privileged container",
			change: func(t *testing.T, c *dockerContainer) {
				withHost(t, c, func(h *dockerHostConfig) { h.Privileged = true })
			},
			prefix: security,
			want:   []string{"privileged is true (want false)"},
		},
		{
			name: "every security difference at once",
			change: func(t *testing.T, c *dockerContainer) {
				withHost(t, c, func(h *dockerHostConfig) { h.Privileged, h.ReadonlyRootfs, h.NetworkMode = true, false, "bridge" })
			},
			prefix: security,
			want:   []string{"privileged is true (want false)", "read-only rootfs is false (want true)", `network mode is "bridge" (want "host")`},
		},
		{
			name: "another agent's ID",
			change: func(t *testing.T, c *dockerContainer) {
				withConfig(t, c, func(config *dockerConfig) { config.Labels[DockerLabelAgentID] = "agt_other" })
			},
			prefix: labels,
			want:   []string{DockerLabelAgentID + ` is "agt_other" (want "agt_docker_upgrade_test")`},
		},
		{
			name: "a missing version label",
			change: func(t *testing.T, c *dockerContainer) {
				withConfig(t, c, func(config *dockerConfig) { delete(config.Labels, "org.opencontainers.image.version") })
			},
			prefix: labels,
			want:   []string{`org.opencontainers.image.version is missing (want "4.1.0")`},
		},
		{
			// Every mismatching label is named, not just the first one met, so a
			// node with several wrong does not need one upgrade attempt per label.
			name: "every label wrong at once",
			change: func(t *testing.T, c *dockerContainer) {
				withConfig(t, c, func(config *dockerConfig) {
					config.Labels[DockerLabelManaged] = "false"
					delete(config.Labels, DockerLabelRole)
					config.Labels[DockerLabelAgentID] = "agt_other"
					config.Labels["org.opencontainers.image.version"] = "4.0.9"
					config.Labels[DockerLabelStateSchema] = "10"
					config.Labels[DockerLabelUpgradeContract] = "2"
				})
			},
			prefix: labels,
			want: []string{
				DockerLabelManaged + ` is "false" (want "true")`,
				DockerLabelRole + ` is missing (want "agent")`,
				DockerLabelAgentID + ` is "agt_other" (want "agt_docker_upgrade_test")`,
				`org.opencontainers.image.version is "4.0.9" (want "4.1.0")`,
				DockerLabelStateSchema + ` is "10" (want "9")`,
				DockerLabelUpgradeContract + ` is "2" (want "1")`,
			},
		},
		{
			name: "an image from another repository",
			change: func(t *testing.T, c *dockerContainer) {
				withConfig(t, c, func(config *dockerConfig) { config.Image = "registry.example/passwall-node:4.1.0" })
			},
			prefix: env,
			want:   []string{`image is "registry.example/passwall-node:4.1.0" (want ` + DockerImageRepository + `:<tag> or @<digest>)`},
		},
		{
			name: "no agent ID in the environment",
			change: func(t *testing.T, c *dockerContainer) {
				withConfig(t, c, func(config *dockerConfig) { config.Env = []string{"PSP_NODE_DOCKER_REMOTE_UPGRADE=true"} })
			},
			prefix: env,
			want:   []string{`PSP_NODE_AGENT_ID is missing (want "agt_docker_upgrade_test")`},
		},
		{
			name: "another agent ID in the environment",
			change: func(t *testing.T, c *dockerContainer) {
				withConfig(t, c, func(config *dockerConfig) {
					config.Env = []string{"PSP_NODE_AGENT_ID=agt_other", "PSP_NODE_DOCKER_REMOTE_UPGRADE=true"}
				})
			},
			prefix: env,
			want:   []string{`PSP_NODE_AGENT_ID is "agt_other" (want "agt_docker_upgrade_test")`},
		},
		{
			name: "remote upgrade switched off",
			change: func(t *testing.T, c *dockerContainer) {
				withConfig(t, c, func(config *dockerConfig) {
					config.Env = []string{"PSP_NODE_AGENT_ID=agt_docker_upgrade_test", "PSP_NODE_DOCKER_REMOTE_UPGRADE=false"}
				})
			},
			prefix: env,
			want:   []string{`PSP_NODE_DOCKER_REMOTE_UPGRADE is "false" (want "true")`},
		},
		{
			name: "remote upgrade never switched on",
			change: func(t *testing.T, c *dockerContainer) {
				withConfig(t, c, func(config *dockerConfig) { config.Env = []string{"PSP_NODE_AGENT_ID=agt_docker_upgrade_test"} })
			},
			prefix: env,
			want:   []string{`PSP_NODE_DOCKER_REMOTE_UPGRADE is missing (want "true")`},
		},
		{
			name: "a tmpfs data directory",
			change: func(_ *testing.T, c *dockerContainer) {
				c.Mounts = []dockerMount{{Type: "tmpfs", Destination: DockerDataDir, RW: true}, bind(DockerControlDir)}
			},
			prefix: mounts,
			want:   []string{`data mount at ` + DockerDataDir + ` is type "tmpfs" (want volume or bind)`},
		},
		{
			name: "a read-only upgrade-control mount",
			change: func(_ *testing.T, c *dockerContainer) {
				c.Mounts = []dockerMount{bind(DockerDataDir), {Type: "bind", Source: "/srv/u", Destination: DockerControlDir}}
			},
			prefix: mounts,
			want:   []string{`upgrade-control mount at ` + DockerControlDir + ` is read-only`},
		},
		{
			name:   "neither mount",
			change: func(_ *testing.T, c *dockerContainer) { c.Mounts = nil },
			prefix: mounts,
			want:   []string{`data mount at ` + DockerDataDir + ` is missing`, `upgrade-control mount at ` + DockerControlDir + ` is missing`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controller, engine, _ := dockerControllerFixture(t)
			container := engine.containers[controller.options.TargetName]
			tc.change(t, &container)
			_, err := controller.validateContainer(container, "4.1.0")
			if err == nil {
				t.Fatal("validateContainer accepted the container")
			}
			message := err.Error()
			if !strings.HasPrefix(message, tc.prefix) {
				t.Fatalf("message = %q, want the prefix %q", message, tc.prefix)
			}
			for _, want := range tc.want {
				if !strings.Contains(message, want) {
					t.Errorf("message = %q, want it to name %q", message, want)
				}
			}
		})
	}
}

// THE ENVIRONMENT CARRIES THE ENDPOINT AND THE CREDENTIAL PATHS, and the refusal
// travels to PSP. Only the two variables the check is about may ever be named.
func TestDockerEnvironmentRefusalNamesNoOtherVariable(t *testing.T) {
	controller, engine, _ := dockerControllerFixture(t)
	container := engine.containers[controller.options.TargetName]
	withConfig(t, &container, func(config *dockerConfig) {
		config.Env = []string{
			"PSP_NODE_ENDPOINT=https://panel.private.example:8443",
			"PSP_NODE_CREDENTIAL_FILE=/run/secrets/node-credential",
			"PSP_NODE_AGENT_ID=agt_other",
			"PSP_NODE_DOCKER_REMOTE_UPGRADE=false",
		}
	})
	_, err := controller.validateContainer(container, "4.1.0")
	if err == nil {
		t.Fatal("validateContainer accepted the container")
	}
	for _, leaked := range []string{"PSP_NODE_ENDPOINT", "panel.private.example", "PSP_NODE_CREDENTIAL_FILE", "/run/secrets"} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("message %q names %q", err, leaked)
		}
	}
}

// LABEL VALUES ARE WHATEVER THE OPERATOR, OR WHOEVER CAN EDIT THE COMPOSE FILE,
// PUT THERE. Quoted, a newline cannot start a forged log line, a bidirectional
// override cannot reorder what the panel shows and an invalid byte cannot corrupt
// the UTF-8 the panel requires; bounded, one label cannot crowd out the rest of
// the message or the panel's error field.
func TestDockerLabelRefusalQuotesAndBoundsHostileValues(t *testing.T) {
	controller, engine, _ := dockerControllerFixture(t)
	container := engine.containers[controller.options.TargetName]
	withConfig(t, &container, func(config *dockerConfig) {
		config.Labels[DockerLabelAgentID] = "agt_x\nhandover: forged log line"
		config.Labels[DockerLabelRole] = strings.Repeat("x", 5000)
		config.Labels[DockerLabelStateSchema] = "9\u202e01"
	})
	// The engine's JSON can carry a byte that is not UTF-8. The validator decodes
	// Config itself, so the byte goes in raw, as an engine would send it.
	invalid := bytes.Replace(container.Config, []byte(`"true"`), []byte("\"tr\xffue\""), 1)
	if bytes.Equal(invalid, container.Config) {
		t.Fatal("the fixture's managed label was not found to corrupt")
	}
	container.Config = invalid
	_, err := controller.validateContainer(container, "4.1.0")
	if err == nil {
		t.Fatal("validateContainer accepted the container")
	}
	message := err.Error()
	if strings.ContainsAny(message, "\n\r\u202e") {
		t.Fatalf("message carries a raw line break or override: %q", message)
	}
	if !utf8.ValidString(message) {
		t.Fatalf("message is not valid UTF-8: %q", message)
	}
	for _, want := range []string{
		DockerLabelAgentID + ` is "agt_x\nhandover: forged log line"`,
		DockerLabelStateSchema + ` is "9\u202e01"`,
		// The decoder turned the byte into U+FFFD, which prints.
		DockerLabelManaged + " is \"tr\ufffdue\" (want \"true\")",
		DockerLabelRole + ` is "` + strings.Repeat("x", 64) + `"... (5000 bytes) (want "agent")`,
	} {
		if !strings.Contains(message, want) {
			t.Errorf("message = %q, want it to carry %q", message, want)
		}
	}
	if strings.Contains(message, strings.Repeat("x", 65)) {
		t.Errorf("message carries more than 64 bytes of one label: %d bytes", len(message))
	}
	if len(message) > 1024 {
		t.Errorf("message is %d bytes", len(message))
	}
}

// validateImage takes the inspected struct, so whether a byte that is not UTF-8
// reaches it depends on whoever decoded the inspect. The quoting holds either way.
func TestDockerImageRefusalQuotesAnInvalidByte(t *testing.T) {
	controller, engine, request := dockerControllerFixture(t)
	image := engine.images[DockerImageRepository+":"+request.Args.Version]
	image.OS = "lin\xffux\n"
	err := controller.validateImage(image, request.Args.Version)
	if err == nil {
		t.Fatal("validateImage accepted the image")
	}
	if want := `OS is "lin\xffux\n" (want "linux")`; !strings.Contains(err.Error(), want) || !utf8.ValidString(err.Error()) {
		t.Fatalf("message = %q, want valid UTF-8 carrying %q", err, want)
	}
}

// The bound cuts between characters, never inside one, and marks only a value
// it actually cut.
func TestQuoteValueBoundsAtACharacter(t *testing.T) {
	for _, tc := range []struct{ value, want string }{
		{strings.Repeat("x", 64), `"` + strings.Repeat("x", 64) + `"`},
		{strings.Repeat("x", 63) + "é", `"` + strings.Repeat("x", 63) + `"... (65 bytes)`},
		{"", `""`},
	} {
		if got := quoteValue(tc.value); got != tc.want {
			t.Errorf("quoteValue(%q) = %q, want %q", tc.value, got, tc.want)
		}
	}
}

func TestDockerImageRefusalNamesTheCheckAndBothValues(t *testing.T) {
	const (
		platform = "target image platform identity is invalid: "
		contract = "target image does not declare the same state schema and upgrade contract: "
	)
	for _, tc := range []struct {
		name   string
		change func(*dockerImage)
		prefix string
		want   []string
	}{
		{
			name:   "a short image ID",
			change: func(i *dockerImage) { i.ID = "sha256:ab" },
			prefix: platform,
			want:   []string{"image ID is 9 characters (want at least 12)"},
		},
		{
			name:   "another operating system",
			change: func(i *dockerImage) { i.OS = "windows" },
			prefix: platform,
			want:   []string{`OS is "windows" (want "linux")`},
		},
		{
			name:   "an unsupported architecture",
			change: func(i *dockerImage) { i.Architecture = "386" },
			prefix: platform,
			want:   []string{`architecture is "386" (want "amd64" or "arm64")`},
		},
		{
			name:   "another version",
			change: func(i *dockerImage) { i.Config.Labels["org.opencontainers.image.version"] = "4.1.2" },
			prefix: contract,
			want:   []string{`org.opencontainers.image.version is "4.1.2" (want "4.1.3")`},
		},
		{
			name:   "another state schema",
			change: func(i *dockerImage) { i.Config.Labels[DockerLabelStateSchema] = "10" },
			prefix: contract,
			want:   []string{DockerLabelStateSchema + ` is "10" (want "9")`},
		},
		{
			name:   "no upgrade contract",
			change: func(i *dockerImage) { delete(i.Config.Labels, DockerLabelUpgradeContract) },
			prefix: contract,
			want:   []string{DockerLabelUpgradeContract + ` is missing (want "1")`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controller, engine, request := dockerControllerFixture(t)
			image := engine.images[DockerImageRepository+":"+request.Args.Version]
			labels := make(map[string]string, len(image.Config.Labels))
			for key, value := range image.Config.Labels {
				labels[key] = value
			}
			image.Config.Labels = labels
			tc.change(&image)
			err := controller.validateImage(image, request.Args.Version)
			if err == nil {
				t.Fatal("validateImage accepted the image")
			}
			message := err.Error()
			if !strings.HasPrefix(message, tc.prefix) {
				t.Fatalf("message = %q, want the prefix %q", message, tc.prefix)
			}
			for _, want := range tc.want {
				if !strings.Contains(message, want) {
					t.Errorf("message = %q, want it to name %q", message, want)
				}
			}
		})
	}
}

// THE RECEIPT IS WHAT LEAVES THE HOST. The validator's detail is no use if the
// path that writes the failed receipt drops it, as the target image's path did:
// it replaced every reason with one fixed sentence.
func TestDockerUpgradeReceiptCarriesTheRefusalDetail(t *testing.T) {
	t.Run("the managed container", func(t *testing.T) {
		controller, engine, request := dockerControllerFixture(t)
		container := engine.containers[controller.options.TargetName]
		withConfig(t, &container, func(config *dockerConfig) { config.Labels[DockerLabelAgentID] = "agt_other" })
		engine.containers[controller.options.TargetName] = container
		if err := controller.processCurrent(t.Context()); err == nil {
			t.Fatal("the upgrade was not refused")
		}
		receipt := readDockerReceipt(t, controller, request)
		want := "managed Docker container labels do not bind the expected agent and contract: " +
			DockerLabelAgentID + ` is "agt_other" (want "agt_docker_upgrade_test")`
		if receipt.Phase != "failed" || receipt.ErrorCode != "agent_upgrade_installation_invalid" || receipt.Error != want {
			t.Fatalf("receipt = %+v, want error %q", receipt, want)
		}
	})
	t.Run("the target image", func(t *testing.T) {
		controller, engine, request := dockerControllerFixture(t)
		reference := DockerImageRepository + ":" + request.Args.Version
		image := engine.images[reference]
		image.Config.Labels = map[string]string{
			"org.opencontainers.image.version": request.Args.Version,
			DockerLabelStateSchema:             "10", DockerLabelUpgradeContract: "1",
		}
		engine.images[reference] = image
		if err := controller.processCurrent(t.Context()); err == nil {
			t.Fatal("the upgrade was not refused")
		}
		receipt := readDockerReceipt(t, controller, request)
		want := "target image identity or upgrade contract is incompatible: " +
			"target image does not declare the same state schema and upgrade contract: " +
			DockerLabelStateSchema + ` is "10" (want "9")`
		if receipt.Phase != "failed" || receipt.ErrorCode != "agent_upgrade_schema_unsupported" || receipt.Error != want {
			t.Fatalf("receipt = %+v, want error %q", receipt, want)
		}
	})
}

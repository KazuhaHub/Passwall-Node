package upgrade

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type dockerRoundTripFunc func(*http.Request) (*http.Response, error)

func (f dockerRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestDockerCreateReplacementPreservesRuntimeConfigAndUsesExactImage(t *testing.T) {
	oldConfig := json.RawMessage(`{"Image":"ghcr.io/kazuhahub/passwall-node:beta","Env":["A=B"],"Labels":{"custom":"kept","org.opencontainers.image.version":"4.1.0"},"Entrypoint":["/entrypoint"],"Cmd":["node"]}`)
	oldHost := json.RawMessage(`{"NetworkMode":"host","ReadonlyRootfs":true,"Binds":["data:/var/lib/passwall-node"]}`)
	old := dockerContainer{Config: oldConfig, HostConfig: oldHost}
	image := dockerImage{}
	image.Config.Labels = map[string]string{
		"org.opencontainers.image.version":  targetDockerVersion,
		"org.opencontainers.image.revision": "new-revision",
		DockerLabelStateSchema:              "9",
		DockerLabelUpgradeContract:          "1",
		"foreign":                           "not-copied",
	}
	client := &dockerHTTP{client: &http.Client{Transport: dockerRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1.41/containers/create" || request.URL.Query().Get("name") != "node-agent" {
			t.Fatalf("unexpected create request: %s %s", request.Method, request.URL.String())
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]json.RawMessage
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("invalid create payload: %v", err)
		}
		if _, nested := payload["Config"]; nested {
			t.Fatal("container Config was nested instead of forming the create payload")
		}
		var reference string
		if json.Unmarshal(payload["Image"], &reference) != nil || reference != DockerImageRepository+":"+targetDockerVersion {
			t.Fatalf("image = %q", reference)
		}
		var labels map[string]string
		if json.Unmarshal(payload["Labels"], &labels) != nil || labels["custom"] != "kept" || labels["foreign"] != "" || labels["org.opencontainers.image.revision"] != "new-revision" ||
			labels["org.opencontainers.image.version"] != targetDockerVersion || labels[DockerLabelStateSchema] != "9" || labels[DockerLabelUpgradeContract] != "1" {
			t.Fatalf("labels = %#v", labels)
		}
		if string(payload["HostConfig"]) != string(oldHost) || string(payload["Entrypoint"]) != `["/entrypoint"]` || string(payload["Cmd"]) != `["node"]` {
			t.Fatalf("runtime configuration was not preserved: %s", body)
		}
		return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader(`{"Id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`)), Header: make(http.Header)}, nil
	})}}

	id, err := client.CreateReplacement(context.Background(), "node-agent", old, image, DockerImageRepository+":"+targetDockerVersion)
	if err != nil || len(id) != 64 {
		t.Fatalf("CreateReplacement = (%q, %v)", id, err)
	}
}

func TestDockerPullRequiresOfficialExactRelease(t *testing.T) {
	client := &dockerHTTP{client: &http.Client{Transport: dockerRoundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid image selection reached Docker Engine")
		return nil, nil
	})}}
	for _, reference := range []string{
		DockerImageRepository + ":latest",
		DockerImageRepository + ":beta",
		"docker.io/foreign/passwall-node:4.1.0",
		DockerImageRepository + ":4.1.0/foreign",
	} {
		if err := client.PullImage(context.Background(), reference); err == nil {
			t.Fatalf("PullImage(%q) succeeded", reference)
		}
	}
}

const targetDockerVersion = "4.1.3"

// THE CLASSIFICATION HAS TO SURVIVE THE REAL TRANSPORT, not just the classifier.
//
// Rollback decides between "try again next poll" and "stop for good" on this
// answer, so it is measured through dockerHTTP.call — the code that actually
// turns a socket failure or a status line into an error — rather than by handing
// the classifier values constructed in the test. A classifier that is correct on
// its own inputs and never sees them from the engine would pass here and fail in
// production.
func TestDockerEngineFailuresAreClassifiedThroughTheRealTransport(t *testing.T) {
	respond := func(code int, body string) *dockerHTTP {
		return &dockerHTTP{client: &http.Client{Transport: dockerRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
		})}}
	}
	unreachable := &dockerHTTP{client: &http.Client{Transport: dockerRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial unix /var/run/docker.sock: connect: connection refused")
	})}}

	for _, tc := range []struct {
		name      string
		call      func() error
		transient bool
		notFound  bool
	}{
		{
			// The case that stranded nodes: the engine did not answer this one call.
			name: "socket unreachable", transient: true,
			call: func() error { _, err := unreachable.InspectContainer(t.Context(), "node-agent"); return err },
		},
		{
			name: "engine error", transient: true,
			call: func() error {
				return respond(http.StatusInternalServerError, "").RemoveContainer(t.Context(), "node-agent", false)
			},
		},
		{
			// force=false against a container whose stop has not finished.
			name: "removal conflict", transient: true,
			call: func() error {
				return respond(http.StatusConflict, "").RemoveContainer(t.Context(), "node-agent", false)
			},
		},
		{
			// A body cut short is a transport problem on a local socket.
			name: "truncated body", transient: true,
			call: func() error {
				_, err := respond(http.StatusOK, `{"Id":`).InspectContainer(t.Context(), "node-agent")
				return err
			},
		},
		{
			// NOT transient: the object is not there, and asking again will not
			// make it be. This must stay final.
			name: "not found", notFound: true,
			call: func() error {
				_, err := respond(http.StatusNotFound, "").InspectContainer(t.Context(), "node-agent")
				return err
			},
		},
		{
			// A request the engine understood and rejected on its merits.
			name: "bad request",
			call: func() error {
				return respond(http.StatusBadRequest, "").RemoveContainer(t.Context(), "node-agent", false)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatal("the engine failure was not reported at all")
			}
			if got := dockerTransient(err); got != tc.transient {
				t.Fatalf("dockerTransient(%v) = %v, want %v", err, got, tc.transient)
			}
			if got := errors.Is(err, errDockerNotFound); got != tc.notFound {
				t.Fatalf("errors.Is(%v, errDockerNotFound) = %v, want %v", err, got, tc.notFound)
			}
		})
	}

	// AN ERROR THE CLASSIFIER HAS NEVER SEEN IS NOT TRANSIENT. Retries are spent on
	// failures known to be worth retrying, not on everything that is not a 404.
	if dockerTransient(errors.New("something else entirely")) {
		t.Fatal("an unrecognised error was classified as transient")
	}
}

// FORCED REMOVAL HAS TO REACH THE ENGINE AS FORCED.
//
// force=true is a destructive capability added for one caller that has already
// established identity. A flag that is accepted by the method and silently sent
// as false would reproduce the stranding it exists to prevent — and would pass
// every test that only checks the method returned.
func TestDockerRemoveContainerSendsTheForceItWasGiven(t *testing.T) {
	for _, force := range []bool{false, true} {
		var query string
		client := &dockerHTTP{client: &http.Client{Transport: dockerRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			query = request.URL.RawQuery
			return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
		})}}
		if err := client.RemoveContainer(t.Context(), "node-agent", force); err != nil {
			t.Fatal(err)
		}
		want := "v=false&force=" + map[bool]string{false: "false", true: "true"}[force]
		if query != want {
			t.Fatalf("force=%v sent %q, want %q", force, query, want)
		}
	}
}

// THE HANDOVER READS WHAT THE AGENT SWAP NEVER NEEDED: whether a container has
// ever started, whether the restart policy has had to bring it back, whether it
// is paused or mid-restart, and what command and hostname it was created with.
// A successor that crashed and was restarted looks Running, so Running alone
// cannot prove it stayed up; RestartCount and StartedAt can. The fields are
// decode-only and read through the real transport, against bodies in the shape
// the Engine returns for an updater container, so a misspelt tag cannot pass.
func TestInspectDecodesRestartAndCommandFields(t *testing.T) {
	const id = "6b1f4e0c9d2a87b3e5f40c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5"
	for _, tc := range []struct {
		file                        string
		running, paused, restarting bool
		restarts                    int
		startedAt                   string
	}{
		{file: "updater-running.json", running: true, restarts: 2, startedAt: "2026-09-30T08:15:42.123456789Z"},
		// Created and never started: Docker reports the zero time.
		{file: "updater-created.json"},
		{file: "updater-paused.json", running: true, paused: true, restarts: 2, startedAt: "2026-09-30T08:15:42.123456789Z"},
		{file: "updater-restarting.json", running: true, restarting: true, restarts: 3, startedAt: "2026-09-30T08:16:03.554201877Z"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join("testdata", "inspect", tc.file))
			if err != nil {
				t.Fatal(err)
			}
			client := &dockerHTTP{client: &http.Client{Transport: dockerRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.Path != "/v1.41/containers/passwall-node-server-7-updater/json" {
					t.Fatalf("unexpected inspect request: %s", request.URL.Path)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{}}, nil
			})}}
			container, err := client.InspectContainer(t.Context(), "passwall-node-server-7-updater")
			if err != nil {
				t.Fatal(err)
			}
			if container.ID != id || container.RestartCount != tc.restarts || container.State.Running != tc.running ||
				container.State.Paused != tc.paused || container.State.Restarting != tc.restarting {
				t.Fatalf("decoded id %s restarts %d running %v paused %v restarting %v", container.ID, container.RestartCount,
					container.State.Running, container.State.Paused, container.State.Restarting)
			}
			if tc.startedAt == "" {
				if !container.State.StartedAt.IsZero() {
					t.Fatalf("a never-started container decoded StartedAt %s, want the zero time", container.State.StartedAt)
				}
			} else if want, _ := time.Parse(time.RFC3339Nano, tc.startedAt); !container.State.StartedAt.Equal(want) {
				t.Fatalf("StartedAt = %s, want %s", container.State.StartedAt, want)
			}
			var config dockerConfig
			if err := json.Unmarshal(container.Config, &config); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(config.Cmd, []string{"--run-docker-upgrade-helper"}) || config.Hostname != id[:12] {
				t.Fatalf("Cmd %q Hostname %q, want the helper command and %q", config.Cmd, config.Hostname, id[:12])
			}
		})
	}
}

// THE SUCCESSOR IS CREATED BY THE AGENT SWAP'S OWN, UNCHANGED REQUEST. Fed the
// updater's inspect with Docker's default hostname stripped, CreateReplacement
// sends the updater's whole configuration with only the image and the image's
// identity labels changed, and its HostConfig byte for byte. Compose's labels
// travel unchanged, com.docker.compose.image included: rewriting that one would
// make a routine `compose up -d` recreate the updater at the older compose tag.
// And the request the agent swap sends is still exactly the one 4.0.1.6 sent.
func TestCreateReplacementBodyForSuccessor(t *testing.T) {
	capture := func(t *testing.T, name string, old dockerContainer, image dockerImage, reference string) []byte {
		t.Helper()
		var body []byte
		client := &dockerHTTP{client: &http.Client{Transport: dockerRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Query().Get("name") != name {
				t.Fatalf("created as %q, want %q", request.URL.Query().Get("name"), name)
			}
			var err error
			if body, err = io.ReadAll(request.Body); err != nil {
				t.Fatal(err)
			}
			return &http.Response{StatusCode: http.StatusCreated, Header: http.Header{},
				Body: io.NopCloser(strings.NewReader(`{"Id":"` + strings.Repeat("3", 64) + `"}`))}, nil
		})}}
		if _, err := client.CreateReplacement(t.Context(), name, old, image, reference); err != nil {
			t.Fatal(err)
		}
		return body
	}

	t.Run("the agent swap's request is unchanged", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join("testdata", "create", "agent.input.json"))
		if err != nil {
			t.Fatal(err)
		}
		var input struct {
			Config      json.RawMessage   `json:"config"`
			HostConfig  json.RawMessage   `json:"host_config"`
			ImageLabels map[string]string `json:"image_labels"`
			Reference   string            `json:"reference"`
		}
		if err := json.Unmarshal(data, &input); err != nil {
			t.Fatal(err)
		}
		image := dockerImage{}
		image.Config.Labels = input.ImageLabels
		golden, err := os.ReadFile(filepath.Join("testdata", "create", "agent.body.golden.json"))
		if err != nil {
			t.Fatal(err)
		}
		body := capture(t, "passwall-node-server-7-agent", dockerContainer{Config: input.Config, HostConfig: input.HostConfig}, image, input.Reference)
		if !bytes.Equal(body, golden) {
			t.Fatalf("the agent swap now sends\n%s\nwhere 4.0.1.6 sent\n%s", body, golden)
		}
	})

	t.Run("the successor", func(t *testing.T) {
		_, self, _ := identityFixture(t, false)
		reference := DockerImageRepository + ":4.0.1.8"
		image := dockerImage{ID: "sha256:" + strings.Repeat("2", 64)}
		image.Config.Labels = map[string]string{
			"org.opencontainers.image.version":  "4.0.1.8",
			"org.opencontainers.image.revision": "0c3f6a9d2e5b8c1f4a7d0e3b6c9f2a5d8e1b4c7f",
			DockerLabelStateSchema:              "9",
			DockerLabelUpgradeContract:          "1",
			DockerLabelUpdaterHandover:          "1",
			"foreign":                           "not-copied",
		}
		source, err := successorSource(self)
		if err != nil {
			t.Fatal(err)
		}
		body := capture(t, "passwall-node-server-7-updater-next-1a2b3c4d", source, image, reference)
		var sent, original map[string]json.RawMessage
		if err := json.Unmarshal(body, &sent); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(self.Config, &original); err != nil {
			t.Fatal(err)
		}
		if _, kept := sent["Hostname"]; kept {
			t.Fatal("the predecessor's default hostname was sent")
		}
		if !bytes.Equal(sent["HostConfig"], self.HostConfig) {
			t.Fatalf("HostConfig = %s, want the predecessor's %s verbatim", sent["HostConfig"], self.HostConfig)
		}
		var image2 string
		if json.Unmarshal(sent["Image"], &image2) != nil || image2 != reference {
			t.Fatalf("Image = %s, want %q", sent["Image"], reference)
		}
		for key, value := range original {
			switch key {
			case "Hostname", "Image", "Labels":
				continue
			}
			if !bytes.Equal(sent[key], value) {
				t.Fatalf("%s = %s, want the predecessor's %s", key, sent[key], value)
			}
		}
		var labels, before map[string]string
		if json.Unmarshal(sent["Labels"], &labels) != nil || json.Unmarshal(original["Labels"], &before) != nil {
			t.Fatal("invalid labels")
		}
		want := map[string]string{}
		for key, value := range before {
			want[key] = value
		}
		want["org.opencontainers.image.version"] = "4.0.1.8"
		want["org.opencontainers.image.revision"] = "0c3f6a9d2e5b8c1f4a7d0e3b6c9f2a5d8e1b4c7f"
		if len(labels) != len(want) {
			t.Fatalf("labels = %v, want %v", labels, want)
		}
		for key, value := range want {
			if labels[key] != value {
				t.Fatalf("label %s = %q, want %q (labels %v)", key, labels[key], value, labels)
			}
		}
		if labels["com.docker.compose.image"] != before["com.docker.compose.image"] {
			t.Fatal("com.docker.compose.image was rewritten")
		}
	})
}

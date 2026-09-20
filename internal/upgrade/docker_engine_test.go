package upgrade

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
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

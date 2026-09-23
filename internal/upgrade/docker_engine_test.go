package upgrade

import (
	"context"
	"encoding/json"
	"errors"
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
				return respond(http.StatusInternalServerError, "").RemoveContainer(t.Context(), "node-agent")
			},
		},
		{
			// force=false against a container whose stop has not finished.
			name: "removal conflict", transient: true,
			call: func() error { return respond(http.StatusConflict, "").RemoveContainer(t.Context(), "node-agent") },
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
			call: func() error { return respond(http.StatusBadRequest, "").RemoveContainer(t.Context(), "node-agent") },
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

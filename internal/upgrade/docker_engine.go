package upgrade

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KazuhaHub/passwall-node/deployment"
)

const dockerAPIVersion = "v1.41"

var errDockerNotFound = errors.New("Docker object not found")

type dockerMount struct {
	Type        string `json:"Type"`
	Name        string `json:"Name"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}

type dockerContainer struct {
	ID         string          `json:"Id"`
	Image      string          `json:"Image"`
	Name       string          `json:"Name"`
	Config     json.RawMessage `json:"Config"`
	HostConfig json.RawMessage `json:"HostConfig"`
	Mounts     []dockerMount   `json:"Mounts"`
	State      struct {
		Running bool `json:"Running"`
		PID     int  `json:"Pid"`
	} `json:"State"`
}

type dockerConfig struct {
	Image  string            `json:"Image"`
	Env    []string          `json:"Env"`
	Labels map[string]string `json:"Labels"`
}

type dockerHostConfig struct {
	NetworkMode    string `json:"NetworkMode"`
	Privileged     bool   `json:"Privileged"`
	ReadonlyRootfs bool   `json:"ReadonlyRootfs"`
}

type dockerImage struct {
	ID           string   `json:"Id"`
	RepoTags     []string `json:"RepoTags"`
	Architecture string   `json:"Architecture"`
	OS           string   `json:"Os"`
	Config       struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

type dockerEngine interface {
	Ping(context.Context) error
	InspectContainer(context.Context, string) (dockerContainer, error)
	PullImage(context.Context, string) error
	InspectImage(context.Context, string) (dockerImage, error)
	StopContainer(context.Context, string) error
	StartContainer(context.Context, string) error
	RenameContainer(context.Context, string, string) error
	CreateReplacement(context.Context, string, dockerContainer, dockerImage, string) (string, error)
	RemoveContainer(context.Context, string) error
}

type dockerHTTP struct {
	client *http.Client
}

func newDockerHTTP(socket string) (*dockerHTTP, error) {
	if socket != "/var/run/docker.sock" {
		return nil, errors.New("Docker helper requires the fixed local Engine socket")
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		},
		DisableCompression: true,
		MaxIdleConns:       4,
		IdleConnTimeout:    30 * time.Second,
	}
	return &dockerHTTP{client: &http.Client{Transport: transport, Timeout: 5 * time.Minute}}, nil
}

func (d *dockerHTTP) Ping(ctx context.Context) error {
	return d.call(ctx, http.MethodGet, "/_ping", nil, []int{http.StatusOK}, nil)
}

func (d *dockerHTTP) InspectContainer(ctx context.Context, name string) (dockerContainer, error) {
	var result dockerContainer
	err := d.call(ctx, http.MethodGet, "/"+dockerAPIVersion+"/containers/"+url.PathEscape(name)+"/json", nil,
		[]int{http.StatusOK}, &result)
	return result, err
}

func (d *dockerHTTP) PullImage(ctx context.Context, reference string) error {
	repository, tag, ok := strings.Cut(reference, ":")
	if !ok || repository != DockerImageRepository || !deploymentVersion(tag) {
		return errors.New("Docker pull requires one official exact release tag")
	}
	path := "/" + dockerAPIVersion + "/images/create?fromImage=" + url.QueryEscape(repository) + "&tag=" + url.QueryEscape(tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return errors.New("Docker image pull failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Docker image pull returned HTTP %d", resp.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, (8<<20)+1))
	for {
		var event struct {
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := decoder.Decode(&event); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return errors.New("Docker image pull response was invalid")
		}
		if event.Error != "" || event.ErrorDetail.Message != "" {
			return errors.New("Docker registry rejected the official image pull")
		}
	}
	return nil
}

func (d *dockerHTTP) InspectImage(ctx context.Context, reference string) (dockerImage, error) {
	var result dockerImage
	err := d.call(ctx, http.MethodGet, "/"+dockerAPIVersion+"/images/"+url.PathEscape(reference)+"/json", nil,
		[]int{http.StatusOK}, &result)
	return result, err
}

func (d *dockerHTTP) StopContainer(ctx context.Context, name string) error {
	return d.call(ctx, http.MethodPost, "/"+dockerAPIVersion+"/containers/"+url.PathEscape(name)+"/stop?t=30", nil,
		[]int{http.StatusNoContent, http.StatusNotModified}, nil)
}

func (d *dockerHTTP) StartContainer(ctx context.Context, name string) error {
	return d.call(ctx, http.MethodPost, "/"+dockerAPIVersion+"/containers/"+url.PathEscape(name)+"/start", nil,
		[]int{http.StatusNoContent, http.StatusNotModified}, nil)
}

func (d *dockerHTTP) RenameContainer(ctx context.Context, name, replacement string) error {
	path := "/" + dockerAPIVersion + "/containers/" + url.PathEscape(name) + "/rename?name=" + url.QueryEscape(replacement)
	return d.call(ctx, http.MethodPost, path, nil, []int{http.StatusNoContent}, nil)
}

func (d *dockerHTTP) RemoveContainer(ctx context.Context, name string) error {
	return d.call(ctx, http.MethodDelete, "/"+dockerAPIVersion+"/containers/"+url.PathEscape(name)+"?v=false&force=false", nil,
		[]int{http.StatusNoContent}, nil)
}

func (d *dockerHTTP) CreateReplacement(ctx context.Context, name string, old dockerContainer, image dockerImage, reference string) (string, error) {
	var config map[string]json.RawMessage
	if err := json.Unmarshal(old.Config, &config); err != nil {
		return "", errors.New("managed container configuration is invalid")
	}
	encodedImage, _ := json.Marshal(reference)
	config["Image"] = encodedImage
	var labels map[string]string
	if raw := config["Labels"]; len(raw) > 0 {
		_ = json.Unmarshal(raw, &labels)
	}
	if labels == nil {
		labels = map[string]string{}
	}
	for key, value := range image.Config.Labels {
		if strings.HasPrefix(key, "org.opencontainers.image.") || key == DockerLabelStateSchema || key == DockerLabelUpgradeContract {
			labels[key] = value
		}
	}
	encodedLabels, _ := json.Marshal(labels)
	config["Labels"] = encodedLabels
	config["HostConfig"] = old.HostConfig
	body, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	var created struct {
		ID string `json:"Id"`
	}
	path := "/" + dockerAPIVersion + "/containers/create?name=" + url.QueryEscape(name)
	if err := d.call(ctx, http.MethodPost, path, bytes.NewReader(body), []int{http.StatusCreated}, &created); err != nil {
		return "", err
	}
	if len(created.ID) < 12 {
		return "", errors.New("Docker returned an invalid replacement container identity")
	}
	return created.ID, nil
}

func (d *dockerHTTP) call(ctx context.Context, method, path string, body io.Reader, accepted []int, output any) error {
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return errors.New("Docker Engine request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errDockerNotFound
	}
	valid := false
	for _, status := range accepted {
		valid = valid || resp.StatusCode == status
	}
	if !valid {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("Docker Engine returned HTTP %d", resp.StatusCode)
	}
	if output == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, (2<<20)+1))
	if err := decoder.Decode(output); err != nil {
		return errors.New("Docker Engine response was invalid")
	}
	return nil
}

func deploymentVersion(value string) bool {
	return deployment.ValidReleaseVersion(value)
}

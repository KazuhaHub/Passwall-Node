// Package upgrade owns the narrow managed-agent upgrade contract for supported
// Linux/systemd and Docker layouts. Proxy-core selection remains declarative
// configuration, not an agent upgrade task.
package upgrade

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"

	"github.com/KazuhaHub/passwall-node/v4/releaseid"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

const TaskKind = protocol.TaskKindAgentUpgradeV1
const InstallRoot = "/opt/passwall-node"

const (
	UpgradeContract            = 1
	DockerControlDir           = "/run/passwall-node-upgrades"
	DockerBinaryPath           = "/usr/local/bin/passwall-node"
	DockerDataDir              = "/var/lib/passwall-node"
	DockerMarker               = "agent.upgrade.v1 docker.v1\n"
	DockerImageRepository      = "ghcr.io/kazuhahub/passwall-node"
	DockerLabelManaged         = "io.kazuhahub.passwall-node.managed"
	DockerLabelRole            = "io.kazuhahub.passwall-node.role"
	DockerLabelAgentID         = "io.kazuhahub.passwall-node.agent-id"
	DockerLabelStateSchema     = "io.kazuhahub.passwall-node.state-schema"
	DockerLabelUpgradeContract = "io.kazuhahub.passwall-node.upgrade-contract"
)

type Args = protocol.AgentUpgradeArgs

// A same-boot elapsed deadline prevents a stale filesystem request from becoming
// a new upgrade authorization after restart, suspend, or wall-clock changes.
type Request struct {
	Task                      protocol.Task `json:"task"`
	Args                      Args          `json:"args"`
	BootID                    string        `json:"boot_id"`
	AuthorizedUntilBoottimeNS int64         `json:"authorized_until_boottime_ns"`
}

type Result = protocol.AgentUpgradeResult

type Receipt struct {
	Request         Request `json:"request"`
	Phase           string  `json:"phase"`
	Result          *Result `json:"result,omitempty"`
	ErrorCode       string  `json:"error_code,omitempty"`
	Error           string  `json:"error,omitempty"`
	ActivationNonce string  `json:"activation_nonce,omitempty"`
}

type Ready struct {
	TaskID          string `json:"task_id"`
	InputSHA256     string `json:"input_sha256"`
	Version         string `json:"version"`
	BinarySHA256    string `json:"binary_sha256"`
	ActivationNonce string `json:"activation_nonce"`
	PID             int    `json:"pid"`
}

type BuildInfo struct {
	Version         string `json:"version"`
	StateSchema     int    `json:"state_schema"`
	UpgradeContract int    `json:"upgrade_contract"`
}

func DecodeStrict(data []byte, target any) error {
	if err := checkJSONShape(json.NewDecoder(bytes.NewReader(data)), reflect.TypeOf(target)); err != nil {
		return errors.New("invalid upgrade document shape")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("invalid upgrade document")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("upgrade document must contain one JSON value")
	}
	return nil
}

func checkJSONShape(d *json.Decoder, t reflect.Type) error {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim == '{' {
		seen := map[string]bool{}
		fields := map[string]reflect.Type{}
		if t != nil && t.Kind() == reflect.Struct {
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				name := strings.Split(f.Tag.Get("json"), ",")[0]
				if name != "" && name != "-" {
					fields[name] = f.Type
				}
			}
		}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := k.(string)
			if !ok || seen[key] {
				return errors.New("duplicate JSON key")
			}
			seen[key] = true
			child := fields[key]
			if t != nil && t.Kind() == reflect.Struct && child == nil {
				return errors.New("noncanonical JSON key")
			}
			if err := checkJSONShape(d, child); err != nil {
				return err
			}
		}
	} else if delim == '[' {
		var child reflect.Type
		if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
			child = t.Elem()
		}
		for d.More() {
			if err := checkJSONShape(d, child); err != nil {
				return err
			}
		}
	} else {
		return errors.New("unexpected JSON delimiter")
	}
	_, err = d.Token()
	return err
}

func ParseArgs(task protocol.Task) (Args, error) {
	if task.Kind != TaskKind || task.NotAfterMS <= 0 || protocol.ValidateTasks([]protocol.Task{task}) != nil {
		return Args{}, errors.New("upgrade requires a valid identity-bound task and start deadline")
	}
	args, err := protocol.DecodeAgentUpgradeArgs(task.Args)
	if err != nil {
		return Args{}, err
	}
	// THE TARGET IS EXACT, AND THAT IS AN ADDRESSING REQUIREMENT. Fetch derives the
	// download address from this version and the checksum manifest names it, so a
	// target that is not a release version cannot be fetched at all.
	if !releaseid.ValidVersion(args.Version) {
		return args, errors.New("upgrade requires an exact release to install")
	}
	// THE VERSION BEING REPLACED IS OPAQUE. The agent compares it against its own
	// compiled version — see client.go — so it is an IDENTITY rather than a version
	// this has any business parsing, and requiring a product version here is what
	// made a node still reporting a stamp from the replaced scheme impossible to
	// move: the request never got past this function.
	if args.ExpectedVersion == "" {
		return args, errors.New("upgrade requires the version the agent is expected to be on")
	}
	// A NO-OP IS REFUSED BY IDENTITY, NOT BY ORDER. There is no ordering rule any
	// more: it cannot order a stamp from the replaced scheme against a product
	// version at all, and an operator choosing an older release is making an
	// explicit choice. What stops that choice from installing something else is the
	// signed checksum manifest and the downloaded binary's own version check.
	if args.ExpectedVersion == args.Version {
		return args, errors.New("upgrade requires a target other than the version the agent is on")
	}
	return args, nil
}

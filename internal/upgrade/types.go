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

	"github.com/KazuhaHub/passwall-node/releaseid"
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
	if !releaseid.ValidVersion(args.Version) || !releaseid.ValidVersion(args.ExpectedVersion) ||
		CompareVersions(args.Version, args.ExpectedVersion) <= 0 {
		return args, errors.New("upgrade requires an exact newer release and exact expected current release")
	}
	return args, nil
}

// CompareVersions orders two release versions, -1 / 0 / +1.
//
// It delegates to releaseid rather than carrying its own copy of the rule. The
// rule is the project's release order, and it is applied in three places — here,
// the release CLI, and the panel's admission check — so a second implementation
// is a second opinion about whether an upgrade is an upgrade.
//
// IT PARSES, AND IT USED NOT TO HAVE TO. The old rule compared the strings, which
// works for a shape whose order the text happens to encode and stops working the
// moment one does not; releaseid's product rule compares parsed versions, which
// is the same answer for every input that is a version and no answer at all for
// one that is not.
//
// AN UNPARSEABLE INPUT COMPARES EQUAL, which the caller turns into a refusal: it
// validates both versions with releaseid.ValidVersion before asking which is
// newer, so a string that cannot be parsed here is a programming error rather
// than an operator's input — and the fail-closed reading of "cannot be shown to
// be newer" is the same one the shape check makes.
func CompareVersions(a, b string) int {
	left, leftErr := releaseid.ParseProductVersion(a)
	right, rightErr := releaseid.ParseProductVersion(b)
	if leftErr != nil || rightErr != nil {
		return 0
	}
	return releaseid.CompareProductVersion(left, right)
}

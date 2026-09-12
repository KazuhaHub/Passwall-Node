// Package upgrade owns the narrow Linux/systemd agent upgrade contract.
// Proxy-core selection remains declarative configuration, not an upgrade task.
package upgrade

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"

	"github.com/KazuhaHub/passwall-node/deployment"
	"github.com/KazuhaHub/passwall-node/protocol"
)

const TaskKind = "agent.upgrade.v1"
const InstallRoot = "/opt/passwall-node"

type Args struct {
	Version         string `json:"version"`
	ExpectedVersion string `json:"expected_version"`
}

// A same-boot elapsed deadline prevents a stale filesystem request from becoming
// a new upgrade authorization after restart, suspend, or wall-clock changes.
type Request struct {
	Task                      protocol.Task `json:"task"`
	Args                      Args          `json:"args"`
	BootID                    string        `json:"boot_id"`
	AuthorizedUntilBoottimeNS int64         `json:"authorized_until_boottime_ns"`
}

type Result struct {
	Version         string `json:"version"`
	PreviousVersion string `json:"previous_version"`
	BinarySHA256    string `json:"binary_sha256"`
	Restarted       bool   `json:"restarted"`
}

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
	var args Args
	if task.Kind != TaskKind || task.NotAfterMS <= 0 || protocol.ValidateTasks([]protocol.Task{task}) != nil {
		return args, errors.New("upgrade requires a valid identity-bound task and start deadline")
	}
	if err := DecodeStrict(task.Args, &args); err != nil {
		return args, err
	}
	if !deployment.ValidReleaseVersion(args.Version) || !deployment.ValidReleaseVersion(args.ExpectedVersion) ||
		CompareVersions(args.Version, args.ExpectedVersion) <= 0 {
		return args, errors.New("upgrade requires an exact newer release and exact expected current release")
	}
	return args, nil
}

// CompareVersions accepts only canonical tags already validated by deployment.
// Compare numeric identifiers by length so untrusted numbers cannot overflow.
func CompareVersions(a, b string) int {
	left, lp, _ := strings.Cut(strings.TrimPrefix(a, "v"), "-")
	right, rp, _ := strings.Cut(strings.TrimPrefix(b, "v"), "-")
	for i, l := range strings.Split(left, ".") {
		r := strings.Split(right, ".")[i]
		if c := compareNumeric(l, r); c != 0 {
			return c
		}
	}
	if lp == rp {
		return 0
	}
	if lp == "" {
		return 1
	}
	if rp == "" {
		return -1
	}
	ls, rs := strings.Split(lp, "."), strings.Split(rp, ".")
	for i := 0; i < len(ls) && i < len(rs); i++ {
		ln, rn := numeric(ls[i]), numeric(rs[i])
		if ln && !rn {
			return -1
		}
		if !ln && rn {
			return 1
		}
		c := strings.Compare(ls[i], rs[i])
		if ln {
			c = compareNumeric(ls[i], rs[i])
		}
		if c != 0 {
			return c
		}
	}
	if len(ls) < len(rs) {
		return -1
	}
	if len(ls) > len(rs) {
		return 1
	}
	return 0
}

func numeric(s string) bool { return s != "" && strings.Trim(s, "0123456789") == "" }
func compareNumeric(a, b string) int {
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return strings.Compare(a, b)
}

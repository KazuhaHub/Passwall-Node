package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// TaskKindAgentUpgradeV1 is the durable task kind for replacing the Node
// binary and proving the resulting process identity.
const TaskKindAgentUpgradeV1 = "agent.upgrade.v1"

// AgentUpgradeArgs is the exact v1 request body. Both fields are required;
// accepting an unknown or missing field would let the two peers assign
// different meaning to the same signed task input.
type AgentUpgradeArgs struct {
	Version         string `json:"version"`
	ExpectedVersion string `json:"expected_version"`
}

// AgentUpgradeResult is the exact v1 success body returned by the Node.
type AgentUpgradeResult struct {
	Version         string `json:"version"`
	PreviousVersion string `json:"previous_version"`
	BinarySHA256    string `json:"binary_sha256"`
	Restarted       bool   `json:"restarted"`
}

// DecodeAgentUpgradeArgs accepts exactly the fields defined by
// AgentUpgradeArgs, once each, with no trailing JSON value.
func DecodeAgentUpgradeArgs(data []byte) (AgentUpgradeArgs, error) {
	var value AgentUpgradeArgs
	err := decodeExactObject(data, &value)
	return value, err
}

// DecodeAgentUpgradeResult accepts exactly the fields defined by
// AgentUpgradeResult, once each, with no trailing JSON value.
func DecodeAgentUpgradeResult(data []byte) (AgentUpgradeResult, error) {
	var value AgentUpgradeResult
	err := decodeExactObject(data, &value)
	return value, err
}

func decodeExactObject(data []byte, target any) error {
	targetType := reflect.TypeOf(target)
	if targetType == nil || targetType.Kind() != reflect.Pointer || targetType.Elem().Kind() != reflect.Struct {
		return errors.New("upgrade decoder target must point to a struct")
	}
	fields := make([]string, 0, targetType.Elem().NumField())
	allowed := make(map[string]struct{}, targetType.Elem().NumField())
	for i := 0; i < targetType.Elem().NumField(); i++ {
		field := strings.Split(targetType.Elem().Field(i).Tag.Get("json"), ",")[0]
		if field == "" || field == "-" {
			continue
		}
		fields = append(fields, field)
		allowed[field] = struct{}{}
	}
	seen := make(map[string]struct{}, len(fields))
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return errors.New("invalid JSON object")
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return errors.New("upgrade document must be a JSON object")
	}
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return errors.New("invalid JSON object")
		}
		field, ok := token.(string)
		if !ok {
			return errors.New("invalid JSON object key")
		}
		if _, ok := allowed[field]; !ok {
			return fmt.Errorf("unknown field %q", field)
		}
		if _, ok := seen[field]; ok {
			return fmt.Errorf("duplicate field %q", field)
		}
		seen[field] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("decode field %q: %w", field, err)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return errors.New("invalid JSON object")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("upgrade document must contain one JSON value")
	}
	for _, field := range fields {
		if _, ok := seen[field]; !ok {
			return fmt.Errorf("missing field %q", field)
		}
	}
	if err := json.Unmarshal(data, target); err != nil {
		return errors.New("invalid upgrade document")
	}
	return nil
}

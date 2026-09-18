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
	return decodeExactObjectMayOmit(data, target, nil)
}

// decodeExactObjectMayOmit is decodeExactObject for a document that is allowed
// to leave the named fields out.
//
// A MISSING FIELD IS STILL AN ERROR BY DEFAULT, because accepting an absent one
// lets the two peers assign different meaning to the same bytes — the reason
// this decoder is exact at all. The exception exists for fields whose absence is
// itself a statement: a diagnostics result omits a section it was not asked to
// collect, and "not asked" must stay distinguishable from "asked, found
// nothing". Unknown fields, duplicates and trailing values are refused either
// way.
func decodeExactObjectMayOmit(data []byte, target any, optional []string) error {
	targetType := reflect.TypeOf(target)
	if targetType == nil || targetType.Kind() != reflect.Pointer || targetType.Elem().Kind() != reflect.Struct {
		return errors.New("decoder target must point to a struct")
	}
	mayOmit := make(map[string]struct{}, len(optional))
	for _, name := range optional {
		mayOmit[name] = struct{}{}
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
		return errors.New("document must be a JSON object")
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
		return errors.New("document must contain one JSON value")
	}
	for _, field := range fields {
		if _, ok := seen[field]; ok {
			continue
		}
		if _, ok := mayOmit[field]; ok {
			continue
		}
		return fmt.Errorf("missing field %q", field)
	}
	if err := json.Unmarshal(data, target); err != nil {
		return errors.New("invalid document")
	}
	return nil
}

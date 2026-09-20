// Package nodeconfig validates and serialises the local control-plane identity.
package nodeconfig

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

var agentIdentity = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)

// Connection is the complete secret-bearing identity required by the agent.
// Callers must never log the struct or its Credential field.
type Connection struct {
	Endpoint   string
	AgentID    string
	Credential string
}

// Validate checks the exact same connection contract for private installers,
// the public interactive setup and subsequent pn configuration changes.
func Validate(connection Connection) error {
	if !agentIdentity.MatchString(connection.AgentID) {
		return errors.New("agent ID must be 1..64 canonical ASCII characters")
	}
	if len(connection.Credential) < protocol.MinNodeCredentialBytes || len(connection.Credential) > protocol.MaxNodeCredentialBytes {
		return fmt.Errorf("node credential must contain %d..%d bytes", protocol.MinNodeCredentialBytes, protocol.MaxNodeCredentialBytes)
	}
	for _, character := range []byte(connection.Credential) {
		if character < 0x21 || character > 0x7e {
			return errors.New("node credential must use visible ASCII without whitespace")
		}
	}
	return ValidateEndpoint(connection.Endpoint)
}

// ValidateEndpoint accepts only the canonical HTTPS sync endpoint understood
// by the production agent. Plain HTTP remains a daemon-only development flag.
func ValidateEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.RawPath != "" || u.String() != endpoint || !strings.HasSuffix(u.Path, "/v1/node/sync") {
		return errors.New("endpoint must be an absolute HTTPS sync URL without userinfo, query or fragment")
	}
	for _, character := range []byte(endpoint) {
		if character < 0x21 || character > 0x7e || character == '\\' {
			return errors.New("endpoint must be canonical ASCII")
		}
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return errors.New("endpoint path must not traverse directories")
		}
	}
	if strings.Contains(u.Path, "//") {
		return errors.New("endpoint path must be canonical")
	}
	return nil
}

// ValidAgentID reports whether value is a canonical wire identity.
func ValidAgentID(value string) bool { return agentIdentity.MatchString(value) }

// EnvironmentFile returns the canonical non-secret systemd EnvironmentFile.
func EnvironmentFile(connection Connection) string {
	return "PSP_NODE_AGENT_ID=" + strconv.Quote(connection.AgentID) + "\n" +
		"PSP_NODE_ENDPOINT=" + strconv.Quote(connection.Endpoint) + "\n"
}

// ParseEnvironmentFile reads only the two managed fields. Unknown fields are
// ignored for forwards compatibility, while duplicate managed fields fail.
func ParseEnvironmentFile(contents []byte) (endpoint, agentID string, err error) {
	seen := map[string]bool{}
	for lineNumber, raw := range strings.Split(string(contents), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, encoded, ok := strings.Cut(line, "=")
		if !ok {
			return "", "", fmt.Errorf("environment line %d is invalid", lineNumber+1)
		}
		if key != "PSP_NODE_ENDPOINT" && key != "PSP_NODE_AGENT_ID" {
			continue
		}
		if seen[key] {
			return "", "", fmt.Errorf("environment field %s appears more than once", key)
		}
		seen[key] = true
		value, decodeErr := strconv.Unquote(encoded)
		if decodeErr != nil {
			return "", "", fmt.Errorf("environment field %s is not canonically quoted", key)
		}
		switch key {
		case "PSP_NODE_ENDPOINT":
			endpoint = value
		case "PSP_NODE_AGENT_ID":
			agentID = value
		}
	}
	if endpoint == "" || agentID == "" {
		return "", "", errors.New("environment is missing PSP_NODE_ENDPOINT or PSP_NODE_AGENT_ID")
	}
	if err := ValidateEndpoint(endpoint); err != nil {
		return "", "", err
	}
	if !ValidAgentID(agentID) {
		return "", "", errors.New("agent ID must be 1..64 canonical ASCII characters")
	}
	return endpoint, agentID, nil
}

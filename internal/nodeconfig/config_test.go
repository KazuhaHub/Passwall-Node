package nodeconfig

import (
	"strings"
	"testing"
)

func validConnection() Connection {
	return Connection{
		Endpoint:   "https://panel.example/psp/v1/node/sync",
		AgentID:    "agt_node-1",
		Credential: "pspn_" + strings.Repeat("a", 40),
	}
}

func TestEnvironmentFileRoundTrip(t *testing.T) {
	connection := validConnection()
	endpoint, agentID, err := ParseEnvironmentFile([]byte(EnvironmentFile(connection)))
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != connection.Endpoint || agentID != connection.AgentID {
		t.Fatalf("round trip = %q %q", endpoint, agentID)
	}
}

func TestValidateRejectsUnsafeConnection(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Connection)
	}{
		{"http", func(c *Connection) { c.Endpoint = "http://panel.example/v1/node/sync" }},
		{"query", func(c *Connection) { c.Endpoint += "?secret=yes" }},
		{"wrong-path", func(c *Connection) { c.Endpoint = "https://panel.example/api" }},
		{"agent", func(c *Connection) { c.AgentID = "bad agent" }},
		{"short-credential", func(c *Connection) { c.Credential = "short" }},
		{"credential-space", func(c *Connection) { c.Credential += " " }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connection := validConnection()
			test.edit(&connection)
			if err := Validate(connection); err == nil {
				t.Fatal("unsafe connection was accepted")
			}
		})
	}
}

func TestParseEnvironmentFileRejectsDuplicateManagedFields(t *testing.T) {
	contents := EnvironmentFile(validConnection()) + `PSP_NODE_AGENT_ID="other"` + "\n"
	if _, _, err := ParseEnvironmentFile([]byte(contents)); err == nil {
		t.Fatal("duplicate managed field was accepted")
	}
}

package singbox

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func TestCompilerAlwaysRejectsVisiblePrivateDestinationsBeforePolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy *protocol.DestinationPolicy
	}{
		{"no-policy", nil},
		{"empty-or-paused-policy", &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{}}},
		{"unsupported-collection", &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{}, Collect: protocol.CollectHits, CollectRevision: 1}},
		{"global-private-allow", &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleAllow, Private: true}}}},
		{"sniffed-domain-allow", &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleAllow, Domains: []string{"full:allowed.example"}}}}},
		{"exempt-user", &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleObserve, Ports: "443"}}, Exempt: []protocol.SubjectKey{"usr_61"}}},
		{"allowlist-catch-all", &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{{ID: "g1", Action: protocol.RuleBlock, Subjects: []protocol.SubjectKey{"usr_61"}, CatchAll: true}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := realitySnapshot(t)
			snapshot.DestinationPolicy = tc.policy
			artifact, err := (Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}).Compile(context.Background(), snapshot)
			if err != nil {
				t.Fatal(err)
			}
			var config struct {
				Route struct {
					Rules []map[string]any `json:"rules"`
					Final string           `json:"final"`
				} `json:"route"`
			}
			if json.Unmarshal(artifact.Config, &config) != nil {
				t.Fatal("invalid core artifact")
			}
			if len(config.Route.Rules) == 0 {
				t.Fatal("private-address guard is absent")
			}
			first := config.Route.Rules[0]
			if len(first) != 2 || first["ip_is_private"] != true || first["action"] != "reject" || config.Route.Final != "direct" {
				t.Fatal("private-address rejection is conditional, reordered or implicitly resolves domains")
			}
			for _, rule := range config.Route.Rules {
				if rule["action"] == "resolve" {
					t.Fatal("private-address guard expanded to domain resolution")
				}
			}
		})
	}
}

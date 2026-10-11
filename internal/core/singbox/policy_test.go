package singbox

import (
	"context"
	"encoding/json"
	"github.com/KazuhaHub/passwall-protocol/protocol"
	"testing"
)

func TestDestinationPolicyNativeRuleOrderAndDomainIPUnion(t *testing.T) {
	snapshot := realitySnapshot(t)
	snapshot.DestinationPolicy = &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p9", Action: protocol.RuleAllow, Domains: []string{"full:allowed.example"}},
		{ID: "p1", Action: protocol.RuleBlock, Subjects: []protocol.SubjectKey{"usr_61"}, Domains: []string{"domain:example.com", "keyword:example", "regexp:example"}, CIDRs: []string{"10.0.0.0/8"}, Ports: "25,80-90", Network: "tcp", Private: true},
		{ID: "g2", Action: protocol.RuleBlock, Subjects: []protocol.SubjectKey{"usr_999"}, CatchAll: true},
		{ID: "p2", Action: protocol.RuleObserve, Ports: "443"},
	}}
	artifact, err := (Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}).Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
			Final string           `json:"final"`
		} `json:"route"`
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(artifact.Config, &config); err != nil {
		t.Fatal(err)
	}
	if config.Route.Final != "direct" || config.Outbounds[0]["tag"] != "direct" || len(config.Route.Rules) != 5 || config.Route.Rules[1]["action"] != "sniff" {
		t.Fatalf("unexpected rules: %s", artifact.Config)
	}
	block := config.Route.Rules[3]
	if block["action"] != "reject" || block["domain_suffix"] == nil || block["ip_cidr"] == nil || block["ip_is_private"] != true {
		t.Fatalf("domain/IP union was lost or split: %#v", block)
	}
	if block["port_range"].([]any)[0] != "80:90" || len(block["auth_user"].([]any)) != 1 {
		t.Fatal("ports or username scope compiled incorrectly")
	}
	if config.Route.Rules[4]["outbound"] != "psp-watch-p2" {
		t.Fatal("observe must route normally through a distinct direct outbound")
	}
}

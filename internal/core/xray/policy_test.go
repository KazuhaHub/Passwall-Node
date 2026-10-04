package xray

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func TestDestinationPolicyRoutingOrderAndSubjectExpansion(t *testing.T) {
	snapshot := realitySnapshot(t)
	second := snapshot.Clients[0]
	second.Key = "cli_52"
	second.Credentials.Username = "psp-u61-row2@example.invalid"
	second.Credentials.UUID = "0f62f495-b5ca-4509-b6cd-54a040deafd6"
	snapshot.Clients = append(snapshot.Clients, second)
	snapshot.DestinationPolicy = &protocol.DestinationPolicy{Exempt: []protocol.SubjectKey{"usr_61"}, Rules: []protocol.DestinationRule{
		{ID: "p9", Action: protocol.RuleAllow, Domains: []string{"domain:allowed.example"}},
		{ID: "p1", Action: protocol.RuleBlock, Subjects: []protocol.SubjectKey{"usr_61"}, Domains: []string{"domain:blocked.example"}, CIDRs: []string{"10.0.0.0/8"}, Ports: "443", Network: "tcp"},
		{ID: "g2", Action: protocol.RuleBlock, Subjects: []protocol.SubjectKey{"usr_999"}, CatchAll: true},
		{ID: "p2", Action: protocol.RuleObserve, Ports: "25"},
	}}
	artifact, err := (Compiler{}).Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Routing struct {
			DomainStrategy string           `json:"domainStrategy"`
			Rules          []map[string]any `json:"rules"`
		} `json:"routing"`
		Outbounds []map[string]any `json:"outbounds"`
		Inbounds  []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal(artifact.Config, &config); err != nil {
		t.Fatal(err)
	}
	if config.Routing.DomainStrategy != "AsIs" || len(config.Routing.Rules) != 5 || config.Outbounds[0]["tag"] != "direct" {
		t.Fatalf("unexpected routing: %s", artifact.Config)
	}
	for i, want := range []string{"psp-p9", "psp-exempt", "psp-p1a", "psp-p1b", "psp-p2"} {
		if config.Routing.Rules[i]["ruleTag"] != want {
			t.Fatalf("rule %d = %#v, want %s", i, config.Routing.Rules[i], want)
		}
	}
	if users, ok := config.Routing.Rules[2]["user"].([]any); !ok || len(users) != 2 {
		t.Fatal("all deployed emails for the subject must be expanded")
	}
	if strings.Contains(string(artifact.Config), `"user": []`) || strings.Contains(string(artifact.Config), "psp-g2") {
		t.Fatal("missing subject rule widened to all users")
	}
	if nestedObject(t, config.Inbounds[0], "sniffing")["routeOnly"] != true {
		t.Fatal("new sniffing must not rewrite actual destination")
	}
}

func TestDestinationPolicySniffingErrorIsNotObjectRejection(t *testing.T) {
	snapshot := realitySnapshot(t)
	var spec listenerSpec
	_ = json.Unmarshal(snapshot.Listeners[0].Config, &spec)
	spec.Sniffing = `{"enabled":true,"metadataOnly":true,"destOverride":["http","tls","quic"]}`
	snapshot.Listeners[0].Config, _ = json.Marshal(spec)
	snapshot.DestinationPolicy = &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"full:example.com"}}}}
	_, err := (Compiler{}).Compile(context.Background(), snapshot)
	var policyErr *agentcore.PolicyError
	var objectErr *agentcore.ObjectError
	if !errors.As(err, &policyErr) || errors.As(err, &objectErr) || policyErr.Code != protocol.IssueDestinationPolicySniffingInsufficient || len(policyErr.Listeners) != 1 || policyErr.Listeners[0] != "lst_41" {
		t.Fatalf("error = %#v, want only policy-scoped sniffing rejection", err)
	}
}

func TestDestinationPolicyWebhookRequiresCollectionAndLiveSocket(t *testing.T) {
	for _, v := range []struct {
		name    string
		collect protocol.CollectLevel
		socket  string
		want    bool
	}{{"no receiver", protocol.CollectHits, "", false}, {"off", "", "/tmp/audit.sock", false}, {"receiver", protocol.CollectHits, "/tmp/audit.sock", true}, {"relative path", protocol.CollectHits, "audit.sock", false}, {"path too long", protocol.CollectHits, "/" + strings.Repeat("x", 100), false}} {
		t.Run(v.name, func(t *testing.T) {
			snapshot := realitySnapshot(t)
			revision := uint64(0)
			if v.collect != "" {
				revision = 7
			}
			snapshot.DestinationPolicy = &protocol.DestinationPolicy{Collect: v.collect, CollectRevision: revision, Rules: []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, Ports: "25"}}}
			artifact, err := (Compiler{AuditSocket: v.socket, AuditToken: "0123456789abcdef0123456789abcdef"}).Compile(context.Background(), snapshot)
			if err != nil {
				t.Fatal(err)
			}
			var result map[string]any
			_ = json.Unmarshal(artifact.Config, &result)
			rule := nestedObject(t, result, "routing")["rules"].([]any)[0].(map[string]any)
			_, got := rule["webhook"]
			if got != v.want {
				t.Fatalf("webhook = %v, want %v", got, v.want)
			}
			if got {
				headers := nestedObject(t, nestedObject(t, rule, "webhook"), "headers")
				if headers["X-PSP-Audit-Revision"] != "7" {
					t.Fatal("webhook lost compiled collection revision")
				}
			}
		})
	}
}

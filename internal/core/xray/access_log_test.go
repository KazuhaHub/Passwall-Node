package xray

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func TestUsageAccessLogRequiresBothDeployedCollectionAndInstalledFilter(t *testing.T) {
	for _, tc := range []struct {
		name     string
		policy   *protocol.DestinationPolicy
		filtered bool
		stdout   bool
	}{
		{name: "legacy without filter"},
		{name: "legacy with filter", filtered: true},
		{name: "off with filter", filtered: true, policy: &protocol.DestinationPolicy{}},
		{name: "hits without filter", policy: &protocol.DestinationPolicy{Collect: protocol.CollectHits, CollectRevision: 7}},
		{name: "hits with filter", filtered: true, policy: &protocol.DestinationPolicy{Collect: protocol.CollectHits, CollectRevision: 7}},
		{name: "usage without filter", policy: &protocol.DestinationPolicy{Collect: protocol.CollectHitsAndUsage, CollectRevision: 7}},
		{name: "rule-free usage with filter", filtered: true, stdout: true, policy: &protocol.DestinationPolicy{Collect: protocol.CollectHitsAndUsage, CollectRevision: 7}},
		{name: "usage rules with filter", filtered: true, stdout: true, policy: &protocol.DestinationPolicy{Collect: protocol.CollectHitsAndUsage, CollectRevision: 7, Rules: []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleObserve, Ports: "443"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := realitySnapshot(t)
			snapshot.DestinationPolicy = tc.policy
			artifact, err := (Compiler{AccessLog: "private-unfiltered.log", ErrorLog: "error.log", AccessLogFiltered: tc.filtered}).Compile(context.Background(), snapshot)
			if err != nil {
				t.Fatal(err)
			}
			var config struct {
				Log map[string]any `json:"log"`
			}
			if err := json.Unmarshal(artifact.Config, &config); err != nil {
				t.Fatal(err)
			}
			access, exists := config.Log["access"]
			if tc.stdout && exists || !tc.stdout && (!exists || access != "none") {
				t.Fatalf("log.access=%v present=%t filtered stdout=%t", access, exists, tc.stdout)
			}
			if config.Log["error"] != "error.log" || config.Log["loglevel"] != "warning" {
				t.Fatal("access collection rewrote ordinary error logging")
			}
		})
	}
}

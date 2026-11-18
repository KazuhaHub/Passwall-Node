package agent

import (
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func guardHitsFixture() []protocol.SourceGuardHit {
	return []protocol.SourceGuardHit{
		{Set: "src_a", Listener: "lst_1", SourceIP: "203.0.113.9", Count: 3, LastSeenMS: 1700000000000},
	}
}

// Guard hits go after telemetry and before the audit batch, and the interface
// addresses stay until the report turns partial, where both must be gone: a
// partial report that carried them would fail validation.
func TestFitReportToWireDropsGuardHitsAfterTelemetryAndBeforeAudit(t *testing.T) {
	report := protocol.NodeReport{
		AgentID: "agent-1", Host: &protocol.HostObservation{SampleID: "0123456789abcdef0123456789abcdef"},
		SourceGuardHits: guardHitsFixture(), InterfaceAddresses: []string{"1.2.3.4"},
		Audit: &protocol.AuditObservation{Hits: []protocol.AuditHit{{RuleID: "p1", Dest: "example.com", Port: 443, Count: 1}}},
	}
	// Room for everything but the telemetry: the sample is the only loss.
	noHost := report
	noHost.Host = nil
	result, err := fitReportToWire(&report, false, wireSize(t, noHost), false)
	if err != nil || !result.HostDropped || result.GuardHitsDropped || len(report.SourceGuardHits) != 1 || report.Audit == nil {
		t.Fatalf("result = %+v, err = %v, report = %+v", result, err, report)
	}
	// Room for the control content and the audit batch, but not the hits.
	noHits := report
	noHits.SourceGuardHits = nil
	result, err = fitReportToWire(&report, false, wireSize(t, noHits), false)
	if err != nil || !result.GuardHitsDropped || report.SourceGuardHits != nil || report.Audit == nil || report.InterfaceAddresses == nil {
		t.Fatalf("result = %+v, err = %v, report = %+v", result, err, report)
	}
}

func TestFitReportToWireClearsGuardObservationsFromAPartialFallback(t *testing.T) {
	report := protocol.NodeReport{
		AgentID: "agent-1", Have: map[string]protocol.StreamState{},
		Objects:         []protocol.ObjectStatus{{Stream: "config", Key: "lst_1"}},
		SourceGuardHits: guardHitsFixture(), InterfaceAddresses: []string{"1.2.3.4"},
		Issues: []protocol.Issue{{Code: "x"}},
	}
	partial := report
	partial.Partial, partial.Objects, partial.SourceGuardHits, partial.InterfaceAddresses = true, nil, nil, nil
	if _, err := fitReportToWire(&report, true, wireSize(t, partial), false); err != nil {
		t.Fatal(err)
	}
	if !report.Partial || report.SourceGuardHits != nil || report.InterfaceAddresses != nil {
		t.Fatalf("report = %+v", report)
	}
}

func TestRosterValidationChecksTheSourceGuard(t *testing.T) {
	client := protocol.Client{
		Key: "cli_1", Subject: "usr_1", Enabled: true, Listeners: []protocol.ListenerKey{"lst_1"},
		SourceGuard: &protocol.ClientSourceGuard{AllowFrom: "src_a"},
	}
	body := &protocol.RosterBody{
		Clients: []protocol.Client{client}, MinConfigVersion: protocol.Version{Epoch: 1, Version: 1},
		Coverage: protocol.SegmentCounts{Entries: 1, Subjects: 1},
	}
	if err := validateRoster(body); err != nil {
		t.Fatalf("valid roster refused: %v", err)
	}
	body.Clients[0].SourceGuard = &protocol.ClientSourceGuard{}
	if err := validateRoster(body); err == nil {
		t.Fatal("a guard with neither allow nor deny was accepted")
	}
}

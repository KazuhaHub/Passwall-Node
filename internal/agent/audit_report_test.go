package agent

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/agent/audit"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func reportAuditFixture() *protocol.AuditObservation {
	hour := int64(1_800_000_000_000)
	return &protocol.AuditObservation{BatchID: strings.Repeat("a", 32), Kind: "block", Hour: hour, CollectRevision: 1, Hits: []protocol.AuditHit{{Hour: hour, RuleID: "p1", Action: "block", Subject: "usr_7", Dest: "a.example", Port: 443, Count: 1, FirstMS: hour + 1234, LastMS: hour + 1234}}}
}

type auditReportSource struct {
	batch        audit.Batch
	err          error
	calls        int
	ack, discard []string
}

func (s *auditReportSource) Next(int) (audit.Batch, error) { s.calls++; return s.batch, s.err }
func (s *auditReportSource) Acknowledge(kind, id string) bool {
	s.ack = append(s.ack, kind+"/"+id)
	return true
}
func (s *auditReportSource) DiscardInvalid(kind, id string) {
	s.discard = append(s.discard, kind+"/"+id)
}

type auditReportStore struct {
	*policyReportStore
	ackError error
}

func (s *auditReportStore) AckOutbox(context.Context, []int64) error { return s.ackError }
func auditReportBuilder() ReportBuilder {
	return ReportBuilder{AgentID: "agent-1", Store: &auditReportStore{policyReportStore: &policyReportStore{}}, Now: func() time.Time { return time.UnixMilli(1_800_000_001_234) }, Capabilities: []string{protocol.CapabilityAuditHits}}
}

func TestAuditReportCarriesBatchOnFullAndPartialShapes(t *testing.T) {
	for _, partial := range []bool{false, true} {
		source := &auditReportSource{batch: audit.Batch{Observation: reportAuditFixture(), HitsTrimmed: 2}}
		built, err := auditReportBuilder().Build(t.Context(), partial, BuildOptions{Audit: source})
		if err != nil {
			t.Fatal(err)
		}
		if built.Report.Audit == nil || built.AuditKind != "block" || built.AuditBatchIDSent != source.batch.Observation.BatchID || built.AuditHitsTrimmed != 2 {
			t.Fatalf("batch attachment partial=%v: %+v", partial, built)
		}
		wire, _ := json.Marshal(built.Report)
		var report protocol.NodeReport
		if json.Unmarshal(wire, &report) != nil || !reflect.DeepEqual(report.Audit, built.Report.Audit) {
			t.Fatalf("wire batch lost: %s", wire)
		}
		if err := protocol.ValidateNodeReport(report); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMalformedAuditIsDiscardedWithoutBlockingControl(t *testing.T) {
	source := &auditReportSource{batch: audit.Batch{Observation: reportAuditFixture(), Frozen: true}}
	source.batch.Observation.Hits[0].Subject = "bad"
	built, err := auditReportBuilder().Build(t.Context(), true, BuildOptions{Audit: source})
	if err != nil || built.Report.Audit != nil || !built.AuditInvalidDropped || len(source.discard) != 1 {
		t.Fatalf("bad audit blocked/escaped control: %+v %v discarded=%v", built, err, source.discard)
	}
	if err := protocol.ValidateNodeReport(built.Report); err != nil {
		t.Fatal(err)
	}
}

func TestAuditSourceFailureAndMissingCapabilitiesDoNotBlockControl(t *testing.T) {
	for _, capable := range []bool{true, false} {
		source := &auditReportSource{err: errors.New("unavailable")}
		builder := auditReportBuilder()
		if !capable {
			builder.Capabilities = nil
		}
		built, err := builder.Build(t.Context(), true, BuildOptions{Audit: source})
		if err != nil || built.Report.Audit != nil {
			t.Fatalf("optional failure blocked report: %+v %v", built, err)
		}
		if capable && (source.calls != 1 || !built.AuditDeferred) {
			t.Fatal("source failure was not isolated")
		}
		if !capable && source.calls != 0 {
			t.Fatal("unadvertised collector was consumed")
		}
	}
	usage := &protocol.AuditObservation{BatchID: strings.Repeat("a", 32), Kind: "usage", Hour: 1_800_000_000_000, CollectRevision: 1, Dropped: 1}
	source := &auditReportSource{batch: audit.Batch{Observation: usage, Frozen: true}}
	built, err := auditReportBuilder().Build(t.Context(), true, BuildOptions{Audit: source})
	if err != nil || built.Report.Audit != nil || !built.AuditDeferred || len(source.discard) != 0 {
		t.Fatalf("unadvertised usage blocked/cleared: %+v %v", built, err)
	}
}

func TestHostDropsBeforeFrozenAuditAndDeferredBatchIsUnchanged(t *testing.T) {
	builder := auditReportBuilder()
	builder.Capabilities = append(builder.Capabilities, protocol.CapabilityHostTelemetry)
	baseline, err := builder.Build(t.Context(), true, BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := &auditReportSource{batch: audit.Batch{Observation: reportAuditFixture(), Frozen: true}}
	withAudit := baseline.Report
	withAudit.Audit = source.batch.Observation
	builder.maxBodyBytes = wireSize(t, withAudit)
	host := validHostSample("0123456789abcdef0123456789abcdef")
	built, err := builder.Build(t.Context(), true, BuildOptions{Host: &host, Audit: source})
	if err != nil || !built.HostDropped || built.Report.Audit == nil || built.AuditDeferred {
		t.Fatalf("wrong degradation order: %+v %v", built, err)
	}
	want, _ := json.Marshal(source.batch.Observation)
	builder.maxBodyBytes = wireSize(t, baseline.Report)
	built, err = builder.Build(t.Context(), true, BuildOptions{Audit: source})
	got, _ := json.Marshal(source.batch.Observation)
	if err != nil || built.Report.Audit != nil || !built.AuditDeferred || built.AuditBatchIDSent != "" || string(got) != string(want) || len(source.discard) != 0 || len(source.ack) != 0 {
		t.Fatalf("frozen batch changed/confirmed while deferred: %+v %v", built, err)
	}
}

func TestNewAuditRowsFitActualControlAllowanceAndRemainAvailable(t *testing.T) {
	c := audit.New(func() time.Time { return time.UnixMilli(1_800_000_001_234) })
	c.SetSnapshot(audit.Snapshot{Collect: "hits", Revision: 1, Subjects: map[string]protocol.SubjectKey{"e": "usr_7"}, Rules: map[string]protocol.RuleAction{"p1": protocol.RuleBlock}})
	for _, dest := range []string{"z.example", "a.example", "m.example"} {
		c.AddHit(1, "e", dest+":443", "psp-deny-p1")
	}
	builder := auditReportBuilder()
	baseline, err := builder.Build(t.Context(), true, BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	withOne := baseline.Report
	withOne.Audit = reportAuditFixture()
	builder.maxBodyBytes = wireSize(t, withOne)
	built, err := builder.Build(t.Context(), true, BuildOptions{Audit: c})
	if err != nil || built.Report.Audit == nil || len(built.Report.Audit.Hits) != 1 || built.Report.Audit.Hits[0].Dest != "a.example" || built.AuditHitsTrimmed != 2 || wireSize(t, built.Report) > builder.maxBodyBytes {
		t.Fatalf("new batch did not fit: %+v %v", built, err)
	}
	if !c.Acknowledge(built.AuditKind, built.AuditBatchIDSent) {
		t.Fatal("sent batch absent")
	}
	rest, err := c.Next(protocol.MaxAuditObservationBytes)
	if err != nil || rest.Observation == nil || len(rest.Observation.Hits) != 2 || rest.Observation.Dropped != 0 {
		t.Fatalf("trim became loss: %+v %v", rest, err)
	}
}

func TestSyncAcknowledgesOnlySentBatchAfterValidResponse(t *testing.T) {
	for _, name := range []string{"valid", "transport failure", "invalid response", "processor failure", "outbox failure", "deferred"} {
		t.Run(name, func(t *testing.T) {
			source := &auditReportSource{batch: audit.Batch{Observation: reportAuditFixture(), Frozen: true}}
			builder := auditReportBuilder()
			store := builder.Store.(*auditReportStore)
			if name == "outbox failure" {
				store.ackError = errors.New("outbox failed")
			}
			if name == "deferred" {
				baseline, err := builder.Build(t.Context(), true, BuildOptions{})
				if err != nil {
					t.Fatal(err)
				}
				builder.maxBodyBytes = wireSize(t, baseline.Report)
			}
			s := Synchronizer{Reports: builder, Store: store, Audit: source,
				Syncer: syncerFunc(func(_ context.Context, report protocol.NodeReport) (protocol.SyncResponse, error) {
					if (report.Audit == nil) != (name == "deferred") {
						t.Fatalf("wrong audit on wire: %+v", report.Audit)
					}
					if name == "transport failure" {
						return protocol.SyncResponse{}, errors.New("offline")
					}
					if name == "invalid response" {
						return protocol.SyncResponse{Envelope: protocol.Envelope{NextPollSeconds: -1}}, nil
					}
					return protocol.SyncResponse{}, nil
				}), Processor: processorFunc(func(context.Context, protocol.SyncResponse) (ProcessResult, error) {
					if name == "processor failure" {
						return ProcessResult{}, errors.New("core failed")
					}
					return ProcessResult{}, nil
				})}
			_, err := s.SyncOnce(t.Context(), true, false)
			wantErr := name != "valid" && name != "deferred"
			wantAck := name == "valid" || name == "processor failure" || name == "outbox failure"
			if (err != nil) != wantErr || (len(source.ack) == 1) != wantAck {
				t.Fatalf("ack=%v err=%v", source.ack, err)
			}
			if wantAck && source.ack[0] != "block/"+source.batch.Observation.BatchID {
				t.Fatalf("wrong kind/ID acknowledged: %v", source.ack)
			}
		})
	}
}

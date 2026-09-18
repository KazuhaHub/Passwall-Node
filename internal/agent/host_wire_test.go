package agent

import (
	"encoding/json"
	"testing"

	"github.com/KazuhaHub/passwall-node/protocol"
)

func wireSize(t *testing.T, report protocol.NodeReport) int64 {
	t.Helper()
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return int64(len(body))
}

// TELEMETRY IS THE FIRST THING TO GO, and this is the property that keeps it
// harmless. It is the only content in a report that is regenerated every
// interval, so losing it costs a visible gap; letting it hold back a roster or a
// quota decision would make an observation the panel can live without into
// something that delays the data plane.
func TestFitReportToWireDropsTelemetryFirst(t *testing.T) {
	withHost := protocol.NodeReport{
		AgentID: "agent-1", Host: &protocol.HostObservation{SampleID: "0123456789abcdef0123456789abcdef"},
	}
	withoutHost := withHost
	withoutHost.Host = nil
	// A limit that fits the control content exactly and not one byte more.
	limit := wireSize(t, withoutHost)

	candidate := withHost
	dropped, err := fitReportToWire(&candidate, false, limit)
	if err != nil {
		t.Fatalf("the sample should have been dropped instead of failing: %v", err)
	}
	if !dropped {
		t.Fatal("a report over the limit kept its telemetry")
	}
	if candidate.Host != nil {
		t.Fatal("the sample was reported as dropped but is still attached")
	}
	// The control content survives: agent id, protocol version, capabilities.
	if candidate.AgentID != "agent-1" {
		t.Fatalf("the control content was lost with the telemetry: %#v", candidate)
	}
}

func TestFitReportToWireKeepsTelemetryWhenItFits(t *testing.T) {
	report := protocol.NodeReport{
		AgentID: "agent-1", Host: &protocol.HostObservation{SampleID: "0123456789abcdef0123456789abcdef"},
	}
	limit := wireSize(t, report)
	dropped, err := fitReportToWire(&report, false, limit)
	if err != nil {
		t.Fatal(err)
	}
	if dropped {
		t.Fatal("a report that fits lost its telemetry")
	}
	if report.Host == nil {
		t.Fatal("the sample was removed from a report that fits")
	}
}

// Only once the telemetry is gone does the durable outbox get flushed. A
// terminal result must not become trapped behind a large enumeration, but it
// must not be the first casualty of a report that is large for another reason.
func TestFitReportToWireFlushesTheOutboxOnlyAfterDroppingTelemetry(t *testing.T) {
	report := protocol.NodeReport{
		AgentID: "agent-1",
		Host:    &protocol.HostObservation{SampleID: "0123456789abcdef0123456789abcdef"},
		Objects: make([]protocol.ObjectStatus, 200),
	}
	full := wireSize(t, report)
	// A limit that fits only the partial, telemetry-free shape.
	partial := report
	partial.Host = nil
	partial.Partial = true
	partial.Objects = nil
	limit := wireSize(t, partial)
	if limit >= full {
		t.Fatalf("the fixture does not exceed the limit: partial=%d full=%d", limit, full)
	}

	dropped, err := fitReportToWire(&report, true, limit)
	if err != nil {
		t.Fatal(err)
	}
	if !dropped {
		t.Fatal("the telemetry was not dropped before the outbox flush")
	}
	if !report.Partial || report.Objects != nil {
		t.Fatal("the outbox flush did not happen after the telemetry was dropped")
	}
	if report.Host != nil {
		t.Fatal("the telemetry survived the flush")
	}
}

// A report with no telemetry at all still degrades by flushing the outbox; the
// new step must not have changed that path.
func TestFitReportToWireStillFlushesWithoutTelemetry(t *testing.T) {
	report := protocol.NodeReport{AgentID: "agent-1", Objects: make([]protocol.ObjectStatus, 200)}
	partial := report
	partial.Partial = true
	partial.Objects = nil
	limit := wireSize(t, partial)

	dropped, err := fitReportToWire(&report, true, limit)
	if err != nil {
		t.Fatal(err)
	}
	if dropped {
		t.Fatal("a report with no telemetry reported a sample as dropped")
	}
	if !report.Partial {
		t.Fatal("the outbox flush did not happen")
	}
}

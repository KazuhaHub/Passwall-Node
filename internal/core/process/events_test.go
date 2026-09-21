package process

import (
	"testing"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

type recordingSink struct{ events []protocol.DiagnosticsEvent }

func (s *recordingSink) Record(code string, severity protocol.DiagnosticsSeverity, summary string) {
	s.events = append(s.events, protocol.DiagnosticsEvent{Code: code, Severity: severity, Summary: summary})
}

// A TRANSITION INTO RUNNING AFTER A RESTART IS A RESTART, not a start. The
// counter is what separates them, and the two read very differently to someone
// working out why a core keeps coming back.
func TestSupervisorRecordsLifecycleTransitions(t *testing.T) {
	first := &recordingSink{}
	(&Supervisor{options: Options{Events: first}}).recordStateChange(agentcore.ProcessStarting, agentcore.ProcessRunning, 0)
	if len(first.events) != 1 || first.events[0].Code != protocol.DiagnosticsEventCoreStarted {
		t.Fatalf("a first start recorded %+v, want core.started", first.events)
	}

	restarted := &recordingSink{}
	(&Supervisor{options: Options{Events: restarted}}).recordStateChange(agentcore.ProcessRunning, agentcore.ProcessRunning, 3)
	if len(restarted.events) != 0 {
		t.Fatalf("a same-state update recorded %+v, want nothing", restarted.events)
	}
	(&Supervisor{options: Options{Events: restarted}}).recordStateChange(agentcore.ProcessDegraded, agentcore.ProcessRunning, 3)
	if len(restarted.events) != 1 || restarted.events[0].Code != protocol.DiagnosticsEventCoreRestarted {
		t.Fatalf("a restart recorded %+v, want core.restarted", restarted.events)
	}

	stopped := &recordingSink{}
	(&Supervisor{options: Options{Events: stopped}}).recordStateChange(agentcore.ProcessRunning, agentcore.ProcessStopped, 0)
	if len(stopped.events) != 1 || stopped.events[0].Code != protocol.DiagnosticsEventCoreStopped {
		t.Fatalf("a stop recorded %+v, want core.stopped", stopped.events)
	}
}

// A supervisor built without a recorder does not panic on a transition: a build
// without a diagnostic is still a working node.
func TestSupervisorWithoutARecorderTransitionsQuietly(t *testing.T) {
	(&Supervisor{}).recordStateChange(agentcore.ProcessStarting, agentcore.ProcessRunning, 0)
}

package agent

import (
	"errors"
	"sync"
)

// ReadinessGate evaluates a readiness check on demand and tells its owner about
// the first result and every change after that.
//
// IT EXISTS BECAUSE READINESS OUTSIDE THE PROCESS IS A CURRENT FACT, NOT A
// STARTUP ONE. The remote-upgrade helper is a separate systemd unit or a
// separate container. After a host reboot Docker restarts both containers with
// no ordering between them, and an operator may enable or repair the helper
// long after the agent started. A check taken once at startup is then wrong for
// the rest of the process lifetime, and wrong silently: the capability is just
// absent, and nothing says why. So the check runs every time someone needs the
// answer — once per report, and again before a task executes — and the gate
// remembers only what it last reported.
//
// REPORTING ONLY CHANGES is what keeps that affordable to read. The check runs
// every sync round; a line per round would bury the one line that matters. The
// first result is always reported, so the log states the initial condition, and
// after that a line appears when readiness flips or when the reason it is not
// ready changes — a different reason is new information for someone halfway
// through fixing the helper. The checks this is built for return fixed
// messages, so a steady condition never produces a second line.
//
// EVALUATIONS ARE SERIALIZED, the check included. The report builder and the
// task worker call Check from different goroutines, and letting two checks
// overlap would let an older result be recorded after a newer one and report a
// transition that did not happen. The checks are a handful of lstat and read
// calls, so holding the lock across one costs nothing measurable. onChange runs
// under the same lock, which keeps reported lines in evaluation order; it must
// therefore not call back into the gate.
type ReadinessGate struct {
	check    func() error
	onChange func(error)

	mu       sync.Mutex
	observed bool
	ready    bool
	reason   string
}

// errReadinessUnconfigured is what a gate with no check reports. FAILING CLOSED
// is deliberate: a missing check is a wiring mistake, and treating it as ready
// would advertise work the node cannot do.
var errReadinessUnconfigured = errors.New("readiness check is not configured")

// NewReadinessGate returns a gate over check. onChange may be nil, in which case
// the gate still evaluates but reports nothing.
func NewReadinessGate(check func() error, onChange func(error)) *ReadinessGate {
	return &ReadinessGate{check: check, onChange: onChange}
}

// Check runs the readiness check now and returns its result unchanged. It is
// safe for concurrent use.
func (g *ReadinessGate) Check() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	err := errReadinessUnconfigured
	if g.check != nil {
		err = g.check()
	}
	ready, reason := err == nil, ""
	if err != nil {
		reason = err.Error()
	}
	if g.observed && ready == g.ready && reason == g.reason {
		return err
	}
	g.observed, g.ready, g.reason = true, ready, reason
	if g.onChange != nil {
		g.onChange(err)
	}
	return err
}

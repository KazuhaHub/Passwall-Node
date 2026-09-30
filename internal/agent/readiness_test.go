package agent

import (
	"errors"
	"slices"
	"sync"
	"testing"
)

// scriptedCheck returns the queued results in order and then repeats the last.
type scriptedCheck struct {
	mu      sync.Mutex
	results []error
}

func (s *scriptedCheck) check() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := s.results[0]
	if len(s.results) > 1 {
		s.results = s.results[1:]
	}
	return result
}

type recordedChanges struct {
	mu      sync.Mutex
	changes []string
}

func (r *recordedChanges) record(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err == nil {
		r.changes = append(r.changes, "ready")
		return
	}
	r.changes = append(r.changes, "unavailable: "+err.Error())
}

func (r *recordedChanges) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.changes...)
}

// The gate is evaluated once per report. Reporting every evaluation would be a
// log line per sync round; reporting only the first result and each change is
// what tells an operator when the helper appeared or went away.
func TestReadinessGateReportsTheFirstResultAndEveryChangeOnly(t *testing.T) {
	stale := errors.New("heartbeat is stale")
	script := &scriptedCheck{results: []error{stale, stale, nil, nil, nil, stale, stale}}
	var recorded recordedChanges
	gate := NewReadinessGate(script.check, recorded.record)

	var results []error
	for range 7 {
		results = append(results, gate.Check())
	}
	for index, want := range []error{stale, stale, nil, nil, nil, stale, stale} {
		if results[index] != want {
			t.Fatalf("Check %d = %v, want %v", index, results[index], want)
		}
	}
	want := []string{"unavailable: heartbeat is stale", "ready", "unavailable: heartbeat is stale"}
	if got := recorded.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("reported changes = %q, want %q", got, want)
	}
}

// A first evaluation that succeeds is reported too: "remote upgrade is ready"
// is the line an operator looks for after fixing the helper.
func TestReadinessGateReportsAReadyFirstEvaluation(t *testing.T) {
	var recorded recordedChanges
	gate := NewReadinessGate(func() error { return nil }, recorded.record)
	for range 3 {
		if err := gate.Check(); err != nil {
			t.Fatal(err)
		}
	}
	if got := recorded.snapshot(); !slices.Equal(got, []string{"ready"}) {
		t.Fatalf("reported changes = %q, want [ready]", got)
	}
}

// A different reason while still unavailable is a change worth one line: the
// operator fixed the ownership and the marker is now what is wrong. The reasons
// are fixed strings, so this cannot turn into a line per report.
func TestReadinessGateReportsAChangedReasonWhileUnavailable(t *testing.T) {
	ownership := errors.New("ownership is invalid")
	marker := errors.New("marker is invalid")
	script := &scriptedCheck{results: []error{ownership, ownership, marker, marker}}
	var recorded recordedChanges
	gate := NewReadinessGate(script.check, recorded.record)
	for range 4 {
		_ = gate.Check()
	}
	want := []string{"unavailable: ownership is invalid", "unavailable: marker is invalid"}
	if got := recorded.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("reported changes = %q, want %q", got, want)
	}
}

// A gate built without a check fails closed. A missing check is a wiring
// mistake, and "always ready" would advertise work the node cannot do.
func TestReadinessGateWithoutACheckIsNeverReady(t *testing.T) {
	var recorded recordedChanges
	gate := NewReadinessGate(nil, recorded.record)
	if err := gate.Check(); err == nil {
		t.Fatal("a gate without a check reported ready")
	}
	if got := recorded.snapshot(); len(got) != 1 || got[0] == "ready" {
		t.Fatalf("reported changes = %q", got)
	}
	if err := NewReadinessGate(func() error { return nil }, nil).Check(); err != nil {
		t.Fatalf("a gate without a change callback failed: %v", err)
	}
}

// The report builder and the task worker evaluate the same gate from different
// goroutines. Evaluations are serialized, so the reported sequence is always a
// valid alternation — never two "ready" lines in a row from interleaved checks.
func TestReadinessGateSerializesConcurrentChecks(t *testing.T) {
	var mu sync.Mutex
	flip := false
	check := func() error {
		mu.Lock()
		defer mu.Unlock()
		flip = !flip
		if flip {
			return nil
		}
		return errors.New("not ready")
	}
	var recorded recordedChanges
	gate := NewReadinessGate(check, recorded.record)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				_ = gate.Check()
			}
		}()
	}
	wg.Wait()
	changes := recorded.snapshot()
	if len(changes) != 400 {
		t.Fatalf("every evaluation alternates, so every one is a change: got %d reports", len(changes))
	}
	for index := 1; index < len(changes); index++ {
		if changes[index] == changes[index-1] {
			t.Fatalf("reports %d and %d repeat %q; evaluations interleaved", index-1, index, changes[index])
		}
	}
}

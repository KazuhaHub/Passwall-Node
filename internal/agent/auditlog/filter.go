package auditlog

import (
	"context"
	"errors"
	"io"
	"math"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

var ErrFilterFailed = errors.New("access log filter stopped unexpectedly")

type Sink interface {
	AddUsageAt(uint64, string, string, time.Time)
	AddLossAt(string, uint64, uint64, uint64, time.Time)
}

type collection struct {
	revision uint64
	enabled  bool
	// Packed receive-hour/count slots keep overflow accounting nonblocking.
	// A collision is at least 74 hours apart, beyond the 48-hour replay limit.
	loss      [74]atomic.Uint64
	unmatched [74]atomic.Uint64
}

type accessEvent struct {
	collection *collection
	at         time.Time
	line       string
	truncated  bool
}

type Stats struct{ Processed, StaleRevision, ForwardDropped uint64 }

type Filter struct {
	sink    Sink
	stdout  io.Writer
	now     func() time.Time
	input   chan accessEvent
	output  chan []byte
	active  atomic.Pointer[collection]
	started atomic.Bool
	stopped atomic.Bool
	failed  atomic.Bool
	fatal   chan error
	done    chan struct{}

	processed, stale, forwardDropped                                        atomic.Uint64
	privateLines, usageEvents, deniedEvents, unmatchedEvents, droppedEvents atomic.Uint64
}

func New(sink Sink, stdout io.Writer, now func() time.Time) (*Filter, error) {
	if sink == nil || stdout == nil {
		return nil, errors.New("access log collector and output are required")
	}
	if now == nil {
		now = time.Now
	}
	f := &Filter{sink: sink, stdout: stdout, now: now, input: make(chan accessEvent, 4096), output: make(chan []byte, 4096), fatal: make(chan error, 1), done: make(chan struct{})}
	f.active.Store(&collection{})
	return f, nil
}

// SetCollection follows the confirmed deployed snapshot, never a desired
// candidate or writer creation. Previously queued data keeps its own revision.
func (f *Filter) SetCollection(revision uint64, enabled bool) {
	enabled = enabled && revision > 0
	for {
		old := f.active.Load()
		if old.revision == revision && old.enabled == enabled {
			return
		}
		if f.active.CompareAndSwap(old, &collection{revision: revision, enabled: enabled}) {
			return
		}
	}
}

func (f *Filter) Stats() Stats {
	return Stats{f.processed.Load(), f.stale.Load(), f.forwardDropped.Load()}
}

// Writer is owned by one actual process deployment. Closing it flushes its
// bounded partial line without closing the agent's shared stdout.
func (f *Filter) Writer(revision uint64) io.WriteCloser {
	return &deploymentWriter{filter: f, revision: revision, line: make([]byte, 0, maxLineBytes)}
}

type deploymentWriter struct {
	mu        sync.Mutex
	filter    *Filter
	revision  uint64
	line      []byte
	truncated bool
	closed    bool
}

func (w *deploymentWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	if w.filter.stopped.Load() || w.filter.failed.Load() {
		return len(p), nil
	}
	for _, b := range p {
		if b == '\n' {
			w.emit(true)
			w.line = w.line[:0]
			w.truncated = false
		} else if len(w.line) < maxLineBytes {
			w.line = append(w.line, b)
		} else {
			// Discard through the newline, never forward the private line's tail.
			w.truncated = true
		}
	}
	return len(p), nil
}

func (w *deploymentWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.closed && len(w.line) > 0 {
		w.emit(false)
	}
	w.closed = true
	w.line = nil
	return nil
}

// Include partial or malformed access headers at EOF. Ordinary Xray messages
// have a severity prefix instead of "from" and retain their forwarding path.
var privatePrefix = regexp.MustCompile(`^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d\.\d{6} from(?: |$)`)

func (w *deploymentWriter) emit(newline bool) {
	f := w.filter
	if f.stopped.Load() || f.failed.Load() {
		return
	}
	line := strings.TrimSuffix(string(w.line), "\r")
	if privatePrefix.MatchString(line) {
		f.privateLines.Add(1)
		epoch := f.active.Load()
		if !epoch.enabled || epoch.revision != w.revision {
			f.stale.Add(1)
			return
		}
		event := accessEvent{collection: epoch, at: f.now().UTC(), line: line, truncated: w.truncated}
		select {
		case f.input <- event:
		default:
			// A denied connection is never a missing usage event. Classify
			// only on overflow so the ordinary writer keeps its short path.
			parsed := parseLine(line)
			switch {
			case !event.truncated && parsed.kind == lineIgnored:
				f.deniedEvents.Add(1)
			case event.truncated || parsed.kind != lineUsage:
				epoch.drop(event.at, true)
				f.unmatchedEvents.Add(1)
			default:
				epoch.drop(event.at, false)
				f.droppedEvents.Add(1)
			}
		}
		return
	}
	copy := append([]byte(nil), w.line...)
	if newline {
		copy = append(copy, '\n')
	}
	select {
	case f.output <- copy:
	default:
		f.forwardDropped.Add(1)
	}
}

func (c *collection) drop(at time.Time, unmatched bool) {
	hour := at.UnixMilli() / protocol.AuditHourMS
	if hour <= 0 || hour > math.MaxUint32 {
		return
	}
	slots := &c.loss
	if unmatched {
		slots = &c.unmatched
	}
	slot := &slots[hour%int64(len(slots))]
	for {
		old := slot.Load()
		previous, count := old>>32, old&math.MaxUint32
		if previous > uint64(hour) {
			return
		}
		if previous != uint64(hour) {
			count = 0
		}
		if count < math.MaxUint32 {
			count++
		}
		if slot.CompareAndSwap(old, uint64(hour)<<32|count) {
			return
		}
	}
}

func (f *Filter) flushLosses() {
	epoch := f.active.Load()
	for group, slots := range []*[74]atomic.Uint64{&epoch.loss, &epoch.unmatched} {
		for i := range slots {
			slot := &slots[i]
			word := slot.Load()
			count := word & math.MaxUint32
			if count == 0 || !slot.CompareAndSwap(word, word&^uint64(math.MaxUint32)) {
				continue
			}
			dropped, unmatched := count, uint64(0)
			if group == 1 {
				dropped, unmatched = 0, count
			}
			f.sink.AddLossAt("usage", epoch.revision, dropped, unmatched, time.UnixMilli(int64(word>>32)*protocol.AuditHourMS))
		}
	}
}

func (f *Filter) consume(event accessEvent) {
	defer f.processed.Add(1)
	current := f.active.Load()
	if !current.enabled || current.revision != event.collection.revision {
		f.stale.Add(1)
		return
	}
	parsed := parseLine(event.line)
	if event.truncated || parsed.kind == lineOrdinary || parsed.kind == lineUnmatched {
		f.sink.AddLossAt("usage", event.collection.revision, 0, 1, event.at)
		f.unmatchedEvents.Add(1)
	} else if parsed.kind == lineUsage {
		f.sink.AddUsageAt(event.collection.revision, parsed.email, parsed.destination, event.at)
		f.usageEvents.Add(1)
	} else if parsed.kind == lineIgnored {
		f.deniedEvents.Add(1)
	}
}

func (f *Filter) fail() {
	f.failed.Store(true)
	select {
	case f.fatal <- ErrFilterFailed:
	default:
	}
}

// Run is a lifecycle service. Failure returns a fixed error and leaves all
// private lines suppressed until the daemon exits. External stdout may block
// its independent forwarding worker; neither core Write nor parsing waits on it.
func (f *Filter) Run(ctx context.Context) (err error) {
	if f.started.Swap(true) {
		return errors.New("access log filter already started")
	}
	defer func() {
		if recover() != nil {
			f.failed.Store(true)
			err = ErrFilterFailed
		}
		f.stopped.Store(true)
		close(f.done)
	}()
	go f.forward(ctx)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-f.fatal:
			return err
		case event := <-f.input:
			f.consume(event)
		case <-ticker.C:
			f.flushLosses()
		}
	}
}

func (f *Filter) forward(ctx context.Context) {
	defer func() {
		if recover() != nil {
			f.fail()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-f.done:
			return
		case line := <-f.output:
			if n, err := f.stdout.Write(line); err != nil || n != len(line) {
				f.fail()
				return
			}
		}
	}
}

package auditlog

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/agent/audit"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

const privateHeader = "2026/10/10 11:00:01.123456 from 192.0.2.44:1234 "

type lockedOutput struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *lockedOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}
func (w *lockedOutput) text() string { w.mu.Lock(); defer w.mu.Unlock(); return w.b.String() }

func await(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatal("filter did not reach the expected state")
		}
		time.Sleep(time.Millisecond)
	}
}

func startFilter(t *testing.T, f *Filter) <-chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- f.Run(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("filter failed to stop")
		}
	})
	return done
}

func TestFilterFragmentsPrivateLinesAndUsesReceiveHourWithRealCollector(t *testing.T) {
	var clock atomic.Int64
	hour := time.Now().UTC().Truncate(time.Hour).UnixMilli()
	clock.Store(hour + 1000)
	now := func() time.Time { return time.UnixMilli(clock.Load()) }
	c := audit.New(now)
	c.SetSnapshot(audit.Snapshot{Collect: "hits_and_usage", Revision: 7, Subjects: map[string]protocol.SubjectKey{"user@example.invalid": "usr_7"}})
	out := &lockedOutput{}
	f, err := New(c, out, now)
	if err != nil {
		t.Fatal(err)
	}
	f.SetCollection(7, true)
	w := f.Writer(7)
	lines := "ordinary warning\n"
	for _, tag := range []string{"direct", "psp-watch-p9", "psp-watch-g9", "psp-deny-p9"} {
		lines += privateHeader + "accepted tcp:www.example.com:443 [vless -> " + tag + "] email: user@example.invalid\r\n"
	}
	lines += privateHeader + "accepted tcp:[2001:db8::1]:443 [vless >> direct] email: user@example.invalid\n"
	lines += privateHeader + "rejected tcp:example.com:443 email: user@example.invalid\n"
	lines += privateHeader + "accepted tcp:example.com:443\n"
	lines += privateHeader + "accepted " + strings.Repeat("private-credential", 1000) + "\nordinary after oversized\n"
	for _, b := range []byte(lines) {
		if n, err := w.Write([]byte{b}); err != nil || n != 1 {
			t.Fatal("fragmented writer did not accept its input")
		}
	}
	// A final partial private header must not become ordinary output at EOF.
	_, _ = io.WriteString(w, privateHeader+"accepted")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	clock.Store(hour + protocol.AuditHourMS + 1000)
	startFilter(t, f)
	await(t, func() bool {
		return f.Stats().Processed == 9 && strings.Contains(out.text(), "ordinary after oversized\n")
	})
	if out.text() != "ordinary warning\nordinary after oversized\n" {
		t.Fatal("private line or overlong tail escaped to stdout")
	}
	batch, err := c.Next(protocol.MaxAuditObservationBytes)
	if err != nil || batch.Observation == nil {
		t.Fatal("missing usage collection")
	}
	o := batch.Observation
	if o.Kind != "usage" || o.Hour != hour || o.CollectRevision != 7 || len(o.Hits) != 0 || len(o.Usage) != 2 || o.Unmatched != 4 {
		t.Fatalf("receive-hour usage contract changed: %+v", o)
	}
	sites := map[string]uint32{}
	for _, row := range o.Usage {
		sites[row.Site] = row.Count
	}
	if sites["example.com"] != 3 || sites["(ip)"] != 1 || protocol.ValidateAuditObservation(*o) != nil {
		t.Fatal("watch/trial/direct counting or address normalization changed")
	}
}

type probeSink struct {
	usage atomic.Uint64
	loss  atomic.Uint64
	hour  atomic.Int64
	panic bool
}

func (s *probeSink) AddUsageAt(_ uint64, _, _ string, _ time.Time) {
	if s.panic {
		panic("private-parser-credential")
	}
	s.usage.Add(1)
}
func (s *probeSink) AddLossAt(_ string, _ uint64, dropped, unmatched uint64, at time.Time) {
	s.hour.Store(at.UTC().Truncate(time.Hour).UnixMilli())
	s.loss.Add(dropped + unmatched)
}

func TestFilterQueueOverflowIsBoundedNonblockingAndKeepsOriginalLossHour(t *testing.T) {
	hour := time.Now().UTC().Truncate(time.Hour)
	var clock atomic.Int64
	clock.Store(hour.UnixMilli())
	sink := &probeSink{}
	f, err := New(sink, io.Discard, func() time.Time { return time.UnixMilli(clock.Load()) })
	if err != nil {
		t.Fatal(err)
	}
	if cap(f.input) != 4096 || cap(f.output) != 4096 {
		t.Fatal("filter queues changed their hard bound")
	}
	f.input = make(chan accessEvent, 1)
	f.SetCollection(1, true)
	w := f.Writer(1)
	line := privateHeader + "accepted tcp:example.com:443 email: user@example.invalid\n"
	returned := make(chan struct{})
	go func() {
		for range 101 {
			_, _ = io.WriteString(w, line)
		}
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("full parse queue blocked the core stdout writer")
	}
	clock.Store(hour.Add(time.Hour).UnixMilli())
	startFilter(t, f)
	await(t, func() bool { return sink.usage.Load() == 1 && sink.loss.Load() == 100 })
	if sink.hour.Load() != hour.UnixMilli() {
		t.Fatal("overflow loss moved into the parser's later hour")
	}
}

func TestFilterOldWriterAndQueuedRevisionCannotEnterNewCollection(t *testing.T) {
	sink := &probeSink{}
	f, _ := New(sink, io.Discard, time.Now)
	f.SetCollection(1, true)
	old := f.Writer(1)
	line := privateHeader + "accepted tcp:example.com:443 email: user@example.invalid\n"
	_, _ = io.WriteString(old, line)
	f.SetCollection(2, true)
	_, _ = io.WriteString(old, line)
	_, _ = io.WriteString(f.Writer(2), line)
	startFilter(t, f)
	await(t, func() bool { return sink.usage.Load() == 1 && f.Stats().StaleRevision == 2 })
	if sink.loss.Load() != 0 {
		t.Fatal("stale process data became current usage loss")
	}
}

type blockedOutput struct{ entered, release chan struct{} }

func (w *blockedOutput) Write(p []byte) (int, error) {
	select {
	case <-w.entered:
	default:
		close(w.entered)
	}
	<-w.release
	return len(p), nil
}

func TestBlockedForwardingDoesNotBlockUsageOrCoreWrites(t *testing.T) {
	sink := &probeSink{}
	out := &blockedOutput{make(chan struct{}), make(chan struct{})}
	f, _ := New(sink, out, time.Now)
	f.output = make(chan []byte, 1)
	f.SetCollection(1, true)
	startFilter(t, f)
	t.Cleanup(func() { close(out.release) })
	w := f.Writer(1)
	_, _ = io.WriteString(w, "ordinary\n")
	select {
	case <-out.entered:
	case <-time.After(time.Second):
		t.Fatal("forwarding did not start")
	}
	returned := make(chan struct{})
	go func() {
		_, _ = io.WriteString(w, strings.Repeat("ordinary\n", 100))
		_, _ = io.WriteString(w, privateHeader+"accepted tcp:example.com:443 email: user@example.invalid\n")
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("blocked agent stdout blocked the core writer")
	}
	await(t, func() bool { return sink.usage.Load() == 1 })
	if f.Stats().ForwardDropped == 0 {
		t.Fatal("forward queue did not retain its bound")
	}
}

func TestParserFailureExitsWithoutLeakingPanicOrAccessLines(t *testing.T) {
	out := &lockedOutput{}
	f, _ := New(&probeSink{panic: true}, out, time.Now)
	f.SetCollection(1, true)
	w := f.Writer(1)
	done := startFilter(t, f)
	line := privateHeader + "accepted tcp:example.com:443 email: user@example.invalid\n"
	_, _ = io.WriteString(w, line)
	select {
	case err := <-done:
		if !errors.Is(err, ErrFilterFailed) || strings.Contains(err.Error(), "private") {
			t.Fatal("parser failure was hidden or leaked its panic detail")
		}
	case <-time.After(time.Second):
		t.Fatal("parser failure did not exit lifecycle service")
	}
	_, _ = io.WriteString(w, line)
	_ = w.Close()
	if out.text() != "" {
		t.Fatal("failed filter forwarded private access lines")
	}
}

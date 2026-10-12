package auditlog

import (
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type categorizedProbe struct {
	usage, dropped, unmatched atomic.Uint64
	hour                      atomic.Int64
}

func (s *categorizedProbe) AddUsageAt(_ uint64, _, _ string, _ time.Time) { s.usage.Add(1) }
func (s *categorizedProbe) AddLossAt(_ string, _ uint64, dropped, unmatched uint64, at time.Time) {
	s.dropped.Add(dropped)
	s.unmatched.Add(unmatched)
	s.hour.Store(at.UTC().Truncate(time.Hour).UnixMilli())
}

func TestFilterOverflowKeepsDenialsOutOfUsageLosses(t *testing.T) {
	hour := time.Now().UTC().Truncate(time.Hour)
	var clock atomic.Int64
	clock.Store(hour.UnixMilli())
	sink := &categorizedProbe{}
	f, err := New(sink, io.Discard, func() time.Time { return time.UnixMilli(clock.Load()) })
	if err != nil {
		t.Fatal("cannot create filter fixture")
	}
	f.input = make(chan accessEvent, 1)
	f.SetCollection(7, true)
	w := f.Writer(7)
	accepted := privateHeader + "accepted tcp:private-usage.test:443 [vless -> direct] email: private-user@example.invalid\n"
	denied := privateHeader + "accepted tcp:private-denied.test:443 [vless -> psp-deny-p9] email: private-user@example.invalid\n"
	_, _ = io.WriteString(w, accepted)
	for range 100 {
		_, _ = io.WriteString(w, denied)
	}
	for range 3 {
		_, _ = io.WriteString(w, privateHeader+"accepted private-malformed\n")
	}
	for range 2 {
		_, _ = io.WriteString(w, accepted)
	}
	before := f.Pressure()
	if before.PrivateLines != 106 || before.UsageEvents != 0 || before.DeniedEvents != 100 || before.UnmatchedEvents != 3 || before.DroppedEvents != 2 || before.PendingDropped != 2 || before.PendingUnmatched != 3 || before.ParseQueued != 1 || before.ParseLimit != 1 || !reflect.DeepEqual(before, f.Pressure()) || len(f.input) != 1 {
		t.Fatal("overflow misclassified denials or numeric view mutated pending state")
	}
	data, err := json.Marshal(before)
	if err != nil || strings.Contains(string(data), "private-") || strings.Contains(string(data), "email") {
		t.Fatal("numeric filter view exposed private input")
	}
	clock.Store(hour.Add(time.Hour).UnixMilli())
	startFilter(t, f)
	await(t, func() bool {
		p := f.Pressure()
		return sink.usage.Load() == 1 && sink.dropped.Load() == 2 && sink.unmatched.Load() == 3 && p.PendingDropped == 0 && p.PendingUnmatched == 0 && p.ParseQueued == 0 && p.UsageEvents == 1
	})
	p := f.Pressure()
	if p.PrivateLines != p.UsageEvents+p.DeniedEvents+p.UnmatchedEvents+p.DroppedEvents+p.StaleEvents || sink.hour.Load() != hour.UnixMilli() {
		t.Fatal("quiescent ingress accounting lost a category or receive hour")
	}
}

func TestFilterPressureReconcilesStaleWritersAndQueuedRevisionWithoutPrivateRows(t *testing.T) {
	f, _ := New(&categorizedProbe{}, io.Discard, time.Now)
	f.SetCollection(1, true)
	old := f.Writer(1)
	line := privateHeader + "accepted tcp:private-target.test:443 email: private-user@example.invalid\n"
	_, _ = io.WriteString(old, line)
	f.SetCollection(2, true)
	_, _ = io.WriteString(old, line)
	_, _ = io.WriteString(f.Writer(2), line)
	startFilter(t, f)
	await(t, func() bool { p := f.Pressure(); return p.StaleEvents == 2 && p.UsageEvents == 1 && p.ParseQueued == 0 })
	p := f.Pressure()
	if p.Available != 1 || p.PrivateLines != 3 || p.PrivateLines != p.UsageEvents+p.StaleEvents || p.PendingDropped != 0 || p.PendingUnmatched != 0 {
		t.Fatal("stale collection crossed the numeric ingress boundary")
	}
}

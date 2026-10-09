package audit

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

const testHour = int64(1_800_000_000_000)

func testCollector() (*Collector, *int64) {
	now := testHour + 1234
	c := New(func() time.Time { return time.UnixMilli(now) })
	c.SetSnapshot(Snapshot{Collect: "hits_and_usage", Revision: 1,
		Subjects: map[string]protocol.SubjectKey{"user@example": "usr_7", "other@example": "usr_8"},
		Rules:    map[string]protocol.RuleAction{"p1": protocol.RuleBlock, "p2": protocol.RuleObserve, "g3": protocol.RuleObserve}})
	return c, &now
}

func nextBatch(t *testing.T, c *Collector, limit int) Batch {
	t.Helper()
	b, err := c.Next(limit)
	if err != nil || b.Observation == nil {
		t.Fatalf("missing batch: %+v, %v", b, err)
	}
	if err := protocol.ValidateAuditObservation(*b.Observation); err != nil {
		t.Fatalf("invalid batch: %v", err)
	}
	return b
}

func TestHitNormalizationAndTrialCollapse(t *testing.T) {
	c, _ := testCollector()
	c.AddHit(1, "user@example", "WWW.Bücher.Example.:443", "psp-deny-p1")
	b := nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation
	if len(b.Hits) != 1 || b.Hits[0].Dest != "www.xn--bcher-kva.example" || b.Hits[0].Subject != "usr_7" || b.Hits[0].Port != 443 {
		t.Fatalf("normalized hit: %+v", b)
	}
	c.Acknowledge(b.Kind, b.BatchID)
	for _, email := range []string{"user@example", "other@example"} {
		c.AddHit(1, email, "a.example.com:443", "psp-watch-g3")
		c.AddHit(1, email, "b.example.com:8443", "psp-watch-g3")
	}
	b = nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation
	if b.Kind != "trial" || len(b.Hits) != 1 || b.Hits[0].Dest != "example.com" || b.Hits[0].Subject != "" || b.Hits[0].Port != 0 || b.Hits[0].Count != 4 {
		t.Fatalf("per-user trial escaped: %+v", b)
	}
	wire, _ := json.Marshal(b)
	if strings.Contains(string(wire), "usr_") || strings.Contains(string(wire), "a.example") || strings.Contains(string(wire), "8443") {
		t.Fatalf("trial wire: %s", wire)
	}
}

func TestKindsHaveIndependentCapacityAndPending(t *testing.T) {
	c, _ := testCollector()
	// Fill the trial class beyond its production limit before inserting block.
	for i := 0; i <= 10_000; i++ {
		c.AddHit(1, "user@example", fmt.Sprintf("s%d.example:443", i), "psp-watch-g3")
	}
	c.AddHit(1, "user@example", "blocked.example:443", "psp-deny-p1")
	b := nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation
	if b.Kind != "block" || len(b.Hits) != 1 || b.Dropped != 0 {
		t.Fatalf("trial crowded block: %+v", b)
	}
	var trial *protocol.AuditObservation
	for i := 0; i < 7; i++ {
		o := nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation
		if o.Kind == "trial" {
			trial = o
			break
		}
	}
	if trial == nil || len(trial.Hits) != protocol.MaxAuditHits || trial.Dropped != 1 {
		t.Fatalf("trial bound/loss: %+v", trial)
	}
	if !c.Acknowledge("trial", trial.BatchID) {
		t.Fatal("trial ack failed")
	}
	b = nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation
	if b.Kind != "block" {
		t.Fatalf("trial ack cleared block pending: %+v", b)
	}
}

func TestFrozenRetryCannotMergeTrimOrBeMutatedByCaller(t *testing.T) {
	c, _ := testCollector()
	c.AddHit(1, "user@example", "one.example:443", "psp-deny-p1")
	first := nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation
	want, _ := json.Marshal(first)
	c.AddHit(1, "user@example", "two.example:443", "psp-deny-p1")
	first.Hits[0].Dest = "tampered.example"
	retry := nextBatch(t, c, 1)
	got, _ := json.Marshal(retry.Observation)
	if !retry.Frozen || string(want) != string(got) {
		t.Fatalf("retry changed: %s vs %s", want, got)
	}
	if c.Acknowledge("block", "wrong-id") || c.Acknowledge("usage", retry.Observation.BatchID) {
		t.Fatal("ack cleared unsent batch")
	}
	if !c.Acknowledge("block", retry.Observation.BatchID) {
		t.Fatal("correct ack failed")
	}
	after := nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation
	if after.BatchID == retry.Observation.BatchID || len(after.Hits) != 1 || after.Hits[0].Dest != "two.example" {
		t.Fatalf("new events lost or merged: %+v", after)
	}
}

func TestSevenSlotScheduleProgressesOnFailedReports(t *testing.T) {
	c, _ := testCollector()
	c.AddHit(1, "user@example", "one.example:443", "psp-deny-p1")
	c.AddHit(1, "user@example", "one.example:443", "psp-watch-p2")
	c.AddHit(1, "user@example", "a.example.com:443", "psp-watch-g3")
	c.AddUsage(1, "user@example", "tcp:a.example.com:443")
	var got []string
	for i := 0; i < 14; i++ {
		got = append(got, nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation.Kind)
	}
	want := []string{"block", "block", "block", "block", "observe", "trial", "usage", "block", "block", "block", "block", "observe", "trial", "usage"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("failed block starved lower classes: %v", got)
	}
}

func TestLossOnlyMalformedAndStaleRevisionIsolation(t *testing.T) {
	c, _ := testCollector()
	c.AddHit(1, "missing", "one.example:443", "psp-deny-p1")
	c.AddHit(1, "user@example", "bad", "psp-deny-p1")
	c.AddHit(1, "user@example", "one.example:443", "psp-deny-p999")
	c.AddHit(1, "user@example", "one.example:443", "psp-watch-g3x1")
	c.AddHit(2, "user@example", "one.example:443", "psp-deny-p1")
	c.AddHit(1, "user@example", "one.example:443", "unclassifiable")
	b := nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation
	if b.Kind != "block" || len(b.Hits) != 0 || b.Unmatched != 3 {
		t.Fatalf("malformed/stale relabeled: %+v", b)
	}
	if c.Stats().StaleRevision != 1 || c.Stats().Unclassified != 2 {
		t.Fatalf("local error counts: %+v", c.Stats())
	}
}

func TestOldestHourExpiryAndRevisionOffNeverRelabel(t *testing.T) {
	c, now := testCollector()
	c.AddHit(1, "user@example", "old.example:443", "psp-deny-p1")
	*now += protocol.AuditHourMS
	c.AddHit(1, "user@example", "new.example:443", "psp-deny-p1")
	b := nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation
	if b.Hour != testHour {
		t.Fatalf("new hour sent first: %+v", b)
	}
	*now = testHour + protocol.MaxAuditReplayAgeMS + 1
	next := nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation
	if next.Hour != testHour+protocol.AuditHourMS || next.BatchID == b.BatchID || c.Stats().ExpiredRows != 1 {
		t.Fatalf("expired batch replayed: %+v stats=%+v", next, c.Stats())
	}
	c.SetSnapshot(Snapshot{Collect: "hits", Revision: 2, Subjects: map[string]protocol.SubjectKey{"user@example": "usr_7"}, Rules: map[string]protocol.RuleAction{"p1": protocol.RuleBlock}})
	c.AddHit(1, "user@example", "stale.example:443", "psp-deny-p1")
	if c.Acknowledge("block", next.BatchID) {
		t.Fatal("old pending survived revision")
	}
	if empty, err := c.Next(protocol.MaxAuditObservationBytes); err != nil || empty.Observation != nil {
		t.Fatalf("old data relabeled: %+v %v", empty, err)
	}
	c.AddHit(2, "user@example", "current.example:443", "psp-deny-p1")
	c.SetSnapshot(Snapshot{})
	if empty, _ := c.Next(protocol.MaxAuditObservationBytes); empty.Observation != nil || c.Stats().OffRows != 2 {
		t.Fatalf("off backlog: %+v stats=%+v", empty, c.Stats())
	}
}

func TestWireTrimReturnsRowsAndSortsBeforeFreeze(t *testing.T) {
	c, _ := testCollector()
	for _, dest := range []string{"z.example", "a.example", "m.example"} {
		c.AddHit(1, "user@example", dest+":443", "psp-deny-p1")
	}
	// Enough for exactly one row, determined from a normal frozen encoding.
	one, _ := testCollector()
	one.AddHit(1, "user@example", "a.example:443", "psp-deny-p1")
	oneWire, _ := json.Marshal(nextBatch(t, one, protocol.MaxAuditObservationBytes).Observation)
	b := nextBatch(t, c, len(oneWire))
	if b.Frozen || len(b.Observation.Hits) != 1 || b.Observation.Hits[0].Dest != "a.example" || b.HitsTrimmed != 2 || b.Observation.Dropped != 0 {
		t.Fatalf("trim discarded/misordered rows: %+v", b)
	}
	c.Acknowledge("block", b.Observation.BatchID)
	rest := nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation
	if len(rest.Hits) != 2 || rest.Hits[0].Dest != "m.example" || rest.Hits[1].Dest != "z.example" {
		t.Fatalf("trimmed rows lost: %+v", rest)
	}
}

func TestConcurrentIngressAndAcknowledgement(t *testing.T) {
	c, _ := testCollector()
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for n := 0; n < 100; n++ {
				c.AddHit(1, "user@example", "one.example:443", "psp-deny-p1")
			}
		}()
	}
	workers.Wait()
	b := nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation
	if b.Hits[0].Count != 800 {
		t.Fatalf("concurrent count lost: %+v", b)
	}
}

func TestCountSaturationAndCapacityAcrossHours(t *testing.T) {
	c, now := testCollector()
	c.lanes["block"].limit = 2
	c.AddHit(1, "user@example", "one.example:443", "psp-deny-p1")
	bucket := c.lanes["block"].buckets[testHour]
	key := hitKey{"p1", "usr_7", "one.example", 443}
	row := bucket.hits[key]
	row.Count = math.MaxUint32
	bucket.hits[key] = row
	c.AddHit(1, "user@example", "one.example:443", "psp-deny-p1")
	*now += protocol.AuditHourMS
	c.AddHit(1, "user@example", "two.example:443", "psp-deny-p1")
	c.AddHit(1, "user@example", "three.example:443", "psp-deny-p1")
	first := nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation
	if first.Hits[0].Count != math.MaxUint32 || first.Dropped != 1 {
		t.Fatalf("count wrapped: %+v", first)
	}
	c.Acknowledge(first.Kind, first.BatchID)
	second := nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation
	if len(second.Hits) != 1 || second.Dropped != 1 {
		t.Fatalf("per-hour cap multiplied capacity: %+v", second)
	}
}

func TestIPv6AndUsageNeverCarryIPOrOriginalSubdomain(t *testing.T) {
	c, _ := testCollector()
	c.AddHit(1, "user@example", "[2001:0db8::1]:443", "psp-deny-p1")
	first := nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation
	if first.Hits[0].Dest != "2001:db8::1" {
		t.Fatalf("IP canonicalization: %+v", first)
	}
	c.Acknowledge(first.Kind, first.BatchID)
	c.AddHit(1, "user@example", "[2001:db8::1]:443", "psp-watch-g3")
	trial := nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation
	if trial.Hits[0].Dest != "(ip)" {
		t.Fatalf("trial IP escaped: %+v", trial)
	}
	c.Acknowledge(trial.Kind, trial.BatchID)
	c.AddUsage(1, "user@example", "udp:[2001:db8::1]:53")
	c.AddUsage(1, "user@example", "tcp:a.example.com:443")
	usage := nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation
	if len(usage.Usage) != 2 || usage.Usage[0].Site != "(ip)" || usage.Usage[1].Site != "example.com" {
		t.Fatalf("usage destinations: %+v", usage)
	}
}

func TestSnapshotIsCopiedAndZeroLossDoesNotReserveBucket(t *testing.T) {
	c, _ := testCollector()
	s := Snapshot{Collect: "hits", Revision: 2, Subjects: map[string]protocol.SubjectKey{"user@example": "usr_7"}, Rules: map[string]protocol.RuleAction{"p1": protocol.RuleBlock}}
	c.SetSnapshot(s)
	s.Subjects["user@example"] = "usr_99"
	delete(s.Rules, "p1")
	c.AddLoss("block", 2, 0, 0)
	if len(c.lanes["block"].buckets) != 0 {
		t.Fatal("zero loss reserved a scheduler slot")
	}
	c.AddHit(2, "user@example", "one.example:443", "psp-deny-p1")
	b := nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation
	if b.Hits[0].Subject != "usr_7" {
		t.Fatal("caller changed deployed snapshot")
	}
}

func TestCounterOnlyLossExpiryKeepsOriginalHour(t *testing.T) {
	c, now := testCollector()
	c.AddLoss("observe", 1, 3, 2)
	b := nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation
	if b.Hour != testHour || b.Dropped != 3 || b.Unmatched != 2 || len(b.Hits) != 0 {
		t.Fatalf("loss-only batch: %+v", b)
	}
	*now = testHour + protocol.MaxAuditReplayAgeMS + 1
	if empty, _ := c.Next(protocol.MaxAuditObservationBytes); empty.Observation != nil {
		t.Fatalf("loss relabeled/replayed: %+v", empty)
	}
	if c.Stats().ExpiredRows != 0 || c.Stats().ExpiredEvents != 5 {
		t.Fatalf("loss expiry stats: %+v", c.Stats())
	}
}

func TestASCIIHostNormalizationRetainsProtocolAllowedUnderscores(t *testing.T) {
	c, _ := testCollector()
	c.AddHit(1, "user@example", "_Service.Example.:443", "psp-deny-p1")
	b := nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation
	if len(b.Hits) != 1 || b.Hits[0].Dest != "_service.example" || b.Unmatched != 0 {
		t.Fatalf("valid ASCII hostname rejected: %+v", b)
	}
}

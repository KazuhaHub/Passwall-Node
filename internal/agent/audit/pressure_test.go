package audit

import (
	"encoding/json"
	"github.com/KazuhaHub/passwall-protocol/protocol"
	"reflect"
	"strings"
	"testing"
)

func TestPressureReadsPendingCanonicalBytesWithoutChangingRetries(t *testing.T) {
	c, _ := testCollector()
	c.AddHit(1, "user@example", "one.private.example:443", "psp-deny-p1")
	before := c.Pressure()
	if before[0].Keys != 1 || before[0].Pending != 0 {
		t.Fatal("aggregation state missing")
	}
	batch := nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation
	wire, err := json.Marshal(batch)
	if err != nil {
		t.Fatal("encode owned frozen payload")
	}
	c.AddHit(1, "user@example", "two.private.example:443", "psp-deny-p1")
	first := c.Pressure()
	if first[0].Keys != 1 || first[0].Pending != 1 || first[0].PendingRows != 1 || first[0].PendingBytes != len(wire) {
		t.Fatal("pending counted as aggregation or wire size drifted")
	}
	for range 10 {
		if !reflect.DeepEqual(first, c.Pressure()) {
			t.Fatal("read modified collector state")
		}
	}
	for i, kind := range []string{"block", "observe", "trial", "usage"} {
		if first[i].Kind != kind || first[i].KeyLimit != []int{20000, 10000, 10000, 50000}[i] {
			t.Fatal("kind or original bound changed")
		}
	}
	data, _ := json.Marshal(first)
	for _, private := range []string{"user@example", "private.example", "usr_7", "p1", batch.BatchID} {
		if strings.Contains(string(data), private) {
			t.Fatal("pressure view exported private identity")
		}
	}
	first[0].Kind = "changed"
	if c.Pressure()[0].Kind != "block" {
		t.Fatal("returned view aliases collector")
	}
	retry := nextBatch(t, c, 1).Observation
	retryWire, _ := json.Marshal(retry)
	if !reflect.DeepEqual(wire, retryWire) {
		t.Fatal("pressure reading changed frozen retry")
	}
	if !c.Acknowledge(batch.Kind, batch.BatchID) || c.Pressure()[0].PendingBytes != 0 || c.Pressure()[0].PendingRows != 0 || c.Pressure()[0].Keys != 1 {
		t.Fatal("acknowledgement kept stale wire budget or erased new aggregation")
	}
}

func TestPressureWireCacheClearsOnInvalidExpiryAndRevisionChange(t *testing.T) {
	for _, mode := range []string{"invalid", "expiry", "revision"} {
		c, now := testCollector()
		c.AddHit(1, "user@example", "owned.example:443", "psp-deny-p1")
		batch := nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation
		switch mode {
		case "invalid":
			c.DiscardInvalid(batch.Kind, batch.BatchID)
		case "expiry":
			*now = testHour + protocol.MaxAuditReplayAgeMS + 1
			_, _ = c.Next(protocol.MaxAuditObservationBytes)
		case "revision":
			c.SetSnapshot(Snapshot{})
		}
		state := c.Pressure()[0]
		if state.Pending != 0 || state.PendingRows != 0 || state.PendingBytes != 0 {
			t.Fatal("retired pending retained a wire measurement")
		}
	}
}

func TestPressureEmptyViewDoesNotFreezeCounterOnlyOrAdvanceSchedule(t *testing.T) {
	c, _ := testCollector()
	c.lanes["trial"].buckets[testHour] = &bucket{dropped: 3, unmatched: 4}
	before := c.Pressure()
	if before[2].Hours != 1 || before[2].Keys != 0 || before[2].Dropped != 3 || before[2].Unmatched != 4 || c.slot != 0 {
		t.Fatal("loss-only state was omitted or schedule advanced")
	}
	if !reflect.DeepEqual(before, c.Pressure()) || c.slot != 0 {
		t.Fatal("pressure read consumed a scheduler opportunity")
	}
}

func TestPressureCanonicalByteCacheCoversEveryKind(t *testing.T) {
	c, _ := testCollector()
	c.AddHit(1, "user@example", "blocked.example:443", "psp-deny-p1")
	c.AddHit(1, "user@example", "observed.example:443", "psp-watch-p2")
	c.AddHit(1, "user@example", "trial.example:443", "psp-watch-g3")
	c.AddUsage(1, "user@example", "tcp:usage.example:443")
	wires := map[string]int{}
	for range 7 {
		batch := nextBatch(t, c, protocol.MaxAuditObservationBytes).Observation
		encoded, err := json.Marshal(batch)
		if err != nil {
			t.Fatal("canonical batch encoding failed")
		}
		wires[batch.Kind] = len(encoded)
	}
	if len(wires) != 4 {
		t.Fatal("a pressure kind was never frozen")
	}
	for _, lane := range c.Pressure() {
		if lane.Pending != 1 || lane.PendingRows != 1 || lane.PendingBytes != wires[lane.Kind] || lane.Keys != 0 {
			t.Fatal("canonical bytes differ from actual immutable wire encoding")
		}
	}
}

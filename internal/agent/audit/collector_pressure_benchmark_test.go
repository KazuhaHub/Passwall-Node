package audit

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// This is a retention/component measurement, not a live core or control-latency
// claim. All four real collectors and frozen pending subtrees coexist at once.
// Run with -benchtime=1x; production capacities and the wall clock are unchanged.
func BenchmarkCollectorMixedPressure(b *testing.B) {
	definitions := []struct {
		kind  string
		limit int
	}{{"block", 20_000}, {"observe", 10_000}, {"trial", 10_000}, {"usage", 50_000}}
	schedule := []string{"block", "block", "block", "block", "observe", "trial", "usage"}
	for range b.N {
		runtime.GC()
		var before, current runtime.MemStats
		runtime.ReadMemStats(&before)
		peak := before.HeapAlloc
		sample := func() {
			runtime.ReadMemStats(&current)
			peak = max(peak, current.HeapAlloc)
		}
		c := New(nil)
		c.SetSnapshot(Snapshot{Collect: "hits_and_usage", Revision: 1,
			Subjects: map[string]protocol.SubjectKey{"pressure@example.test": "usr_7"},
			Rules:    map[string]protocol.RuleAction{"p1": protocol.RuleBlock, "p2": protocol.RuleObserve, "g3": protocol.RuleObserve}})
		label, padding := strings.Repeat("d", 56), strings.Repeat("a", 48)
		add := func(kind string, id int) {
			destination := fmt.Sprintf("sub.%s.%s.%s.%s%06d%s.test:443", label, label, label, kind, id, padding)
			if kind == "usage" {
				c.AddUsage(1, "pressure@example.test", destination)
			} else {
				tag := map[string]string{"block": "psp-deny-p1", "observe": "psp-watch-p2", "trial": "psp-watch-g3"}[kind]
				c.AddHit(1, "pressure@example.test", destination, tag)
			}
		}
		// Interleave ingress without borrowing capacity from any other lane.
		for id := 0; id <= 50_000; id++ {
			for _, definition := range definitions {
				if id <= definition.limit {
					add(definition.kind, id)
				}
			}
			if id%512 == 0 {
				sample()
			}
		}
		for _, definition := range definitions {
			if l := c.lanes[definition.kind]; l.limit != definition.limit || l.keys != definition.limit {
				b.Fatal("collector pressure did not reach the unchanged production key limit")
			}
		}
		// Retain only hashes and lengths for the comparator, so measurement
		// does not keep a second copy of every serialized pending body alive.
		frozen := map[string]struct {
			digest [32]byte
			bytes  int
		}{}
		for _, kind := range schedule {
			batch, err := c.Next(protocol.MaxAuditObservationBytes)
			if err != nil || batch.Observation == nil || batch.Observation.Kind != kind || protocol.ValidateAuditObservation(*batch.Observation) != nil {
				b.Fatal("collector pressure lost the exact seven-slot schedule or valid pending subtree")
			}
			wire, err := json.Marshal(batch.Observation)
			if err != nil || len(wire) > protocol.MaxAuditObservationBytes {
				b.Fatal("collector pressure exceeded the pending wire bound")
			}
			if prior, exists := frozen[kind]; exists {
				if !batch.Frozen || prior.digest != sha256.Sum256(wire) || prior.bytes != len(wire) {
					b.Fatal("collector pressure changed a frozen retry")
				}
			} else {
				if batch.Frozen {
					b.Fatal("collector pressure borrowed an earlier pending subtree")
				}
				frozen[kind] = struct {
					digest [32]byte
					bytes  int
				}{sha256.Sum256(wire), len(wire)}
			}
		}
		// Keep each pending intact while filling its newly freed aggregate slots
		// and overflowing it again. The next batch cannot merge into the retry.
		for _, definition := range definitions {
			pending := c.lanes[definition.kind].pending
			rows := len(pending.Hits) + len(pending.Usage)
			for id := 0; id <= rows; id++ {
				add(definition.kind, definition.limit+1+id)
				if id%512 == 0 {
					sample()
				}
			}
		}
		opportunities := map[string]int{}
		for _, kind := range schedule {
			batch, err := c.Next(protocol.MaxAuditObservationBytes)
			if err != nil || !batch.Frozen || batch.Observation == nil || batch.Observation.Kind != kind {
				b.Fatal("collector pressure stopped a pending lane from receiving its own slot")
			}
			wire, err := json.Marshal(batch.Observation)
			if err != nil || frozen[kind].digest != sha256.Sum256(wire) || frozen[kind].bytes != len(wire) {
				b.Fatal("collector pressure merged ingress into immutable pending data")
			}
			opportunities[kind]++
		}
		keys, pendingBytes := 0, 0
		for _, definition := range definitions {
			l := c.lanes[definition.kind]
			pending := l.pending
			rows := len(pending.Hits) + len(pending.Usage)
			dropped, unmatched := pending.Dropped, pending.Unmatched
			for _, bucket := range l.buckets {
				dropped += bucket.dropped
				unmatched += bucket.unmatched
			}
			anonymous, identified := 0, 0
			for _, hit := range pending.Hits {
				if hit.Subject == "" && hit.Port == 0 && strings.HasPrefix(hit.Dest, "trial") && !strings.HasPrefix(hit.Dest, "sub.") {
					anonymous++
				} else if hit.Subject == "usr_7" && hit.Port == 443 {
					identified++
				}
			}
			for _, usage := range pending.Usage {
				if usage.Subject == "usr_7" && strings.HasPrefix(usage.Site, "usage") && !strings.HasPrefix(usage.Site, "sub.") {
					identified++
				}
			}
			if l.keys != definition.limit || dropped != 2 || unmatched != 0 || rows == 0 || anonymous+identified != rows || definition.kind == "trial" && anonymous != rows || definition.kind != "trial" && identified != rows {
				b.Fatal("collector pressure lost isolation, exact overflow accounting or anonymous trial rows")
			}
			metrics := map[string]int{"keys": l.keys, "key-limit": l.limit, "pending-rows": rows, "pending-bytes": frozen[definition.kind].bytes, "slots": opportunities[definition.kind], "dropped-events": int(dropped), "unmatched": int(unmatched), "anonymous-rows": anonymous, "identified-rows": identified}
			for name, value := range metrics {
				b.ReportMetric(float64(value), definition.kind+"-"+name)
			}
			keys += l.keys
			pendingBytes += frozen[definition.kind].bytes
		}
		runtime.GC()
		sample()
		b.ReportMetric(float64(keys), "keys")
		b.ReportMetric(4, "pending-count")
		b.ReportMetric(float64(pendingBytes), "pending-bytes")
		b.ReportMetric(float64(current.HeapAlloc-before.HeapAlloc), "retained-heap-bytes")
		b.ReportMetric(float64(peak-before.HeapAlloc), "sampled-peak-heap-bytes")
		runtime.KeepAlive(c)
		runtime.KeepAlive(frozen)
	}
}

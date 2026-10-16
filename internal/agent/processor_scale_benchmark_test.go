package agent

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	statesqlite "github.com/KazuhaHub/passwall-node/v4/internal/state/sqlite"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// Isolate the production processor and real durable SQLite state. Runtime calls
// are counted, not executed: this profile cannot measure core/CLI/network cost
// or replace the real multi-process pressure acceptance.
type processorScaleRuntime struct{ calls int }

func (r *processorScaleRuntime) UpsertListener(context.Context, protocol.Listener) error {
	r.calls++
	return nil
}
func (r *processorScaleRuntime) RemoveListener(context.Context, protocol.ListenerKey) error {
	r.calls++
	return nil
}
func (r *processorScaleRuntime) UpsertClient(context.Context, protocol.Client) error {
	r.calls++
	return nil
}
func (r *processorScaleRuntime) RemoveClient(context.Context, protocol.ClientKey) error {
	r.calls++
	return nil
}

func processorScaleResponse() protocol.SyncResponse {
	response := validSyncResponse()
	version := protocol.Version{Epoch: 1, Version: 1}
	roster := protocol.RosterBody{MinConfigVersion: version, Coverage: protocol.SegmentCounts{Entries: 200, Subjects: 200}}
	directives := protocol.DirectivesBody{ForRosterVersion: version, Coverage: protocol.SegmentCounts{Entries: 200, Subjects: 200}}
	for i := int64(1); i <= 200; i++ {
		key, subject := protocol.NewClientKey(i), protocol.NewSubjectKey(i)
		headroom := int64(1000000)
		roster.Clients = append(roster.Clients, protocol.Client{Key: key, Subject: subject, Enabled: true,
			Listeners:   []protocol.ListenerKey{protocol.NewListenerKey(9)},
			Credentials: protocol.Credential{UUID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i)}})
		directives.Quota = append(directives.Quota, protocol.QuotaEntry{Client: key, HeadroomBytes: &headroom})
		directives.IPShadow = append(directives.IPShadow, protocol.IPShadowEntry{Subject: subject})
	}
	response.Roster, response.Directives = changedSegment(version, roster), changedSegment(version, directives)
	return response
}

func newProcessorScale(tb testing.TB) (*Processor, state.Store, *processorScaleRuntime, protocol.SyncResponse) {
	tb.Helper()
	store, err := statesqlite.Open(context.Background(), filepath.Join(tb.TempDir(), "node-state.db"))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = store.Close() })
	runtime := &processorScaleRuntime{}
	processor, err := NewProcessor(ProcessorOptions{Store: store, Runtime: runtime,
		Issues:              IssueSinkFunc(func(context.Context, LocalIssue) (bool, error) { return false, nil }),
		SkewToleranceRounds: 3, ObjectIssueTimeout: 5 * time.Minute,
		Now: func() time.Time { return time.UnixMilli(1700000000000) }})
	if err != nil {
		tb.Fatal(err)
	}
	response := processorScaleResponse()
	if _, err := processor.Process(context.Background(), response); err != nil {
		tb.Fatal(err)
	}
	response.Config = unchangedSegment[protocol.ConfigBody](response.Config.Version, response.Config.ETag)
	response.Roster = unchangedSegment[protocol.RosterBody](response.Roster.Version, response.Roster.ETag)
	runtime.calls = 0
	return processor, store, runtime, response
}

func TestProcessorScaleKeepsAll200CurrentGrantsWithoutRuntimeMutation(t *testing.T) {
	processor, store, runtime, response := newProcessorScale(t)
	for version := uint64(2); version <= 4; version++ {
		response.Directives.Version.Version = version
		if _, err := processor.Process(t.Context(), response); err != nil {
			t.Fatal(err)
		}
	}
	clients, err := store.Clients(t.Context())
	if err != nil || len(clients) != 200 {
		t.Fatal("processor scale fixture lost current durable clients")
	}
	for _, client := range clients {
		if client.Gate != protocol.GateArmed || client.HeadroomBytes == nil || *client.HeadroomBytes != 1000000 || client.QuotaFingerprint == "" {
			t.Fatal("steady quota processing changed a current grant")
		}
	}
	if runtime.calls != 0 {
		t.Fatal("steady quota processing mutated the core runtime")
	}
}

func BenchmarkProcessorCurrentQuota200(b *testing.B) {
	processor, _, runtime, response := newProcessorScale(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		response.Directives.Version.Version = uint64(i + 2)
		if _, err := processor.Process(b.Context(), response); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(200, "clients/op")
	if runtime.calls != 0 {
		b.Fatal("steady benchmark mutated the core runtime")
	}
}

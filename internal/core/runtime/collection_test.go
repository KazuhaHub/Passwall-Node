package runtime

import (
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func TestCollectionRevisionRestartsUnchangedArtifact(t *testing.T) {
	r, store, _, snapshots := auditRuntimeFixture(t)
	supervisor := r.supervisor.(*supervisorStub)
	setPolicy := func(revision uint64) {
		store.body(t, protocol.StreamConfig, protocol.ConfigBody{Policy: &protocol.DestinationPolicy{Collect: "hits_and_usage", CollectRevision: revision}})
	}
	setPolicy(1)
	if err := r.Converge(t.Context()); err != nil {
		t.Fatal(err)
	}
	setPolicy(2)
	if err := r.Converge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if supervisor.deployCalls != 2 || supervisor.deployment.CollectRevision != 2 || len(*snapshots) != 2 || (*snapshots)[1].Revision != 2 {
		t.Fatalf("unchanged artifact retained old collector: calls=%d deployment=%+v snapshots=%+v", supervisor.deployCalls, supervisor.deployment, *snapshots)
	}
	if err := r.Converge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if supervisor.deployCalls != 2 {
		t.Fatal("unchanged revision restarted")
	}
	supervisor.status.CollectRevision = 1
	if err := r.Converge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if supervisor.deployCalls != 3 {
		t.Fatal("fingerprint cache hid process revision mismatch")
	}
}

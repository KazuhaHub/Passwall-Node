package runtime

import (
	"errors"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/agent/audit"
	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/install"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func auditRuntimeFixture(t *testing.T) (*Runtime, *policyStore, *compilerStub, *[]audit.Snapshot) {
	t.Helper()
	store := &policyStore{}
	policy := runtimePolicy()
	policy.Collect = "hits"
	policy.CollectRevision = 1
	store.body(t, protocol.StreamConfig, protocol.ConfigBody{Policy: policy})
	client := protocol.Client{Key: protocol.NewClientKey(7), Subject: "usr_7", Enabled: true, Listeners: []protocol.ListenerKey{protocol.NewListenerKey(1)}}
	client.Credentials.Username = "confirmed-email"
	store.body(t, protocol.StreamRoster, protocol.RosterBody{Clients: []protocol.Client{client}})
	compiler := &compilerStub{artifact: testArtifact(`{"inbounds":[]}`)}
	var snapshots []audit.Snapshot
	r, err := New(Options{Store: store, Installer: &installerStub{result: install.Installation{Engine: "xray", Version: "26.6.27", BinaryPath: "/cores/xray"}}, Supervisor: &supervisorStub{}, CompilerFactory: func(protocol.CoreSelection) (agentcore.Compiler, error) { return compiler, nil }, Now: func() time.Time { return time.UnixMilli(1_800_000_001_234) }, OnDeployedAudit: func(s audit.Snapshot) { snapshots = append(snapshots, s) }})
	if err != nil {
		t.Fatal(err)
	}
	return r, store, compiler, &snapshots
}

func TestAuditSnapshotPublishedOnlyAfterDurableDeployment(t *testing.T) {
	for _, failure := range []bool{false, true} {
		r, store, _, snapshots := auditRuntimeFixture(t)
		if failure {
			store.saveErr = errors.New("cannot save deployment")
		}
		err := r.Converge(t.Context())
		if failure {
			if err == nil || len(*snapshots) != 0 {
				t.Fatal("unsaved deployment changed collector")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(*snapshots) != 1 {
			t.Fatalf("confirmed snapshot not delivered: %v", *snapshots)
		}
		s := (*snapshots)[0]
		if s.Collect != "hits" || s.Revision != 1 || s.Subjects["confirmed-email"] != "usr_7" || s.Rules["p1"] != protocol.RuleBlock {
			t.Fatalf("confirmed snapshot: %+v", s)
		}
	}
}

func TestAuditRestoreUsesConfirmedBodiesInsteadOfReceivedCandidate(t *testing.T) {
	r, store, _, snapshots := auditRuntimeFixture(t)
	if err := r.Converge(t.Context()); err != nil {
		t.Fatal(err)
	}
	newPolicy := runtimePolicy()
	newPolicy.Collect = "hits"
	newPolicy.CollectRevision = 2
	store.body(t, protocol.StreamConfig, protocol.ConfigBody{Policy: newPolicy})
	client := protocol.Client{Key: protocol.NewClientKey(8), Subject: "usr_8", Enabled: true, Listeners: []protocol.ListenerKey{protocol.NewListenerKey(1)}}
	client.Credentials.Username = "received-email"
	store.body(t, protocol.StreamRoster, protocol.RosterBody{Clients: []protocol.Client{client}})
	*snapshots = nil
	if err := r.RestoreStatus(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(*snapshots) != 1 || (*snapshots)[0].Revision != 1 || (*snapshots)[0].Subjects["confirmed-email"] != "usr_7" || (*snapshots)[0].Subjects["received-email"] != "" {
		t.Fatalf("received candidate relabeled collection: %+v", *snapshots)
	}
}

func TestAuditSnapshotExcludesClosedGatesAndClearsMissingDeployment(t *testing.T) {
	r, store, _, snapshots := auditRuntimeFixture(t)
	store.clients = []state.ClientRuntime{{ClientIdentity: state.ClientIdentity{Key: protocol.NewClientKey(7)}, Gate: protocol.GateClosed}}
	if err := r.Converge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(*snapshots) != 1 || len((*snapshots)[0].Subjects) != 0 {
		t.Fatalf("closed gate appeared in deployed roster: %+v", *snapshots)
	}
	*snapshots = nil
	if err := r.RestoreStatus(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(*snapshots) != 1 || len((*snapshots)[0].Subjects) != 0 {
		t.Fatalf("startup restored a gated credential: %+v", *snapshots)
	}
	*snapshots = nil
	store.deployment = nil
	if err := r.RestoreStatus(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(*snapshots) != 1 || (*snapshots)[0].Collect != "" || (*snapshots)[0].Revision != 0 {
		t.Fatalf("missing deployment did not clear collection: %+v", *snapshots)
	}
}

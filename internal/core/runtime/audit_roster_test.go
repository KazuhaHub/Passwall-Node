package runtime

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/install"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

type rosterRecorder struct {
	mu    sync.Mutex
	calls int
	// events is the order of what the receiver was told, and deploysAtStage the
	// number of Deploy calls the supervisor had seen when each stage happened.
	events         []string
	deploysAtStage []int
	staged         map[string]protocol.SubjectKey
	supervisor     *supervisorStub
	users          map[string]protocol.SubjectKey
	rules          []string
}

func (r *rosterRecorder) StageRoster(users map[string]protocol.SubjectKey, _ []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, "stage")
	r.staged = users
	if r.supervisor != nil {
		r.deploysAtStage = append(r.deploysAtStage, r.supervisor.deployCalls)
	}
}

func (r *rosterRecorder) DiscardStaged() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, "discard")
}

func (r *rosterRecorder) SetRoster(users map[string]protocol.SubjectKey, ruleIDs []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, "set")
	r.calls++
	r.users = users
	r.rules = append([]string(nil), ruleIDs...)
	sort.Strings(r.rules)
}

func auditFixture(t *testing.T, recorder *rosterRecorder) *policyFixture {
	t.Helper()
	store := openRuntimeStore(t)
	policy := &protocol.DestinationPolicy{Collect: protocol.CollectHits, Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Ports: "25"},
		{ID: "p2", Action: protocol.RuleObserve, Ports: "26"},
	}}
	saveVersioned(t, store, protocol.StreamConfig, 1, protocol.ConfigBody{Policy: policy})
	disabled := idleClient(2, time.Time{})
	disabled.Enabled = false
	saveVersioned(t, store, protocol.StreamRoster, 1, protocol.RosterBody{Clients: []protocol.Client{idleClient(1, time.Time{}), disabled}})
	fixture := &policyFixture{
		store:      store,
		compiler:   &compilerStub{artifact: testArtifact(`{"inbounds":[]}`)},
		installer:  &installerStub{result: install.Installation{Engine: "xray", Version: "26.6.27", BinaryPath: "/xray"}},
		supervisor: &supervisorStub{},
	}
	runtime, err := New(Options{
		Store: store, Installer: fixture.installer, Supervisor: fixture.supervisor,
		CompilerFactory: func(protocol.CoreSelection) (agentcore.Compiler, error) { return fixture.compiler, nil },
		Now:             func() time.Time { return time.Unix(1_700_000_000, 0) },
		Audit:           recorder,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.runtime = runtime
	recorder.supervisor = fixture.supervisor
	return fixture
}

// The receiver attributes a hit with the roster that is DEPLOYED, and only
// after it is: the snapshot is pushed once the deployment is confirmed.
func TestTheDeployedRosterAndRulesAreHandedToTheAuditReceiverAfterTheDeployment(t *testing.T) {
	recorder := &rosterRecorder{}
	fixture := auditFixture(t, recorder)
	if err := fixture.converge(t); err != nil {
		t.Fatal(err)
	}
	want := map[string]protocol.SubjectKey{"u1@example.invalid": "usr_1", "u2@example.invalid": "usr_2"}
	if recorder.calls != 1 || !reflect.DeepEqual(recorder.users, want) || !reflect.DeepEqual(recorder.rules, []string{"p1", "p2"}) {
		t.Fatalf("calls = %d users = %v rules = %v", recorder.calls, recorder.users, recorder.rules)
	}
}

func TestAFailedDeploymentDoesNotChangeWhatHitsAreAttributedTo(t *testing.T) {
	recorder := &rosterRecorder{}
	fixture := auditFixture(t, recorder)
	fixture.supervisor.err = errors.New("core refused")
	if err := fixture.converge(t); err == nil {
		t.Fatal("the deployment was expected to fail")
	}
	if recorder.calls != 0 {
		t.Fatalf("the receiver was given a roster that never deployed: %+v", recorder)
	}
}

func TestRestoreStatusRestoresTheAuditSnapshotFromTheSavedDeployment(t *testing.T) {
	recorder := &rosterRecorder{}
	fixture := auditFixture(t, recorder)
	if err := fixture.converge(t); err != nil {
		t.Fatal(err)
	}
	// A restarted agent: a new runtime and receiver over the same database.
	restarted := &rosterRecorder{}
	runtime, err := New(Options{
		Store: fixture.store, Installer: fixture.installer, Supervisor: fixture.supervisor, Audit: restarted,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.RestoreStatus(t.Context()); err != nil {
		t.Fatal(err)
	}
	want := map[string]protocol.SubjectKey{"u1@example.invalid": "usr_1", "u2@example.invalid": "usr_2"}
	if restarted.calls != 1 || !reflect.DeepEqual(restarted.users, want) || !reflect.DeepEqual(restarted.rules, []string{"p1", "p2"}) {
		t.Fatalf("calls = %d users = %v rules = %v", restarted.calls, restarted.users, restarted.rules)
	}
}

func TestRestoreStatusWithNoSavedDeploymentOrAnUndecodableOneHoldsNothing(t *testing.T) {
	for name, deployment := range map[string]*state.CoreDeployment{
		"no deployment": nil,
		"undecodable": {
			Engine: "xray", Version: "26.6.27", ConfigDigest: testArtifact(`{}`).Digest, Artifact: []byte(`{}`),
			ConfigBody: []byte(`[]`), RosterBody: []byte(`[]`), AppliedAtMS: 5,
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := openRuntimeStore(t)
			if deployment != nil {
				if err := store.SaveCoreDeployment(t.Context(), *deployment); err != nil {
					t.Fatal(err)
				}
			}
			recorder := &rosterRecorder{}
			runtime, err := New(Options{Store: store, Installer: &installerStub{}, Supervisor: &supervisorStub{}, Audit: recorder})
			if err != nil {
				t.Fatal(err)
			}
			if err := runtime.RestoreStatus(t.Context()); err != nil {
				t.Fatal(err)
			}
			// An empty snapshot: with nothing known, every hit is unmatched, and
			// none is attributed to a person it may not belong to.
			if len(recorder.users) != 0 || len(recorder.rules) != 0 {
				t.Fatalf("users = %v rules = %v, want an empty snapshot", recorder.users, recorder.rules)
			}
		})
	}
}

func TestARuntimeWithoutAnAuditReceiverStillDeploys(t *testing.T) {
	fixture := newPolicyFixture(t, blockPolicy("25"))
	if err := fixture.converge(t); err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.RestoreStatus(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// The candidate roster is given to the receiver BEFORE the core is deployed: a
// core that starts sending hits as soon as it is up would otherwise have them
// attributed against the roster it replaced. A deployment that fails goes back
// to the old one, and one that succeeds commits the new.
func TestTheCandidateRosterIsStagedBeforeTheDeploymentAndCommittedOrDiscardedAfter(t *testing.T) {
	recorder := &rosterRecorder{}
	fixture := auditFixture(t, recorder)
	if err := fixture.converge(t); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(recorder.events); got != "[stage set]" || len(recorder.deploysAtStage) != 1 || recorder.deploysAtStage[0] != 0 {
		t.Fatalf("events = %v, deploys seen at stage = %v: want the stage before the first Deploy and then the commit", recorder.events, recorder.deploysAtStage)
	}
	if !reflect.DeepEqual(recorder.staged, map[string]protocol.SubjectKey{"u1@example.invalid": "usr_1", "u2@example.invalid": "usr_2"}) {
		t.Fatalf("staged = %v", recorder.staged)
	}

	failing := &rosterRecorder{}
	broken := auditFixture(t, failing)
	broken.supervisor.err = errors.New("core refused")
	if err := broken.converge(t); err == nil {
		t.Fatal("the deployment was expected to fail")
	}
	if got := fmt.Sprint(failing.events); got != "[stage discard]" || failing.calls != 0 {
		t.Fatalf("events = %v, commits = %d: a failed deployment must discard what it staged", failing.events, failing.calls)
	}
}

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/KazuhaHub/passwall-node/v4/internal/agent/audit"
	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// Only convergence inputs belong here. Wall-clock time itself would defeat
// idle caching; the set of deadlines already crossed captures its effect.
type convergenceInputs struct {
	Config   protocol.ETag
	Roster   protocol.ETag
	Core     protocol.CoreSelection
	Disabled []protocol.ClientKey
	Expired  []protocol.ClientKey
}

func (inputs convergenceInputs) digest() string {
	sort.Slice(inputs.Disabled, func(i, j int) bool { return inputs.Disabled[i] < inputs.Disabled[j] })
	sort.Slice(inputs.Expired, func(i, j int) bool { return inputs.Expired[i] < inputs.Expired[j] })
	body, _ := json.Marshal(inputs)
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

// PolicyStatus is safe to build into a concurrent full or partial report.
func (r *Runtime) PolicyStatus() *protocol.PolicyStatus {
	r.policyMu.RLock()
	defer r.policyMu.RUnlock()
	status := r.policyStatus
	status.Listeners = append([]protocol.ListenerKey(nil), status.Listeners...)
	return &status
}

func (r *Runtime) setPolicyStatus(status protocol.PolicyStatus) {
	r.policyMu.Lock()
	r.policyStatus = status
	r.policyMu.Unlock()
}

func (r *Runtime) rejectPolicy(policy *protocol.DestinationPolicy, rejected *agentcore.PolicyError) {
	listeners := append([]protocol.ListenerKey(nil), rejected.Listeners...)
	sort.Slice(listeners, func(i, j int) bool { return listeners[i] < listeners[j] })
	r.setPolicyStatus(protocol.PolicyStatus{
		Digest: protocol.PolicyDigest(policy), State: "rejected", IssueCode: rejected.Code, Listeners: listeners,
	})
}

func (r *Runtime) confirmDeployment(ctx context.Context, selection protocol.CoreSelection, artifact agentcore.Artifact, config *protocol.ConfigBody, roster *protocol.RosterBody, fingerprint string, snapshot agentcore.Snapshot) error {
	if err := r.saveDeployment(ctx, selection, artifact, config, roster); err != nil {
		return err
	}
	r.publishAuditSnapshot(selection.Engine, snapshot)
	r.setPolicyStatus(protocol.PolicyStatus{Digest: protocol.PolicyDigest(config.Policy), State: "applied"})
	r.lastFingerprint = fingerprint
	return nil
}

// RestoreStatus must run before lifecycle starts the core and report builder.
// Received streams are deliberately not consulted: they may contain rejected
// candidates and cannot establish what the saved process actually executes.
func (r *Runtime) RestoreStatus(ctx context.Context) error {
	r.convergeMu.Lock()
	defer r.convergeMu.Unlock()
	deployment, err := r.store.CoreDeployment(ctx)
	if errors.Is(err, state.ErrNotFound) {
		r.setPolicyStatus(protocol.PolicyStatus{State: "applied"})
		r.lastDeployment = nil
		r.lastFingerprint = ""
		r.publishAuditSnapshot("", agentcore.Snapshot{})
		return nil
	}
	if err != nil {
		return fmt.Errorf("restore confirmed policy: %w", err)
	}
	var config protocol.ConfigBody
	var roster protocol.RosterBody
	if err := json.Unmarshal(deployment.ConfigBody, &config); err != nil {
		return fmt.Errorf("decode confirmed config: %w", err)
	}
	if err := json.Unmarshal(deployment.RosterBody, &roster); err != nil {
		return fmt.Errorf("decode confirmed roster: %w", err)
	}
	if err := protocol.ValidateDestinationPolicy(config.Policy); err != nil {
		return fmt.Errorf("validate confirmed policy: %w", err)
	}
	deployed := agentcore.Snapshot{DestinationPolicy: config.Policy, Clients: roster.Clients, Now: r.now()}
	if r.onDeployedAudit != nil {
		// RosterBody stores the received roster, while compilation may have
		// disabled credentials using durable local quota gates. Apply those
		// gates when restoring bindings; never substitute received usernames.
		clients, err := r.store.Clients(ctx)
		if err != nil {
			return fmt.Errorf("restore confirmed roster gates: %w", err)
		}
		denied := map[protocol.ClientKey]bool{}
		for _, client := range clients {
			denied[client.Key] = client.Gate == protocol.GateClosed || client.Gate == protocol.GateUnconfigured && client.HeadroomBytes != nil
		}
		for i := range deployed.Clients {
			if denied[deployed.Clients[i].Key] {
				deployed.Clients[i].Enabled = false
			}
		}
	}
	r.lastDeployment = &deployment
	r.lastFingerprint = "" // Local gates and crossed deadlines must be checked again.
	r.setPolicyStatus(protocol.PolicyStatus{Digest: protocol.PolicyDigest(config.Policy), State: "applied"})
	r.publishAuditSnapshot(deployment.Engine, deployed)
	return nil
}

// Build bindings from the snapshot actually compiled, not newly received
// desired documents. A rejected candidate and failed persistence leave the
// previous collector snapshot in place. Startup uses only saved deployment
// bodies; sing-box does not collect hits even when a stale input requests them.
func (r *Runtime) publishAuditSnapshot(engine string, deployed agentcore.Snapshot) {
	if r.onDeployedAudit == nil {
		return
	}
	s := audit.Snapshot{Subjects: map[string]protocol.SubjectKey{}, Rules: map[string]protocol.RuleAction{}}
	p := deployed.DestinationPolicy
	if engine != "xray" || p == nil {
		r.onDeployedAudit(s)
		return
	}
	s.Collect, s.Revision = string(p.Collect), p.CollectRevision
	ambiguous := map[string]bool{}
	for _, client := range deployed.Clients {
		if !client.Enabled || len(client.Listeners) == 0 || client.ExpiresAtMS > 0 && deployed.Now.UnixMilli() >= client.ExpiresAtMS {
			continue
		}
		email := strings.TrimSpace(client.Credentials.Username)
		if email == "" {
			continue
		}
		if _, err := client.Subject.RowID(); err != nil {
			continue
		}
		if previous, found := s.Subjects[email]; found && previous != client.Subject {
			delete(s.Subjects, email)
			ambiguous[email] = true
		}
		if !ambiguous[email] {
			s.Subjects[email] = client.Subject
		}
	}
	for _, rule := range p.Rules {
		if rule.Action == protocol.RuleAllow || len(rule.Subjects) > 0 && len(agentcore.PolicyEmails(deployed, rule.Subjects)) == 0 {
			continue
		}
		s.Rules[rule.ID] = rule.Action
	}
	r.onDeployedAudit(s)
}

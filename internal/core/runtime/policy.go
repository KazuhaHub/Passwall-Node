package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

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

func (r *Runtime) confirmDeployment(ctx context.Context, selection protocol.CoreSelection, artifact agentcore.Artifact, config *protocol.ConfigBody, roster *protocol.RosterBody, fingerprint string) error {
	if err := r.saveDeployment(ctx, selection, artifact, config, roster); err != nil {
		return err
	}
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
	r.lastDeployment = &deployment
	r.lastFingerprint = "" // Local gates and crossed deadlines must be checked again.
	r.setPolicyStatus(protocol.PolicyStatus{Digest: protocol.PolicyDigest(config.Policy), State: "applied"})
	return nil
}

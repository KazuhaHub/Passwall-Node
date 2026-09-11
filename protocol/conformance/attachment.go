// Package conformance contains the executable convergence rules shared by the
// agent implementation and its contract tests.
//
// It deliberately contains no I/O. The sync loop and the durable store must
// call these functions instead of growing private copies of protocol policy.
package conformance

import (
	"fmt"

	"github.com/KazuhaHub/passwall-node/protocol"
)

// AttachmentDisposition explains why one roster attachment is or is not
// converged. Keeping the reason distinct from ObjectState prevents a temporary
// version skew from being reported as a malformed PSP document.
type AttachmentDisposition string

const (
	AttachmentReady              AttachmentDisposition = "ready"
	AttachmentWaitingForConfig   AttachmentDisposition = "waiting_for_config"
	AttachmentUnknownListener    AttachmentDisposition = "unknown_listener"
	AttachmentWaitingForListener AttachmentDisposition = "waiting_for_listener"
	AttachmentBlockedByListener  AttachmentDisposition = "blocked_by_listener"
)

// AttachmentInput is the complete evidence needed to judge one client to
// listener attachment.
type AttachmentInput struct {
	ClientKey           protocol.ClientKey
	ListenerKey         protocol.ListenerKey
	RosterMinConfig     protocol.Version
	AppliedConfig       protocol.Version
	ListenerKnown       bool
	ListenerState       protocol.ObjectState
	AheadRounds         int
	EscalateAfterRounds int
}

// AttachmentDecision is the client object's state plus any issue that must be
// surfaced immediately. A nil Issue is intentional for self-healing skew.
type AttachmentDecision struct {
	Disposition AttachmentDisposition
	State       protocol.ObjectState
	Issue       *protocol.Issue
}

// EvaluateAttachment implements the three-way reference-integrity ruling from
// the wire contract.
func EvaluateAttachment(in AttachmentInput) (AttachmentDecision, error) {
	if in.ClientKey == "" || in.ListenerKey == "" {
		return AttachmentDecision{}, fmt.Errorf("client and listener keys are required")
	}
	if in.AheadRounds < 0 || in.EscalateAfterRounds < 0 {
		return AttachmentDecision{}, fmt.Errorf("round counts must be non-negative")
	}

	if in.RosterMinConfig.Newer(in.AppliedConfig) {
		decision := AttachmentDecision{
			Disposition: AttachmentWaitingForConfig,
			State:       protocol.ObjectPending,
		}
		// "Past K rounds" is strict: K tolerated rounds are still the normal
		// self-healing window; the next one becomes observable.
		if in.AheadRounds > in.EscalateAfterRounds {
			decision.Issue = &protocol.Issue{
				Code: protocol.IssueRosterAheadOfConfig,
				Key:  string(in.ClientKey),
				Detail: fmt.Sprintf("listener %s requires config %s; agent has %s after %d rounds",
					in.ListenerKey, in.RosterMinConfig, in.AppliedConfig, in.AheadRounds),
			}
		}
		return decision, nil
	}

	if !in.ListenerKnown {
		return AttachmentDecision{
			Disposition: AttachmentUnknownListener,
			State:       protocol.ObjectRejected,
			Issue: &protocol.Issue{
				Code:   protocol.IssueAttachmentUnknownListener,
				Key:    string(in.ClientKey),
				Detail: fmt.Sprintf("listener %s is absent after config versions closed", in.ListenerKey),
			},
		}, nil
	}

	switch in.ListenerState {
	case protocol.ObjectApplied:
		return AttachmentDecision{Disposition: AttachmentReady, State: protocol.ObjectApplied}, nil
	case protocol.ObjectRejected:
		return AttachmentDecision{
			Disposition: AttachmentBlockedByListener,
			State:       protocol.ObjectBlocked,
		}, nil
	case protocol.ObjectPending, protocol.ObjectBlocked:
		return AttachmentDecision{
			Disposition: AttachmentWaitingForListener,
			State:       protocol.ObjectPending,
		}, nil
	default:
		return AttachmentDecision{}, fmt.Errorf("listener %s has invalid object state %q", in.ListenerKey, in.ListenerState)
	}
}

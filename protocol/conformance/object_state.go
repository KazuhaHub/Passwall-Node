package conformance

import (
	"fmt"
	"time"

	"github.com/KazuhaHub/passwall-node/protocol"
)

// ObjectEvent is an observation that advances one object's convergence state.
type ObjectEvent string

const (
	EventAccepted          ObjectEvent = "accepted"
	EventApplied           ObjectEvent = "applied"
	EventRetryableFailure  ObjectEvent = "retryable_failure"
	EventRejected          ObjectEvent = "rejected"
	EventDependencyBlocked ObjectEvent = "dependency_blocked"
	EventDependencyReady   ObjectEvent = "dependency_ready"
)

// Transition carries the event's evidence. Version is required for Accepted;
// IssueCode for Rejected; BlockedOn for DependencyBlocked.
type Transition struct {
	Event     ObjectEvent
	Version   protocol.Version
	AtMS      int64
	IssueCode string
	BlockedOn string
}

// AdvanceObject is the sole object-state transition function. It rejects
// impossible transitions instead of silently manufacturing a green state.
func AdvanceObject(current protocol.ObjectStatus, tr Transition) (protocol.ObjectStatus, error) {
	switch tr.Event {
	case EventAccepted:
		return acceptVersion(current, tr)
	case EventApplied:
		if current.State == protocol.ObjectRejected {
			return current, fmt.Errorf("rejected content cannot become applied without a newer accepted version")
		}
		if current.State != protocol.ObjectPending && current.State != protocol.ObjectBlocked && current.State != protocol.ObjectApplied {
			return current, fmt.Errorf("cannot apply object from state %q", current.State)
		}
		current.State = protocol.ObjectApplied
		current.FirstFailedAtMS = 0
		current.IssueCode = ""
		current.BlockedOn = ""
		return current, nil
	case EventRetryableFailure:
		if current.State == protocol.ObjectRejected || current.State == "" {
			return current, fmt.Errorf("retryable failure cannot replace state %q", current.State)
		}
		current.State = protocol.ObjectPending
		current.BlockedOn = ""
		current.FirstFailedAtMS = firstNonZero(current.FirstFailedAtMS, tr.AtMS)
		return current, nil
	case EventRejected:
		if current.State != protocol.ObjectPending && current.State != protocol.ObjectRejected && current.State != protocol.ObjectApplied {
			return current, fmt.Errorf("rejection requires accepted content, got %q", current.State)
		}
		if tr.IssueCode == "" {
			return current, fmt.Errorf("rejection requires an issue code")
		}
		current.State = protocol.ObjectRejected
		current.FirstFailedAtMS = firstNonZero(current.FirstFailedAtMS, tr.AtMS)
		current.IssueCode = tr.IssueCode
		current.BlockedOn = ""
		return current, nil
	case EventDependencyBlocked:
		if current.State != protocol.ObjectPending && current.State != protocol.ObjectApplied && current.State != protocol.ObjectBlocked {
			return current, fmt.Errorf("dependency block cannot replace state %q", current.State)
		}
		if tr.BlockedOn == "" {
			return current, fmt.Errorf("dependency block requires blocked_on")
		}
		current.State = protocol.ObjectBlocked
		current.FirstFailedAtMS = firstNonZero(current.FirstFailedAtMS, tr.AtMS)
		current.IssueCode = ""
		current.BlockedOn = tr.BlockedOn
		return current, nil
	case EventDependencyReady:
		if current.State != protocol.ObjectBlocked {
			return current, fmt.Errorf("dependency-ready requires blocked state, got %q", current.State)
		}
		current.State = protocol.ObjectPending
		current.BlockedOn = ""
		return current, nil
	default:
		return current, fmt.Errorf("unknown object event %q", tr.Event)
	}
}

func acceptVersion(current protocol.ObjectStatus, tr Transition) (protocol.ObjectStatus, error) {
	if !tr.Version.Committed() {
		return current, fmt.Errorf("accepted version must be non-zero")
	}
	if current.SinceVersion == tr.Version {
		// Re-delivery is idempotent. In particular, it must not make rejected
		// byte-identical content retry forever.
		return current, nil
	}
	if !current.SinceVersion.Zero() && !tr.Version.Newer(current.SinceVersion) {
		return current, fmt.Errorf("accepted version %s is older than current %s", tr.Version, current.SinceVersion)
	}
	current.State = protocol.ObjectPending
	current.SinceVersion = tr.Version
	current.FirstFailedAtMS = tr.AtMS
	current.IssueCode = ""
	current.BlockedOn = ""
	return current, nil
}

func firstNonZero(current, candidate int64) int64 {
	if current != 0 {
		return current
	}
	return candidate
}

// TimeoutIssue promotes a long-lived pending or rejected object into an Issue.
// It never mutates the state: degraded convergence remains visible after the
// alert has been emitted.
func TimeoutIssue(status protocol.ObjectStatus, now time.Time, timeout time.Duration) (*protocol.Issue, error) {
	if timeout <= 0 {
		return nil, fmt.Errorf("timeout must be positive")
	}
	if status.State != protocol.ObjectPending && status.State != protocol.ObjectRejected {
		return nil, nil
	}
	if status.FirstFailedAtMS <= 0 {
		return nil, nil
	}
	first := time.UnixMilli(status.FirstFailedAtMS)
	if now.Before(first) || now.Sub(first) < timeout {
		return nil, nil
	}

	code := protocol.IssueObjectPendingTimeout
	if status.State == protocol.ObjectRejected {
		code = protocol.IssueObjectRejectedTimeout
	}
	return &protocol.Issue{
		Code:   code,
		Key:    status.Key,
		Detail: fmt.Sprintf("%s object has remained %s since %s", status.Stream, status.State, first.UTC().Format(time.RFC3339)),
	}, nil
}

package agent

import (
	"context"
	"errors"
	"fmt"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// Runtime is the B3 boundary. B2 owns ordering, persistence, joins, retries,
// and object states; a core adapter owns only idempotent local convergence.
// UpsertClient must enforce Enabled and ExpiresAtMS locally, including firing
// an already-delivered absolute expiry while PSP is unreachable. Waiting for a
// later roster omission would turn a predictable deadline into an outage leak.
type Runtime interface {
	UpsertListener(context.Context, protocol.Listener) error
	RemoveListener(context.Context, protocol.ListenerKey) error
	UpsertClient(context.Context, protocol.Client) error
	RemoveClient(context.Context, protocol.ClientKey) error
}

// TransitRuntime is implemented by a runtime that can relay transit: forwards
// and links, each named by its config object key. A runtime that does not
// implement it gets every transit object rejected, so nothing is reported
// applied by something that opened no port.
type TransitRuntime interface {
	UpsertTransit(ctx context.Context, key string) error
}

// RoundScopedRuntime gives a full-config core adapter one scope per sync
// response. Every object operation in that scope may share one compiled
// snapshot and one deploy result; Finalize also covers an empty listener/client
// set. This is the mechanism that makes “one sync round → at most one core
// transition” true without weakening B2's per-object convergence states.
type RoundScopedRuntime interface {
	Runtime
	NewRound() RuntimeRound
}

type RuntimeRound interface {
	Runtime
	Finalize(context.Context) error
}

// ObjectRejection is one object the deployment the core runs left out.
type ObjectRejection struct {
	Stream, Key, Code string
	Err               error
}

// RejectionSource is implemented by a runtime that can deploy without some
// objects (agentcore.Artifact.Rejected). After a round the processor makes every
// object's state agree with it, whether or not the object was asked about.
type RejectionSource interface {
	Rejections() []ObjectRejection
}

// RejectedError marks content that retrying unchanged cannot fix. Ordinary
// errors remain pending and may heal on retry.
type RejectedError struct {
	Code string
	Err  error
}

func (e *RejectedError) Error() string {
	if e == nil {
		return "rejected"
	}
	if e.Err == nil {
		return fmt.Sprintf("rejected: %s", e.Code)
	}
	return fmt.Sprintf("rejected: %s: %v", e.Code, e.Err)
}

func (e *RejectedError) Unwrap() error { return e.Err }

func rejectionCode(err error) (string, bool) {
	var rejected *RejectedError
	if !errors.As(err, &rejected) || rejected.Code == "" {
		return "", false
	}
	return rejected.Code, true
}

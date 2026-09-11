package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

// SegmentFailure rejects exactly one stream. Other streams in the same
// response remain independently receivable.
type SegmentFailure struct {
	Stream string
	Err    error
}

func (f SegmentFailure) Error() string { return fmt.Sprintf("reject %s segment: %v", f.Stream, f.Err) }
func (f SegmentFailure) Unwrap() error { return f.Err }

type ReceivedDocuments struct {
	Config     *protocol.ConfigBody
	Roster     *protocol.RosterBody
	Directives *protocol.DirectivesBody

	ConfigChanged     bool
	RosterChanged     bool
	DirectivesChanged bool
	NeedImmediatePoll bool
	Failures          []SegmentFailure
}

// SegmentReceiver validates and durably accepts the three streams. Applied
// versions are written only for bodies present in this response.
type SegmentReceiver struct {
	Store state.Store
	NowMS func() int64
}

func (r SegmentReceiver) Receive(ctx context.Context, response protocol.SyncResponse) (ReceivedDocuments, error) {
	if r.Store == nil {
		return ReceivedDocuments{}, fmt.Errorf("state store is required")
	}
	nowMS := r.NowMS
	if nowMS == nil {
		nowMS = func() int64 { return 0 }
	}
	result := ReceivedDocuments{}

	config, changed, needFull, failure, err := receiveSegment(
		ctx, r.Store, protocol.StreamConfig, response.Config, nowMS(), validateConfig,
	)
	if err != nil {
		return ReceivedDocuments{}, err
	}
	result.Config, result.ConfigChanged, result.NeedImmediatePoll = config, changed, needFull
	if failure != nil {
		result.Failures = append(result.Failures, *failure)
	}

	roster, changed, needFull, failure, err := receiveSegment(
		ctx, r.Store, protocol.StreamRoster, response.Roster, nowMS(), validateRoster,
	)
	if err != nil {
		return ReceivedDocuments{}, err
	}
	result.Roster, result.RosterChanged = roster, changed
	result.NeedImmediatePoll = result.NeedImmediatePoll || needFull
	if failure != nil {
		result.Failures = append(result.Failures, *failure)
	}

	directives, changed, needFull, failure, err := receiveSegment(
		ctx, r.Store, protocol.StreamDirectives, response.Directives, nowMS(), validateDirectives,
	)
	if err != nil {
		return ReceivedDocuments{}, err
	}
	result.Directives, result.DirectivesChanged = directives, changed
	result.NeedImmediatePoll = result.NeedImmediatePoll || needFull
	if failure != nil {
		result.Failures = append(result.Failures, *failure)
	}
	return result, nil
}

type segmentValidator[T any] func(*T) error

func receiveSegment[T any](
	ctx context.Context,
	store state.Store,
	stream string,
	segment protocol.Segment[T],
	acceptedAtMS int64,
	validate segmentValidator[T],
) (*T, bool, bool, *SegmentFailure, error) {
	current, currentErr := loadStoredBody[T](ctx, store, stream)
	if currentErr != nil && !errors.Is(currentErr, state.ErrNotFound) {
		return nil, false, false, nil, currentErr
	}
	fail := func(err error) (*T, bool, bool, *SegmentFailure, error) {
		return current, false, false, &SegmentFailure{Stream: stream, Err: err}, nil
	}
	if !segment.Version.Committed() {
		return fail(fmt.Errorf("version must contain a positive epoch and version"))
	}
	if segment.ETag == "" {
		return fail(fmt.Errorf("etag is required"))
	}

	if segment.Unchanged {
		if segment.Body != nil {
			return fail(fmt.Errorf("unchanged segment must not carry a body"))
		}
		if errors.Is(currentErr, state.ErrNotFound) {
			return fail(fmt.Errorf("unchanged segment has no locally persisted body"))
		}
		doc, err := store.Stream(ctx, stream)
		if err != nil {
			return nil, false, false, nil, err
		}
		if segment.Version.Epoch > doc.Version.Epoch {
			if err := store.ClearStreamForHigherEpoch(ctx, stream, segment.Version.Epoch); err != nil {
				return nil, false, false, nil, err
			}
			return current, false, true, nil, nil
		}
		if doc.Version.Newer(segment.Version) {
			return fail(fmt.Errorf("response version %s is behind applied %s", segment.Version, doc.Version))
		}
		if doc.ETag != segment.ETag {
			return fail(fmt.Errorf("unchanged etag %q differs from applied %q", segment.ETag, doc.ETag))
		}
		return current, false, false, nil, nil
	}

	if segment.Body == nil {
		return fail(fmt.Errorf("changed segment must carry a body"))
	}
	if err := validate(segment.Body); err != nil {
		return fail(err)
	}
	body, err := json.Marshal(segment.Body)
	if err != nil {
		return fail(fmt.Errorf("encode body: %w", err))
	}
	doc := state.StreamDocument{
		Stream: stream, Version: segment.Version, ETag: segment.ETag,
		Body: body, AcceptedAtMS: acceptedAtMS,
	}
	if err := store.SaveStream(ctx, doc); err != nil {
		if errors.Is(err, state.ErrStaleVersion) || errors.Is(err, state.ErrVersionConflict) || isValidationError(err) {
			return fail(err)
		}
		return nil, false, false, nil, err
	}
	return segment.Body, true, false, nil, nil
}

func loadStoredBody[T any](ctx context.Context, store state.Store, stream string) (*T, error) {
	doc, err := store.Stream(ctx, stream)
	if err != nil {
		return nil, err
	}
	var body T
	if err := json.Unmarshal(doc.Body, &body); err != nil {
		return nil, fmt.Errorf("decode persisted %s body: %w", stream, err)
	}
	return &body, nil
}

// Store validation errors are local input rejection, not disk failures. The
// concrete store intentionally exposes only semantic sentinels; digest and
// JSON validation are recognizable by their pre-I/O context here.
func isValidationError(err error) bool {
	return errors.Is(err, state.ErrStaleVersion) ||
		errors.Is(err, state.ErrVersionConflict) ||
		errors.Is(err, state.ErrInvalidState)
}

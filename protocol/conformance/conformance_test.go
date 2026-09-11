package conformance

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/protocol"
)

func TestAttachmentContract(t *testing.T) {
	if err := attachmentContract(EvaluateAttachment); err != nil {
		t.Fatal(err)
	}
}

func TestAttachmentContractRejectsUnknownFirstMutation(t *testing.T) {
	mutant := func(in AttachmentInput) (AttachmentDecision, error) {
		// Deliberately wrong: a roster may legitimately lead the config. Looking
		// up its listener before checking that skew raises a false PSP defect.
		if !in.ListenerKnown {
			return AttachmentDecision{
				Disposition: AttachmentUnknownListener,
				State:       protocol.ObjectRejected,
				Issue:       &protocol.Issue{Code: protocol.IssueAttachmentUnknownListener},
			}, nil
		}
		return EvaluateAttachment(in)
	}
	if err := attachmentContract(mutant); err == nil {
		t.Fatal("attachment contract did not detect the unknown-listener-before-version mutation")
	}
}

type attachmentEvaluator func(AttachmentInput) (AttachmentDecision, error)

func attachmentContract(evaluate attachmentEvaluator) error {
	ahead := AttachmentInput{
		ClientKey:           protocol.NewClientKey(7),
		ListenerKey:         protocol.NewListenerKey(9),
		RosterMinConfig:     protocol.Version{Epoch: 1, Version: 12},
		AppliedConfig:       protocol.Version{Epoch: 1, Version: 11},
		ListenerKnown:       false,
		AheadRounds:         3,
		EscalateAfterRounds: 3,
	}
	got, err := evaluate(ahead)
	if err != nil {
		return fmt.Errorf("evaluate tolerated skew: %w", err)
	}
	if got.Disposition != AttachmentWaitingForConfig || got.State != protocol.ObjectPending || got.Issue != nil {
		return fmt.Errorf("tolerated roster/config skew = %+v, want pending without issue", got)
	}

	ahead.AheadRounds++
	got, err = evaluate(ahead)
	if err != nil {
		return fmt.Errorf("evaluate expired skew: %w", err)
	}
	if got.Issue == nil || got.Issue.Code != protocol.IssueRosterAheadOfConfig {
		return fmt.Errorf("skew beyond K rounds = %+v, want %s", got, protocol.IssueRosterAheadOfConfig)
	}

	closed := ahead
	closed.AppliedConfig = closed.RosterMinConfig
	got, err = evaluate(closed)
	if err != nil {
		return fmt.Errorf("evaluate closed missing listener: %w", err)
	}
	if got.Disposition != AttachmentUnknownListener || got.State != protocol.ObjectRejected || got.Issue == nil || got.Issue.Code != protocol.IssueAttachmentUnknownListener {
		return fmt.Errorf("closed missing listener = %+v, want rejected PSP defect", got)
	}

	closed.ListenerKnown = true
	closed.ListenerState = protocol.ObjectRejected
	got, err = evaluate(closed)
	if err != nil {
		return fmt.Errorf("evaluate rejected listener: %w", err)
	}
	if got.Disposition != AttachmentBlockedByListener || got.State != protocol.ObjectBlocked || got.Issue != nil {
		return fmt.Errorf("rejected listener attachment = %+v, want blocked without duplicate issue", got)
	}

	closed.ListenerState = protocol.ObjectApplied
	got, err = evaluate(closed)
	if err != nil {
		return fmt.Errorf("evaluate applied listener: %w", err)
	}
	if got.Disposition != AttachmentReady || got.State != protocol.ObjectApplied || got.Issue != nil {
		return fmt.Errorf("converged attachment = %+v, want applied", got)
	}
	return nil
}

func TestObjectStateContract(t *testing.T) {
	if err := objectStateContract(AdvanceObject, TimeoutIssue); err != nil {
		t.Fatal(err)
	}
}

func TestObjectStateContractRejectsRetryRejectedMutation(t *testing.T) {
	mutant := func(current protocol.ObjectStatus, tr Transition) (protocol.ObjectStatus, error) {
		// Deliberately wrong: retrying unchanged rejected content can never help.
		if tr.Event == EventApplied && current.State == protocol.ObjectRejected {
			current.State = protocol.ObjectApplied
			return current, nil
		}
		return AdvanceObject(current, tr)
	}
	if err := objectStateContract(mutant, TimeoutIssue); err == nil {
		t.Fatal("object-state contract did not detect retrying rejected content")
	}
}

func TestObjectStateContractRejectsNoPendingTimeoutMutation(t *testing.T) {
	mutantTimeout := func(status protocol.ObjectStatus, now time.Time, timeout time.Duration) (*protocol.Issue, error) {
		if status.State == protocol.ObjectPending {
			return nil, nil
		}
		return TimeoutIssue(status, now, timeout)
	}
	if err := objectStateContract(AdvanceObject, mutantTimeout); err == nil {
		t.Fatal("object-state contract did not detect the missing pending timeout")
	}
}

type objectAdvancer func(protocol.ObjectStatus, Transition) (protocol.ObjectStatus, error)
type timeoutEvaluator func(protocol.ObjectStatus, time.Time, time.Duration) (*protocol.Issue, error)

func objectStateContract(advance objectAdvancer, timeoutFor timeoutEvaluator) error {
	v1 := protocol.Version{Epoch: 1, Version: 1}
	v2 := protocol.Version{Epoch: 1, Version: 2}
	start := time.Unix(1_700_000_000, 0).UTC()
	status := protocol.ObjectStatus{Stream: protocol.StreamRoster, Key: "cli_7"}

	var err error
	status, err = advance(status, Transition{Event: EventAccepted, Version: v1, AtMS: start.UnixMilli()})
	if err != nil || status.State != protocol.ObjectPending || status.SinceVersion != v1 || status.FirstFailedAtMS != start.UnixMilli() {
		return fmt.Errorf("accept first version = (%+v, %v), want timed pending", status, err)
	}
	status, err = advance(status, Transition{Event: EventRejected, AtMS: start.Add(time.Second).UnixMilli(), IssueCode: "invalid_credentials"})
	if err != nil || status.State != protocol.ObjectRejected || status.FirstFailedAtMS != start.UnixMilli() {
		return fmt.Errorf("reject version = (%+v, %v), want rejected preserving first failure", status, err)
	}
	if _, err = advance(status, Transition{Event: EventApplied}); err == nil {
		return errors.New("unchanged rejected content became applied")
	}

	redelivered, err := advance(status, Transition{Event: EventAccepted, Version: v1, AtMS: start.Add(time.Minute).UnixMilli()})
	if err != nil || !reflect.DeepEqual(redelivered, status) {
		return fmt.Errorf("same rejected version was not idempotent: got (%+v, %v), want %+v", redelivered, err, status)
	}
	status, err = advance(status, Transition{Event: EventAccepted, Version: v2, AtMS: start.Add(2 * time.Minute).UnixMilli()})
	if err != nil || status.State != protocol.ObjectPending || status.SinceVersion != v2 || status.IssueCode != "" || status.FirstFailedAtMS != start.Add(2*time.Minute).UnixMilli() {
		return fmt.Errorf("new content did not reopen convergence: got (%+v, %v)", status, err)
	}

	pendingIssue, err := timeoutFor(status, start.Add(2*time.Minute+time.Hour), time.Hour)
	if err != nil || pendingIssue == nil || pendingIssue.Code != protocol.IssueObjectPendingTimeout {
		return fmt.Errorf("pending timeout = (%+v, %v), want %s", pendingIssue, err, protocol.IssueObjectPendingTimeout)
	}
	status, err = advance(status, Transition{Event: EventRejected, AtMS: start.Add(3 * time.Minute).UnixMilli(), IssueCode: "invalid_credentials"})
	if err != nil {
		return fmt.Errorf("reject second version: %w", err)
	}
	rejectedIssue, err := timeoutFor(status, start.Add(2*time.Minute+time.Hour), time.Hour)
	if err != nil || rejectedIssue == nil || rejectedIssue.Code != protocol.IssueObjectRejectedTimeout {
		return fmt.Errorf("rejected timeout = (%+v, %v), want %s", rejectedIssue, err, protocol.IssueObjectRejectedTimeout)
	}

	status, err = advance(protocol.ObjectStatus{
		Stream:       protocol.StreamRoster,
		Key:          "cli_7",
		State:        protocol.ObjectApplied,
		SinceVersion: v2,
	}, Transition{Event: EventDependencyBlocked, AtMS: start.UnixMilli(), BlockedOn: "lst_9"})
	if err != nil || status.State != protocol.ObjectBlocked || status.BlockedOn != "lst_9" {
		return fmt.Errorf("dependency block = (%+v, %v), want blocked", status, err)
	}
	if issue, err := timeoutFor(status, start.Add(24*time.Hour), time.Hour); err != nil || issue != nil {
		return fmt.Errorf("blocked object independently timed out: (%+v, %v)", issue, err)
	}
	status, err = advance(status, Transition{Event: EventDependencyReady})
	if err != nil || status.State != protocol.ObjectPending || status.BlockedOn != "" {
		return fmt.Errorf("dependency recovery = (%+v, %v), want pending", status, err)
	}
	return nil
}

func TestFleetQuotaContract(t *testing.T) {
	if err := fleetQuotaContract(AssessFleetQuota); err != nil {
		t.Fatal(err)
	}
}

func TestFleetQuotaContractRejectsLimitMinusUsageMutation(t *testing.T) {
	mutant := func(in FleetQuotaInput) (FleetQuotaAssessment, error) {
		var reported int64
		for _, row := range in.Rows {
			reported += row.LatestReportedBytes
		}
		// Deliberately wrong twice: this is remaining nominal quota, not the
		// cross-agent residual, and "satisfied" overclaims a stale observation.
		return FleetQuotaAssessment{
			LatestReportedBytes:   reported,
			OverburnHeadroomBytes: in.LimitBytes - reported,
			OldestReportAgeMS:     in.OldestReportAgeMS,
			ReportedLimitPosition: ReportedLimitPosition("satisfied"),
		}, nil
	}
	if err := fleetQuotaContract(mutant); err == nil {
		t.Fatal("fleet quota contract did not detect limit-minus-usage/satisfied mutation")
	}
}

type quotaAssessor func(FleetQuotaInput) (FleetQuotaAssessment, error)

func fleetQuotaContract(assess quotaAssessor) error {
	in := FleetQuotaInput{
		LimitBytes:        500,
		NumeratorAsOfMS:   1_700_000_000_000,
		OldestReportAgeMS: 60_000,
		Rows: []QuotaRow{
			{BaselineBytes: 100, HeadroomBytes: 50, LatestReportedBytes: 120},
			{BaselineBytes: 200, HeadroomBytes: 40, LatestReportedBytes: 210},
		},
	}
	got, err := assess(in)
	if err != nil {
		return fmt.Errorf("assess normal fleet: %w", err)
	}
	if got.LatestReportedBytes != 330 || got.OverburnHeadroomBytes != 60 {
		return fmt.Errorf("assessment = %+v, want reported=330 residual=60", got)
	}
	if got.ReportedLimitPosition != ReportedAtOrBelowLimit {
		return fmt.Errorf("safe wording lost: got position %q", got.ReportedLimitPosition)
	}
	if got.NumeratorAsOfMS != in.NumeratorAsOfMS || got.OldestReportAgeMS != in.OldestReportAgeMS {
		return fmt.Errorf("freshness missing from assessment: %+v", got)
	}

	negative := in
	negative.Rows = []QuotaRow{{BaselineBytes: 100, HeadroomBytes: 10, LatestReportedBytes: 125}}
	negative.LimitBytes = 120
	got, err = assess(negative)
	if err != nil || got.OverburnHeadroomBytes != -15 || got.ReportedLimitPosition != ReportedAboveLimit {
		return fmt.Errorf("passed ceiling = (%+v, %v), want signed residual -15 and reported-above", got, err)
	}
	return nil
}

func TestFleetQuotaRejectsOverflow(t *testing.T) {
	_, err := AssessFleetQuota(FleetQuotaInput{
		LimitBytes: math.MaxInt64,
		Rows:       []QuotaRow{{BaselineBytes: math.MaxInt64, HeadroomBytes: 1}},
	})
	if err == nil {
		t.Fatal("overflowing a quota ceiling must fail instead of wrapping negative")
	}
}

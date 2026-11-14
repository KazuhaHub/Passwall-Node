package agent

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"sync"

	"github.com/KazuhaHub/passwall-node/v4/internal/agent/auditsink"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// AuditSource is where destination-rule hits accumulate between reports.
type AuditSource interface {
	// Take removes everything aggregated, with the counters, which restart.
	Take() auditsink.Taken
	// Return gives back rows (and counters) that were taken and not sent.
	Return(auditsink.Taken)
}

// AuditAttachment is the batch a round proposes to send.
type AuditAttachment struct {
	Observation protocol.AuditObservation
	// Frozen is a batch that was already built and not yet confirmed. It is
	// sent exactly as it was.
	Frozen bool
}

// AuditReporterOptions configures an AuditReporter.
type AuditReporterOptions struct {
	Source AuditSource
	// Warnf receives operator-facing warnings. It is only ever given counts:
	// what a hit names, an account and a destination, is never logged.
	Warnf func(format string, args ...any)
	// NewBatchID, when set, replaces the random 16-byte hex ID.
	NewBatchID func() string
}

// AuditReporterStats are counters of the reporter itself.
type AuditReporterStats struct {
	// InvalidDropped counts batches dropped because they failed validation.
	InvalidDropped uint64
}

// AuditReporter owns the batch that is on its way to the panel.
//
// THE RULE IS ONE BATCH AT A TIME, SENT UNCHANGED UNTIL THE PANEL HAS ANSWERED.
// A batch is frozen with a BatchID when it is first built. Until a validated
// response confirms it, every report carries that same batch byte for byte, and
// nothing new is taken from the source. The alternatives both lose data: if the
// rows of an unconfirmed batch were merged with new events under the old ID,
// the panel, which stored the first request and lost only its answer, would
// discard the second as a duplicate and the new events with it; under a new ID
// the old rows would be counted twice.
//
// Nothing here is durable: a restart loses the batch, which is the price of not
// growing the node's schema.
type AuditReporter struct {
	source     AuditSource
	warnf      func(format string, args ...any)
	newBatchID func() string

	mu      sync.Mutex
	pending *protocol.AuditObservation
	invalid uint64
}

// NewAuditReporter builds an AuditReporter.
func NewAuditReporter(options AuditReporterOptions) (*AuditReporter, error) {
	if options.Source == nil {
		return nil, errors.New("audit source is required")
	}
	reporter := &AuditReporter{source: options.Source, warnf: options.Warnf, newBatchID: options.NewBatchID}
	if reporter.newBatchID == nil {
		reporter.newBatchID = randomBatchID
	}
	return reporter, nil
}

func randomBatchID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// crypto/rand does not fail on a supported platform; a panic here is the
		// agent restarting rather than a batch under a predictable ID.
		panic("audit batch id: " + err.Error())
	}
	return hex.EncodeToString(raw[:])
}

// Pending reports whether a frozen batch is waiting for confirmation.
func (r *AuditReporter) Pending() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pending != nil
}

// Stats returns the reporter's counters.
func (r *AuditReporter) Stats() AuditReporterStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return AuditReporterStats{InvalidDropped: r.invalid}
}

// Prepare returns what the next report should carry: the frozen batch if there
// is one, and otherwise whatever the source holds, as a batch that is not yet
// frozen. Nil means there is nothing to send. Every Prepare that returns a
// batch that is not frozen MUST be followed by Settle.
func (r *AuditReporter) Prepare() *AuditAttachment {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending != nil {
		return &AuditAttachment{Observation: *r.pending, Frozen: true}
	}
	taken := r.source.Take()
	if len(taken.Hits) == 0 && len(taken.Usage) == 0 {
		// An empty batch is never sent. The counters wait for one that is.
		if taken.DroppedHits != 0 || taken.DroppedTrial != 0 || taken.DroppedUsage != 0 || taken.Unmatched != 0 {
			r.source.Return(auditsink.Taken{
				DroppedHits: taken.DroppedHits, DroppedTrial: taken.DroppedTrial,
				DroppedUsage: taken.DroppedUsage, Unmatched: taken.Unmatched,
			})
		}
		return nil
	}
	auditsink.SortHits(taken.Hits)
	sort.SliceStable(taken.Usage, func(i, j int) bool { return taken.Usage[i].Hour < taken.Usage[j].Hour })
	return &AuditAttachment{Observation: protocol.AuditObservation{
		BatchID: r.newBatchID(), Hits: taken.Hits, Usage: taken.Usage,
		DroppedHits: taken.DroppedHits, DroppedTrial: taken.DroppedTrial,
		DroppedUsage: taken.DroppedUsage, Unmatched: taken.Unmatched,
	}}
}

// Settle records what Build did with the attachment, before the report is sent.
// It is also called with a zero BuiltReport when Build failed, which returns
// everything that was taken.
//
//   - A batch that was dropped as invalid is gone, and counted.
//   - A frozen batch stays pending however this round went.
//   - A batch that was not frozen is frozen if it was attached, with whatever
//     rows fitted; the rows that were cut go back to the source, and so does
//     everything if nothing was attached.
func (r *AuditReporter) Settle(attachment *AuditAttachment, built BuiltReport) {
	if attachment == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if built.AuditInvalid {
		r.invalid++
		r.pending = nil
		if r.warnf != nil {
			r.warnf("an audit batch failed validation and was dropped (%d hit rows, %d usage rows); the report was sent without it",
				len(attachment.Observation.Hits), len(attachment.Observation.Usage))
		}
		return
	}
	if attachment.Frozen {
		return
	}
	original := attachment.Observation
	var returned auditsink.Taken
	if sent := built.Report.Audit; sent != nil {
		frozen := *sent
		r.pending = &frozen
		returned.Hits = original.Hits[len(sent.Hits):]
		returned.Usage = original.Usage[len(sent.Usage):]
	} else {
		returned = auditsink.Taken{
			Hits: original.Hits, Usage: original.Usage,
			DroppedHits: original.DroppedHits, DroppedTrial: original.DroppedTrial,
			DroppedUsage: original.DroppedUsage, Unmatched: original.Unmatched,
		}
	}
	if len(returned.Hits) != 0 || len(returned.Usage) != 0 || returned.DroppedHits != 0 ||
		returned.DroppedTrial != 0 || returned.DroppedUsage != 0 || returned.Unmatched != 0 {
		r.source.Return(returned)
	}
}

// Confirm releases the pending batch once the panel has answered a report that
// carried it. The panel counts a repeated batch once and answers it normally, so
// the node drops it on any validated response.
func (r *AuditReporter) Confirm(batchID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending != nil && r.pending.BatchID == batchID {
		r.pending = nil
	}
}

package conformance

import (
	"fmt"
	"math"
)

// QuotaRow is one configured client row in the cross-agent residual.
type QuotaRow struct {
	BaselineBytes       int64
	HeadroomBytes       int64
	LatestReportedBytes int64
}

// FleetQuotaInput is the evidence available at one PSP computation instant.
type FleetQuotaInput struct {
	LimitBytes        int64
	Rows              []QuotaRow
	NumeratorAsOfMS   int64
	OldestReportAgeMS int64
}

// ReportedLimitPosition deliberately describes only the reported numerator.
// It is not a statement that a stale fleet-wide aggregate satisfies a limit.
type ReportedLimitPosition string

const (
	ReportedAtOrBelowLimit ReportedLimitPosition = "reported_at_or_below_limit"
	ReportedAboveLimit     ReportedLimitPosition = "reported_above_limit"
)

// FleetQuotaAssessment exposes the residual and its freshness explicitly. It
// intentionally has no "satisfied" or "compliant" field.
type FleetQuotaAssessment struct {
	LatestReportedBytes   int64
	OverburnHeadroomBytes int64
	NumeratorAsOfMS       int64
	OldestReportAgeMS     int64
	ReportedLimitPosition ReportedLimitPosition
}

// AssessFleetQuota computes:
//
//	sum(baseline + headroom) - sum(latest reported counter)
//
// using checked arithmetic. The result may be negative when the latest report
// has already passed the last authorised ceiling; it must not be clamped,
// because the signed residual is operational evidence.
func AssessFleetQuota(in FleetQuotaInput) (FleetQuotaAssessment, error) {
	if in.LimitBytes < 0 || in.NumeratorAsOfMS < 0 || in.OldestReportAgeMS < 0 {
		return FleetQuotaAssessment{}, fmt.Errorf("limit, timestamps, and ages must be non-negative")
	}

	var ceilings int64
	var reported int64
	for i, row := range in.Rows {
		if row.BaselineBytes < 0 || row.HeadroomBytes < 0 || row.LatestReportedBytes < 0 {
			return FleetQuotaAssessment{}, fmt.Errorf("quota row %d contains a negative byte count", i)
		}
		ceiling, ok := checkedAdd(row.BaselineBytes, row.HeadroomBytes)
		if !ok {
			return FleetQuotaAssessment{}, fmt.Errorf("quota row %d ceiling overflows int64", i)
		}
		if ceilings, ok = checkedAdd(ceilings, ceiling); !ok {
			return FleetQuotaAssessment{}, fmt.Errorf("fleet ceiling overflows int64")
		}
		if reported, ok = checkedAdd(reported, row.LatestReportedBytes); !ok {
			return FleetQuotaAssessment{}, fmt.Errorf("fleet reported counter overflows int64")
		}
	}

	residual, ok := checkedSub(ceilings, reported)
	if !ok {
		return FleetQuotaAssessment{}, fmt.Errorf("fleet residual overflows int64")
	}
	position := ReportedAtOrBelowLimit
	if reported > in.LimitBytes {
		position = ReportedAboveLimit
	}
	return FleetQuotaAssessment{
		LatestReportedBytes:   reported,
		OverburnHeadroomBytes: residual,
		NumeratorAsOfMS:       in.NumeratorAsOfMS,
		OldestReportAgeMS:     in.OldestReportAgeMS,
		ReportedLimitPosition: position,
	}, nil
}

func checkedAdd(a, b int64) (int64, bool) {
	if b > 0 && a > math.MaxInt64-b {
		return 0, false
	}
	return a + b, true
}

func checkedSub(a, b int64) (int64, bool) {
	if b > 0 && a < math.MinInt64+b {
		return 0, false
	}
	return a - b, true
}

package manage

import (
	"encoding/json"
	"fmt"
	"io"
)

// WriteDoctorJSON emits the report as a single JSON document.
//
// ONE DOCUMENT AND NOTHING ELSE on the stream, so a caller can pipe stdout
// straight into a parser. Diagnostics from the caller go to stderr; a command
// that mixed the two would produce output no JSON parser accepts and no human
// wants to read.
func WriteDoctorJSON(w io.Writer, report DoctorReport) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("encode doctor report: %w", err)
	}
	return nil
}

// WriteDoctorText renders the same results for a person.
//
// IT COMES FROM THE SAME SLICE AS THE JSON, deliberately. Two renderers over one
// result set can disagree about what was found; two renderers over a shared
// result set can only disagree about formatting, which is a problem worth
// having.
func WriteDoctorText(w io.Writer, report DoctorReport) error {
	if _, err := fmt.Fprintf(w, "passwall-node doctor (schema %d)\n", report.SchemaVersion); err != nil {
		return err
	}
	if report.Host == nil {
		if _, err := fmt.Fprintf(w, "host: not collected on this platform\n"); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(w, "host: %s, scope %s/%s, cgroup v%d, %d interfaces\n",
			report.Host.Platform.OS+" "+report.Host.Platform.Arch,
			report.Host.Scope.Deployment, report.Host.Scope.ResourceScope,
			report.Host.Scope.CgroupVersion, len(report.Host.Network.Interfaces)); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	failures := 0
	for _, check := range report.Checks {
		if check.Status == DoctorFailed {
			failures++
		}
		// The status is padded so a column of codes and a column of outcomes can
		// be scanned independently, which is how this output is actually read.
		if _, err := fmt.Fprintf(w, "  %-11s %-32s %s\n", check.Status, check.Code, check.Summary); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	switch failures {
	case 0:
		_, err := fmt.Fprintf(w, "%d checks, none failed\n", len(report.Checks))
		return err
	case 1:
		_, err := fmt.Fprintf(w, "%d checks, 1 failed\n", len(report.Checks))
		return err
	default:
		_, err := fmt.Fprintf(w, "%d checks, %d failed\n", len(report.Checks), failures)
		return err
	}
}

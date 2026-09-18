package nodeevent

import "github.com/KazuhaHub/passwall-node/protocol"

// Recorder is where a component reports something it observed about itself.
//
// IT IS A LEAF SO EVERY LAYER CAN USE IT. The supervisor, the sync loop and the
// task worker all record, and none of them can import the package that defines
// the ring — that package's handler already imports them. Defining the interface
// here rather than once per consumer keeps the signature from drifting three
// ways.
//
// A NIL RECORDER IS VALID AND RECORDS NOTHING, which is what a build without a
// diagnostic should do rather than inventing an event.
type Recorder interface {
	Record(code string, severity protocol.DiagnosticsSeverity, summary string)
}

// Record is Recorder for a nil receiver, so callers do not each need the guard.
func Record(recorder Recorder, code string, severity protocol.DiagnosticsSeverity, summary string) {
	if recorder == nil {
		return
	}
	recorder.Record(code, severity, summary)
}

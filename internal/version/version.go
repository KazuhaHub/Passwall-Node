// Package version exposes build identity stamped by the release workflow.
package version

var (
	Version   = "dev"
	Commit    = ""
	BuildDate = ""
)

func String() string {
	if Commit == "" {
		return Version
	}
	return Version + " (" + Commit + ")"
}

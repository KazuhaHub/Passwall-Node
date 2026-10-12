//go:build !linux

package manage

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestNonLinuxManagementRefusesMutationsAndKeepsVersionAvailable(t *testing.T) {
	for _, args := range [][]string{nil, {"connect"}, {"rebind"}, {"repair"}, {"backup"}, {"status"}, {"doctor"}, {"help"}, {"version", "extra"}} {
		a, output, runner := newTestApp(t, "")
		before, err := os.ReadFile(a.paths.unit)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.run(args); err == nil || !strings.Contains(err.Error(), "Linux/systemd") {
			t.Fatal("non-Linux management must refuse before entering command handling")
		}
		after, err := os.ReadFile(a.paths.unit)
		if err != nil || !bytes.Equal(before, after) || len(runner.calls) != 0 || output.Len() != 0 {
			t.Fatal("non-Linux refusal must not mutate the fixture or call service tools")
		}
		for _, path := range []string{a.paths.credential, a.paths.environment, a.paths.state, a.paths.pnLink} {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatal("non-Linux refusal must not create identity or management files")
			}
		}
	}
	for _, argument := range []string{"version", "--version"} {
		a, output, runner := newTestApp(t, "")
		if err := a.run([]string{argument}); err != nil || output.Len() == 0 || len(runner.calls) != 0 {
			t.Fatal("non-Linux version must remain available without service tools")
		}
	}
}

package upgrade

import (
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func upgradeTask(args string) protocol.Task {
	task := protocol.Task{ID: "upgrade-test", Kind: TaskKind, Args: []byte(args), NotAfterMS: 2000}
	task.InputSHA256 = protocol.ComputeTaskInputSHA256(task.Kind, task.Args)
	return task
}

// THE TARGET IS AN EXACT RELEASE; THE VERSION IT REPLACES IS WHATEVER THE NODE
// SAYS IT IS.
//
// The agent compares that second field against its own compiled version — see
// client.go — so it is an IDENTITY rather than something to be parsed, and the
// shapes this refused are the ones a node in the field reports about itself. It
// required a product version here once, which made a node still reporting a stamp
// from the replaced scheme (`v0.0.1-beta9`) impossible to move: the panel could
// not create the task, so nothing ever reached the node.
func TestUpgradeInputRequiresExactIdentityBoundRelease(t *testing.T) {
	for _, input := range []string{
		`{"version":"latest","expected_version":"4.1.0"}`,
		// A NO-OP IS REFUSED BY IDENTITY. There is no ordering rule any more, so
		// this is the only thing left that the pair itself can be wrong about.
		`{"version":"4.1.0","expected_version":"4.1.0"}`,
		`{"version":"4.1.1","expected_version":"4.1.0","url":"https://evil.test"}`,
		`{"version":"4.1.1","expected_version":"4.1.0"} {}`,
		`{"version":"4.1.1-01","expected_version":"4.1.0"}`,
		`{"Version":"4.1.1","expected_version":"4.1.0"}`,
		`{"version":"4.1.1","version":"4.1.2","expected_version":"4.1.0"}`,
		`{"version":"4.1.1"}`,
	} {
		if _, err := ParseArgs(upgradeTask(input)); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
	for _, input := range []string{
		`{"version":"4.1.1","expected_version":"4.1.0"}`,
		// THE POINT OF DROPPING THE TWO RULES: a node on the replaced scheme.
		`{"version":"4.1.1","expected_version":"v0.0.1-beta9"}`,
		`{"version":"4.1.1","expected_version":"v0.0.1-beta12"}`,
		// AND NOT-NEWER IS NO LONGER A REFUSAL. An operator choosing an older
		// release is making an explicit choice; what stops it installing something
		// else is the signed manifest and the binary's own version check.
		`{"version":"4.0.6","expected_version":"4.1.0"}`,
	} {
		if _, err := ParseArgs(upgradeTask(input)); err != nil {
			t.Fatalf("refused %s: %v", input, err)
		}
	}
	task := upgradeTask(`{"version":"4.1.1","expected_version":"4.1.0"}`)
	if _, err := ParseArgs(task); err != nil {
		t.Fatal(err)
	}
	task.NotAfterMS = 0
	if _, err := ParseArgs(task); err == nil {
		t.Fatal("accepted missing deadline")
	}
	task.NotAfterMS = 2000
	task.InputSHA256 = "bad"
	if _, err := ParseArgs(task); err == nil {
		t.Fatal("accepted corrupt identity")
	}
}

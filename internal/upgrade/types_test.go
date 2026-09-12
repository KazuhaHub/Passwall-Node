package upgrade

import (
	"github.com/KazuhaHub/passwall-node/protocol"
	"testing"
)

func upgradeTask(args string) protocol.Task {
	task := protocol.Task{ID: "upgrade-test", Kind: TaskKind, Args: []byte(args), NotAfterMS: 2000}
	task.InputSHA256 = protocol.ComputeTaskInputSHA256(task.Kind, task.Args)
	return task
}

func TestUpgradeInputRequiresExactNewerIdentityBoundRelease(t *testing.T) {
	for _, input := range []string{
		`{"version":"latest","expected_version":"v1.0.0"}`,
		`{"version":"v1.0.0","expected_version":"v1.0.0"}`,
		`{"version":"v1.0.0-beta.1","expected_version":"v1.0.0"}`,
		`{"version":"v1.0.1","expected_version":"v1.0.0","url":"https://evil.test"}`,
		`{"version":"v1.0.1","expected_version":"v1.0.0"} {}`,
		`{"version":"v1.0.1-01","expected_version":"v1.0.0"}`,
		`{"Version":"v1.0.1","expected_version":"v1.0.0"}`,
		`{"version":"v1.0.1","version":"v1.0.2","expected_version":"v1.0.0"}`,
	} {
		if _, err := ParseArgs(upgradeTask(input)); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
	task := upgradeTask(`{"version":"v1.0.1","expected_version":"v1.0.0"}`)
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

func TestUpgradeVersionOrder(t *testing.T) {
	versions := []string{"v0.0.1-beta1", "v0.0.1-beta2", "v0.0.1-beta3", "v0.0.1", "v0.0.2-alpha.1", "v0.0.2-alpha.2", "v0.0.2-alpha.10", "v0.0.2-beta.1", "v0.0.2", "v1.0.0", "v10.0.0", "v9999999999999999999999.0.0"}
	for i, a := range versions {
		for j, b := range versions {
			c := CompareVersions(a, b)
			if i == j && c != 0 || i < j && c >= 0 || i > j && c <= 0 {
				t.Fatalf("order %s %s = %d", a, b, c)
			}
		}
	}
}

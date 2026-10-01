package upgrade

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// A SUCCESSOR IS ITS PREDECESSOR'S CONFIGURATION ON A NEWER IMAGE, so the names
// that configuration refers to are permanent.
//
// CreateReplacement copies the predecessor's Config verbatim — its Entrypoint, its
// Cmd and its environment — and changes only the image. The agent swap has always
// depended on the same thing for the agent. A release that moved the entrypoint
// script, renamed the helper's command or renamed one of the four variables the
// helper reads its identity from would therefore start, as a successor, a
// container whose stored command its own image no longer understands: the
// successor would fail to start and every handover onto that release would abort,
// and an agent swap onto it would leave a container that cannot run. These are
// pinned where each one lives: the Dockerfiles that put the script and the binary
// in place, the script's dispatch, the daemon's own dispatch, and the constants the
// helper reads.
func TestImageEntrypointAndHelperCommandArePermanent(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		raw, err := os.ReadFile("../../" + path)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	const entrypoint = "/usr/local/bin/docker-entrypoint.sh"
	if dockerHelperCommand != "--run-docker-upgrade-helper" || dockerTargetContainerEnv != "PSP_NODE_UPGRADE_TARGET_CONTAINER" ||
		dockerTargetAgentIDEnv != "PSP_NODE_UPGRADE_TARGET_AGENT_ID" || DockerBinaryPath != "/usr/local/bin/passwall-node" {
		t.Fatal("the helper's command, its identity variables or its binary path changed; every updater already deployed stores the old ones")
	}
	for _, path := range []string{"Dockerfile", "Dockerfile.release"} {
		text := read(path)
		for _, required := range []string{
			"\nENTRYPOINT [\"" + entrypoint + "\"]\n",
			"\nCOPY docker-entrypoint.sh " + entrypoint + "\n",
			" " + DockerBinaryPath + "\n",
			"    PUID=10001 \\\n",
			"    PGID=10001\n",
		} {
			if !strings.Contains(text, required) {
				t.Errorf("%s no longer has %q", path, strings.TrimSpace(required))
			}
		}
	}
	// THE SCRIPT HANDS THE HELPER COMMAND TO THE BINARY, AS ROOT, untouched.
	script := read("docker-entrypoint.sh")
	arm := regexp.MustCompile(`(?m)^    ` + regexp.QuoteMeta(dockerHelperCommand) + `\)\n(?:        .*\n)*?        exec ` + regexp.QuoteMeta(DockerBinaryPath) + ` "\$1"\n        ;;$`)
	if !arm.MatchString(script) {
		t.Errorf("docker-entrypoint.sh no longer execs %s for %s", DockerBinaryPath, dockerHelperCommand)
	}
	if !strings.Contains(read("cmd/node/main.go"), "\t\tcase \""+dockerHelperCommand+"\":\n") {
		t.Errorf("the daemon no longer dispatches %s", dockerHelperCommand)
	}
	// AND THE HELPER READS ITS IDENTITY UNDER THESE NAMES.
	helper := read("internal/upgrade/docker_helper.go")
	for _, required := range []string{
		"os.Getenv(dockerTargetContainerEnv)", "os.Getenv(dockerTargetAgentIDEnv)",
		`os.Getenv("PUID")`, `os.Getenv("PGID")`,
	} {
		if !strings.Contains(helper, required) {
			t.Errorf("RunDockerHelper no longer reads %s", required)
		}
	}
}

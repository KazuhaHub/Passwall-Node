package deployment

import (
	"os"
	"strings"
	"testing"
)

// THE EXAMPLE COMPOSE HAS TO SATISFY THE CONTAINER IT DESCRIBES.
//
// It drops every capability and then grants back only the ones the entrypoint
// needs, which makes the list a claim about a shell script — and a claim nothing
// checked. The entrypoint chowns the runtime directory to the service account and
// then chmods it; that directory is a tmpfs mount, so it is root-owned and the
// process doing the chmod is NOT the owner, which needs CAP_FOWNER. Without it the
// container starts, reports that it cannot protect its runtime directory, and
// restarts forever — which is how this was found, on a host running a compose the
// panel generated with the same list.
func TestTheExampleComposeGrantsWhatItsEntrypointNeeds(t *testing.T) {
	entrypoint, err := os.ReadFile("../docker-entrypoint.sh")
	if err != nil {
		t.Fatal(err)
	}
	example, err := os.ReadFile("../compose.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	script, compose := string(entrypoint), string(example)

	// THE NEEDS ARE READ FROM THE SCRIPT RATHER THAN LISTED HERE, so this stays a
	// claim about the pair rather than a second copy of the entrypoint's behaviour.
	required := map[string]string{
		"chmod ":    "FOWNER", // a chmod on a path this process does not own
		"chown ":    "CHOWN",
		"su-exec ":  "SETUID", // the privilege drop re-executes as another user
		"su-exec -": "SETGID",
	}
	for command, capability := range required {
		if !strings.Contains(script, command) {
			continue // the entrypoint no longer does this, so the capability is not owed
		}
		if !grantsCapability(compose, capability) {
			t.Errorf("the entrypoint runs %q, which needs CAP_%s, and the example compose does not grant it", strings.TrimSpace(command), capability)
		}
	}
	// AND THE DROP ITSELF STILL HAPPENS: an example that granted everything and ran
	// as root would satisfy the loop above and be the opposite of the point.
	if !strings.Contains(compose, "cap_drop:") || !strings.Contains(compose, "- ALL") {
		t.Error("the example compose no longer drops every capability first")
	}
}

// grantsCapability reports whether a compose file grants exactly this capability
// under cap_add. Written as a scan rather than a YAML decode because the file is
// read as text everywhere else here, and the failure this guards is a list that
// drifted rather than a document that malformed.
func grantsCapability(compose, capability string) bool {
	inAdd := false
	for _, line := range strings.Split(compose, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "cap_add:"):
			inAdd = true
		case inAdd && strings.HasPrefix(trimmed, "- "):
			if strings.TrimPrefix(trimmed, "- ") == capability {
				return true
			}
		case inAdd && trimmed != "" && !strings.HasPrefix(trimmed, "#"):
			inAdd = false
		}
	}
	return false
}

// AND THE ORDER MATTERS AS MUCH AS THE LIST.
//
// The capability check above is derived from the COMMANDS the entrypoint runs, and it
// cannot see the difference between two orderings of the same commands — but there is
// one ordering that needs a capability the compose deliberately withholds. Dropping all
// capabilities and granting back four leaves root without CAP_DAC_OVERRIDE, so a
// directory it has chowned to the service account with mode 0700 is one it can no
// longer stat or write into. This entrypoint did exactly that: it handed the runtime
// directory to PUID and then copied the credential into it, which fails on every start
// with
//
//	cp: can't stat '/run/passwall-node/credential': Permission denied
//
// and restarts the container forever. The same reasoning applies to the credential
// file: once it belongs to the service account, root cannot overwrite it either, so it
// has to be removed rather than written over.
func TestTheEntrypointDoesNotGiveAwayAPathItStillHasToWrite(t *testing.T) {
	entrypoint, err := os.ReadFile("../docker-entrypoint.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(entrypoint)

	if strings.Contains(script, `chown "$PUID:$PGID" /run/passwall-node`) {
		t.Error("the entrypoint gives the runtime directory to the service account and then has to write in it, which needs CAP_DAC_OVERRIDE — a capability the compose deliberately does not grant")
	}
	if !strings.Contains(script, "chmod 0711 /run/passwall-node") {
		t.Error("the runtime directory must stay root's and stay traversable: the agent reads the credential through it")
	}
	remove := strings.Index(script, `rm -f "$CREDENTIAL_FILE"`)
	copy := strings.Index(script, `cp "$SECRET_SOURCE" "$CREDENTIAL_FILE"`)
	if remove < 0 || copy < 0 {
		t.Fatalf("the entrypoint no longer clears (%v) or copies (%v) the credential; this guard is describing a script that changed shape", remove >= 0, copy >= 0)
	}
	if remove > copy {
		t.Error("the credential must be removed before it is copied: a file the service account owns cannot be overwritten by root either")
	}
}

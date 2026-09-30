package deployment

import (
	"os"
	"slices"
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
	// THE AGENT'S OWN BLOCK, NOT THE FILE. The updater grants CHOWN and FOWNER back
	// too, for its own reasons, so a scan of the whole file would be satisfied by the
	// updater's list after either were dropped from the agent's.
	script, compose := string(entrypoint), composeService(t, string(example), "passwall-node")

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
	// DAC_OVERRIDE IS OWED BY A FILE THE SCRIPT READS, NOT BY A COMMAND IT RUNS, so
	// the loop above cannot see it and it is asserted here instead. The deployment
	// instructions chmod 0600 the credential, which on a NAS leaves it owned by the
	// account that ran the install rather than by uid 0: container root is then neither
	// the owner nor "other", and the copy fails with
	//
	//	cp: can't open '/run/secrets/passwall-node/node-credential.txt': Permission denied
	//
	// on every start. Found the same way the FOWNER one was — in a user's container log
	// after a generated compose was applied.
	if !grantsCapability(compose, "DAC_OVERRIDE") {
		t.Error("the entrypoint reads a credential that belongs to the installing account, which needs CAP_DAC_OVERRIDE; without it the container copies nothing and restarts forever")
	}
	// AND THE DROP ITSELF STILL HAPPENS: an example that granted everything and ran
	// as root would satisfy the loop above and be the opposite of the point.
	if !slices.Contains(composeList(compose, "cap_drop"), "ALL") {
		t.Error("the example compose no longer drops every capability first")
	}
}

// THE UPDATER IS ROOT WITHOUT ROOT'S PERMISSION BYPASS, AND IT STILL HAS TO DO ITS JOB.
//
// Its service drops every capability, like the agent's, and until now granted none
// back — a list nothing had checked, because CI starts the example's agent alone
// (`up -d --no-deps passwall-node`). Without CAP_DAC_OVERRIDE, uid 0 is held to the
// ordinary permission bits, and the helper crosses three of them on its way to
// writing its first heartbeat:
//
//   - every file it writes is chowned to PGID so the agent can read it
//     (atomicHelperFile's fchown), and root is not a member of that group, which
//     needs CAP_CHOWN;
//   - it re-asserts mode 0700 on requests/, which belongs to PUID, on every start
//     (prepareControl), and a chmod by a process that does not own the path needs
//     CAP_FOWNER;
//   - it reads the agent's request.json out of that same 0700 directory, which
//     needs CAP_DAC_READ_SEARCH — search and read, and nothing that writes, since
//     the helper never writes there.
//
// EXACTLY THESE, AND NOTHING ELSE. This container holds the Docker socket, so a
// capability added here to make something start is one given to the most
// privileged process on the host. A change to the list is a change to this test.
//
// AND NO NETWORK. It talks to the Engine over a unix socket and to the agent through
// a directory; the daemon, not the updater, is what fetches an image. The README
// already calls it network-disabled, and the service is what makes that true.
func TestTheExampleUpdaterGrantsWhatTheHelperNeeds(t *testing.T) {
	example, err := os.ReadFile("../compose.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	updater := composeService(t, string(example), "passwall-node-updater")

	if drop := composeList(updater, "cap_drop"); !slices.Equal(drop, []string{"ALL"}) {
		t.Errorf("the example updater drops %q, want every capability dropped first", drop)
	}
	add := composeList(updater, "cap_add")
	slices.Sort(add)
	if want := []string{"CHOWN", "DAC_READ_SEARCH", "FOWNER"}; !slices.Equal(add, want) {
		t.Errorf("the example updater grants %q back, want exactly %q", add, want)
	}
	if !slices.Contains(composeList(updater, "security_opt"), "no-new-privileges:true") {
		t.Error("the example updater no longer runs under no-new-privileges")
	}
	if !slices.Contains(strings.Split(updater, "\n"), "    network_mode: none") {
		t.Error("the example updater is not network-disabled: it needs no network, and holds the Docker socket")
	}
}

// composeService returns one service's block of a compose text: its own line and
// every line indented under it, blank lines included. The file is read as text
// everywhere else here, so the service boundary is read the same way.
func composeService(t *testing.T, compose, name string) string {
	t.Helper()
	lines := strings.Split(compose, "\n")
	start := slices.Index(lines, "  "+name+":")
	if start < 0 {
		t.Fatalf("the compose has no service %q", name)
	}
	end := start + 1
	for end < len(lines) && (strings.TrimSpace(lines[end]) == "" || strings.HasPrefix(lines[end], "    ")) {
		end++
	}
	return strings.Join(lines[start:end], "\n")
}

// grantsCapability reports whether a compose text grants exactly this capability
// under cap_add.
func grantsCapability(compose, capability string) bool {
	return slices.Contains(composeList(compose, "cap_add"), capability)
}

// composeList returns the items of every block-style `key:` list in a compose
// text, in order. Written as a scan rather than a YAML decode because the file is
// read as text everywhere else here, and the failure this guards is a list that
// drifted rather than a document that malformed. A comment line inside a list does
// not end it; an item carrying a trailing comment is read with the comment.
func composeList(compose, key string) []string {
	var items []string
	in := false
	for _, line := range strings.Split(compose, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, key+":"):
			in = true
		case in && strings.HasPrefix(trimmed, "- "):
			items = append(items, strings.TrimPrefix(trimmed, "- "))
		case in && trimmed != "" && !strings.HasPrefix(trimmed, "#"):
			in = false
		}
	}
	return items
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
	// THE DIRECTORY IS ALSO TAKEN BACK FIRST. The image builds it owned by the service
	// account and the compose hides that with a tmpfs; a container started from the
	// image without that mount finds the service account's directory instead, where
	// root without CAP_DAC_OVERRIDE is "other" and cannot create a file at all.
	takeBack := strings.Index(script, "chown 0:0 /run/passwall-node")
	chmodDir := strings.Index(script, "chmod 0711 /run/passwall-node")
	copyCred := strings.Index(script, `cp "$SECRET_SOURCE" "$CREDENTIAL_FILE"`)
	if takeBack < 0 || chmodDir < 0 || copyCred < 0 || takeBack > chmodDir || chmodDir > copyCred {
		t.Error("the entrypoint must take the runtime directory back to root before handing it a mode and copying into it, whatever the image layer or the mount left behind")
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

// THE CONTAINER JOB STARTS THE EXAMPLE ITSELF, AND ITS OVERRIDE SWAPS ONLY WHAT CI
// MUST.
//
// The runtime check used to carry a hand copy of part of the example, and the part
// it left out (the read-only root, the tmpfs runtime directory, no-new-privileges,
// the updater's marker) was never started by anything before a user did. It now
// starts compose.example.yaml with a small override, and the override is where a
// hand copy could creep back: a key added there to make CI pass replaces the
// example's own and proves the example no longer. So the override may name the
// image and the stand-in binary's mount, and nothing else.
func TestTheContainerJobStartsTheExampleCompose(t *testing.T) {
	raw, err := os.ReadFile("../.github/workflows/test.yml")
	if err != nil {
		t.Fatal(err)
	}
	job := workflowJob(t, string(raw), "container")
	for _, required := range []string{
		"-f compose.example.yaml -f \"$RUNNER_TEMP/compose.ci.yaml\"",
		"up -d --no-deps passwall-node",
		"docker build --file Dockerfile.release",
	} {
		if !strings.Contains(job, required) {
			t.Errorf("the container job no longer runs %s", required)
		}
	}
	const opening, closing = "cat > \"$RUNNER_TEMP/compose.ci.yaml\" <<YAML\n", "\n          YAML\n"
	start := strings.Index(job, opening)
	if start < 0 {
		t.Fatal("the container job writes no compose override this guard can find")
	}
	end := strings.Index(job[start:], closing)
	if end < 0 {
		t.Fatal("the compose override has no end this guard can find")
	}
	allowed := map[string]bool{"services:": true, "passwall-node:": true, "image: passwall-node:release": true, "volumes:": true, "- $RUNNER_TEMP/fake-node:/usr/local/bin/passwall-node:ro": true}
	for _, line := range strings.Split(job[start+len(opening):start+end], "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" && !allowed[trimmed] {
			t.Errorf("the CI override sets %q, which replaces the example's own setting instead of starting it", trimmed)
		}
	}
}

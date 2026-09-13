package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/KazuhaHub/passwall-node/internal/testutil/nodefixture"
)

const fixturePath = nodefixture.Path

type fixtureObservation = nodefixture.Observation
type controlPlaneFixture struct {
	*nodefixture.Fixture
	agentID, credential string
}

func newControlPlaneFixture(agentID, credential string) (*controlPlaneFixture, error) {
	f, err := nodefixture.New(agentID, credential)
	if err != nil {
		return nil, err
	}
	return &controlPlaneFixture{Fixture: f, agentID: agentID, credential: credential}, nil
}
func (f *controlPlaneFixture) snapshot() fixtureObservation { return f.Snapshot() }
func (f *controlPlaneFixture) beginReinstall()              { f.BeginReinstall() }
func startFixture(f *controlPlaneFixture) (*http.Server, string, []byte, error) {
	return nodefixture.Start(f.Fixture)
}

// Captured installer output is private and must never be included in errors or
// logs. Only successful assertion counts/booleans reach the acceptance summary.
func checkInstallerFeedback(output []byte, offline bool) error {
	previous := -1
	for number := 1; number <= 6; number++ {
		marker := []byte(fmt.Sprintf("Passwall Node [%d/6] ", number))
		index := bytes.Index(output, marker)
		if bytes.Count(output, marker) != 1 || index <= previous {
			return errors.New("installer feedback omitted or reordered a required phase; private output withheld")
		}
		previous = index
	}
	text := string(output)
	for _, notice := range []string{
		"Agent startup confirmed only.",
		"PSP sync, core and proxy readiness are not confirmed by this installer.",
		"verify the server connection, core state and configured nodes in PSP, then test proxy traffic.",
	} {
		if !strings.Contains(text, notice) {
			return errors.New("installer feedback omitted a startup-only notice or next verification step; private output withheld")
		}
	}
	for _, path := range []struct {
		offline bool
		tokens  []string
	}{
		{true, []string{
			"Matching installation retained; download skipped (offline rerun)",
			"Existing exact release retained; checksum download not repeated",
		}},
		{false, []string{
			"Download exact release ", "Downloading checksum manifest...",
			"Downloading release archive...", "Verify checksum, archive members and executable version",
		}},
	} {
		for _, token := range path.tokens {
			if strings.Contains(text, token) != (offline == path.offline) {
				return errors.New("installer feedback did not match fresh-download versus offline-retention behavior; private output withheld")
			}
		}
	}
	return nil
}

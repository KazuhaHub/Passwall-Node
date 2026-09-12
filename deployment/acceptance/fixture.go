package main

import (
	"github.com/KazuhaHub/passwall-node/internal/testutil/nodefixture"
	"net/http"
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

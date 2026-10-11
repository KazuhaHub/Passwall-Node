package main

import (
	"strings"
	"testing"
)

func TestCheckRequiresPrivateUsageTrafficEvidence(t *testing.T) {
	var old []testEvent
	for _, event := range passingEvents() {
		if strings.Contains(event.Package, "/cmd/node") {
			continue
		}
		old = append(old, event)
	}
	if err := checkResults(eventStream(t, old)); err == nil {
		t.Fatal("real-core acceptance passed without private usage traffic evidence")
	}
}

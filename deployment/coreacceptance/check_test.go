package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func passingEvents() []testEvent {
	var events []testEvent
	packages := make(map[string]bool)
	for _, identity := range requiredTests {
		events = append(events, testEvent{Action: "run", Package: identity.Package, Test: identity.Test})
		events = append(events, testEvent{Action: "pass", Package: identity.Package, Test: identity.Test})
		packages[identity.Package] = true
	}
	for name := range packages {
		events = append(events, testEvent{Action: "pass", Package: name})
	}
	return events
}

func eventStream(t *testing.T, events []testEvent) *bytes.Buffer {
	t.Helper()
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	return &buffer
}

func TestCheckRequiresEveryExecutableLeafAndPackage(t *testing.T) {
	if err := checkResults(eventStream(t, passingEvents())); err != nil {
		t.Fatal(err)
	}
	for index, identity := range requiredTests {
		t.Run(identity.Test, func(t *testing.T) {
			events := passingEvents()
			events = append(events[:2*index], events[2*index+2:]...)
			if err := checkResults(eventStream(t, events)); err == nil {
				t.Fatal("missing executable evidence passed")
			}
		})
	}
	for _, name := range []string{"install", "xray", "singbox"} {
		t.Run("missing-package-"+name, func(t *testing.T) {
			var filtered []testEvent
			for _, event := range passingEvents() {
				if event.Package != module+name || event.Test != "" {
					filtered = append(filtered, event)
				}
			}
			if err := checkResults(eventStream(t, filtered)); err == nil {
				t.Fatal("missing package result passed")
			}
		})
	}
}

func TestCheckRejectsSkippedFailedCachedDuplicateAndMalformedEvidence(t *testing.T) {
	for _, action := range []string{"skip", "fail", "build-fail"} {
		t.Run(action, func(t *testing.T) {
			events := append(passingEvents(), testEvent{Action: action, Package: module + "singbox", Test: "another-gate"})
			if err := checkResults(eventStream(t, events)); err == nil {
				t.Fatal("non-passing event accepted")
			}
		})
	}
	t.Run("cached-pass-without-run", func(t *testing.T) {
		events := passingEvents()[1:]
		if err := checkResults(eventStream(t, events)); err == nil {
			t.Fatal("pass without run accepted")
		}
	})
	t.Run("cached-event-replay", func(t *testing.T) {
		events := append(passingEvents(), testEvent{Action: "output", Package: module + "install", Output: "ok  package (cached)\n"})
		if err := checkResults(eventStream(t, events)); err == nil {
			t.Fatal("cached run/pass replay accepted")
		}
	})
	t.Run("duplicate-run", func(t *testing.T) {
		events := passingEvents()
		events = append(events[:1], append([]testEvent{events[0]}, events[1:]...)...)
		if err := checkResults(eventStream(t, events)); err == nil {
			t.Fatal("duplicate run accepted")
		}
	})
	t.Run("duplicate-pass", func(t *testing.T) {
		events := passingEvents()
		events = append(events, events[1])
		if err := checkResults(eventStream(t, events)); err == nil {
			t.Fatal("duplicate pass accepted")
		}
	})
	for _, input := range []string{"", "not JSON\n", `{"Action":"run"`, "null\n"} {
		if err := checkResults(strings.NewReader(input)); err == nil {
			t.Fatalf("invalid or empty evidence %q accepted", input)
		}
	}
}

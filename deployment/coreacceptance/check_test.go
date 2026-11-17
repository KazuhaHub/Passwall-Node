package main

import (
	"bytes"
	"encoding/json"
	"io"
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
	if err := checkResults(eventStream(t, passingEvents()), requiredTests); err != nil {
		t.Fatal(err)
	}
	for index, identity := range requiredTests {
		t.Run(identity.Test, func(t *testing.T) {
			events := passingEvents()
			events = append(events[:2*index], events[2*index+2:]...)
			if err := checkResults(eventStream(t, events), requiredTests); err == nil {
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
			if err := checkResults(eventStream(t, filtered), requiredTests); err == nil {
				t.Fatal("missing package result passed")
			}
		})
	}
}

func TestCheckRejectsSkippedFailedCachedDuplicateAndMalformedEvidence(t *testing.T) {
	for _, action := range []string{"skip", "fail", "build-fail"} {
		t.Run(action, func(t *testing.T) {
			events := append(passingEvents(), testEvent{Action: action, Package: module + "singbox", Test: "another-gate"})
			if err := checkResults(eventStream(t, events), requiredTests); err == nil {
				t.Fatal("non-passing event accepted")
			}
		})
	}
	t.Run("cached-pass-without-run", func(t *testing.T) {
		events := passingEvents()[1:]
		if err := checkResults(eventStream(t, events), requiredTests); err == nil {
			t.Fatal("pass without run accepted")
		}
	})
	t.Run("cached-event-replay", func(t *testing.T) {
		events := append(passingEvents(), testEvent{Action: "output", Package: module + "install", Output: "ok  package (cached)\n"})
		if err := checkResults(eventStream(t, events), requiredTests); err == nil {
			t.Fatal("cached run/pass replay accepted")
		}
	})
	t.Run("duplicate-run", func(t *testing.T) {
		events := passingEvents()
		events = append(events[:1], append([]testEvent{events[0]}, events[1:]...)...)
		if err := checkResults(eventStream(t, events), requiredTests); err == nil {
			t.Fatal("duplicate run accepted")
		}
	})
	t.Run("duplicate-pass", func(t *testing.T) {
		events := passingEvents()
		events = append(events, events[1])
		if err := checkResults(eventStream(t, events), requiredTests); err == nil {
			t.Fatal("duplicate pass accepted")
		}
	})
	for _, input := range []string{"", "not JSON\n", `{"Action":"run"`, "null\n"} {
		if err := checkResults(strings.NewReader(input), requiredTests); err == nil {
			t.Fatalf("invalid or empty evidence %q accepted", input)
		}
	}
}

func TestCheckRequiresEveryXrayVersionToRunNotSkip(t *testing.T) {
	for _, test := range []string{
		"TestCompilerArtifactPassesPinnedXrayValidation",
		"TestCompilerPolicyArtifactPassesPinnedXrayValidation",
		"TestPolicyEnforcedByRealXray",
		"TestRealXrayCountsUsageByDomainByIPAndThroughAnAllowRule",
		"TestRealXrayCountsAnExemptAccountsUsage",
	} {
		for _, version := range []string{"26.6.27", "26.7.28", "26.9.9"} {
			identity := testIdentity{module + "xray", test + "/" + version}
			t.Run("required-"+identity.Test, func(t *testing.T) {
				found := false
				for _, required := range requiredTests {
					found = found || required == identity
				}
				if !found {
					t.Fatalf("%s is not a required acceptance leaf", identity.Test)
				}
				events := append(passingEvents(), testEvent{Action: "skip", Package: identity.Package, Test: identity.Test})
				if err := checkResults(eventStream(t, events), requiredTests); err == nil {
					t.Fatal("skipped Xray version accepted")
				}
			})
		}
	}
}

// The image profile requires both official installs to have executed inside the
// Node image; a skipped sing-box install there is exactly the regression it
// exists to catch, and the host profile's evidence must not stand in for it.
func TestImageProfileRequiresBothCoresExecuted(t *testing.T) {
	var events []testEvent
	for _, identity := range imageTests {
		events = append(events, testEvent{Action: "run", Package: identity.Package, Test: identity.Test})
		events = append(events, testEvent{Action: "pass", Package: identity.Package, Test: identity.Test})
	}
	events = append(events, testEvent{Action: "pass", Package: imageTests[0].Package})
	if err := checkResults(eventStream(t, events), profiles["image"]); err != nil {
		t.Fatal(err)
	}
	skipped := append([]testEvent(nil), events...)
	skipped[3] = testEvent{Action: "skip", Package: imageTests[1].Package, Test: imageTests[1].Test}
	if err := checkResults(eventStream(t, skipped), profiles["image"]); err == nil {
		t.Fatal("image profile accepted a skipped sing-box install")
	}
	if err := checkResults(eventStream(t, events), profiles["core"]); err == nil {
		t.Fatal("image evidence satisfied the host core profile")
	}
	if err := run([]string{"check", "--profile", "nope", "--results", "/dev/null"}, io.Discard, io.Discard); err == nil {
		t.Fatal("unknown profile accepted")
	}
}

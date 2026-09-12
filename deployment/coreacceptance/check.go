package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

type testIdentity struct{ Package, Test string }

const module = "github.com/KazuhaHub/passwall-node/internal/core/"

// Require the eight executable leaves, plus both parent tests and all three
// package pass events. A cached, missing, renamed or skipped gate cannot pass.
var requiredTests = []testIdentity{
	{module + "install", "TestOfficialXrayInstallIntegration"},
	{module + "install", "TestOfficialSingBoxInstallIntegration"},
	{module + "xray", "TestCompilerArtifactPassesPinnedXrayValidation"},
	{module + "xray", "TestCompilerArtifactPassesPinnedXrayValidation/26.6.27"},
	{module + "singbox", "TestCompilerArtifactPassesPinnedSingBoxValidation"},
	{module + "singbox", "TestDaemonAPIWireCompatibilityWithPinnedSingBox"},
	{module + "singbox", "TestRealityHandshakeMatrix"},
	{module + "singbox", "TestRealityHandshakeMatrix/xray-26.6.27"},
	{module + "singbox", "TestRealityHandshakeMatrix/mihomo-1.19.30"},
	{module + "singbox", "TestRealityHandshakeMatrix/sing-box-1.14.0"},
}

type testEvent struct {
	Action  string
	Package string
	Test    string
	Output  string
}

func checkResults(input io.Reader) error {
	decoder := json.NewDecoder(input)
	runs := make(map[testIdentity]int)
	passes := make(map[testIdentity]int)
	packages := make(map[string]int)
	for {
		var event testEvent
		err := decoder.Decode(&event)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("invalid go test JSON: %w", err)
		}
		// go test -json may replay run/pass events from the result cache. The
		// workflow also uses -count=1; do not mistake a replay for execution.
		if event.Test == "" && strings.Contains(event.Output, "(cached)") {
			return errors.New("cached acceptance package result: " + event.Package)
		}
		identity := testIdentity{event.Package, event.Test}
		switch event.Action {
		case "skip", "fail", "build-fail":
			return fmt.Errorf("non-passing acceptance event %s: %s %s", event.Action, event.Package, event.Test)
		case "run":
			runs[identity]++
		case "pass":
			if event.Test == "" {
				packages[event.Package]++
			} else {
				if runs[identity] != 1 {
					return fmt.Errorf("test passed without exactly one preceding run: %s %s", event.Package, event.Test)
				}
				passes[identity]++
			}
		}
	}
	for _, identity := range requiredTests {
		if runs[identity] != 1 || passes[identity] != 1 {
			return fmt.Errorf("required real test did not run and pass exactly once: %s %s (run=%d pass=%d)", identity.Package, identity.Test, runs[identity], passes[identity])
		}
		if packages[identity.Package] != 1 {
			return errors.New("required acceptance package did not pass exactly once: " + identity.Package)
		}
	}
	return nil
}

package protocol_test

import (
	"testing"

	legacy "github.com/KazuhaHub/passwall-node/v4/protocol"
	current "github.com/KazuhaHub/passwall-protocol/protocol"
)

// This file is mostly a COMPILE-TIME assertion, and that is deliberate: "the two
// import paths give the same types" is not something a runtime test can check
// for a type that fails to be assignable. If a name here stops being an alias —
// if someone copies a struct instead of aliasing it — the assignment below stops
// compiling, which is the failure being guarded against.
//
// The reason it matters: PSP still reaches this module for deployment and
// corecatalog while importing the contract from the new one, so a value can
// cross a boundary where one side speaks the old path and the other the new. Two
// structurally identical but distinct types would make every such crossing a
// compile error, or worse, invite a conversion that silently copies.
func TestTheTwoImportPathsAreInterchangeable(t *testing.T) {
	var fromOld legacy.NodeReport
	// Assignable both ways without a conversion: they are the same type.
	var fromNew current.NodeReport = fromOld
	fromOld = fromNew

	var oldComp legacy.Compatibility = current.Compatibility{}
	var newComp current.Compatibility = oldComp
	_ = newComp

	var oldRange legacy.GenerationRange = current.GenerationRange{Min: 1, Max: 1}
	var newRange current.GenerationRange = oldRange
	_ = newRange

	// Constants and functions travel the same way.
	if legacy.ProtocolVersion1 != current.ProtocolVersion1 {
		t.Fatal("ProtocolVersion1 differs between the two import paths")
	}
	if legacy.MaxSyncBodyBytes != current.MaxSyncBodyBytes {
		t.Fatal("MaxSyncBodyBytes differs between the two import paths")
	}
	oldDigest := legacy.ComputeTaskInputSHA256(legacy.TaskKindAgentUpgradeV1, []byte(`{}`))
	newDigest := current.ComputeTaskInputSHA256(current.TaskKindAgentUpgradeV1, []byte(`{}`))
	if oldDigest != newDigest {
		t.Fatalf("the task input digest differs between the two import paths: %s vs %s", oldDigest, newDigest)
	}
}

// The compatibility layer must expose the WHOLE current surface, not the surface
// that happened to exist when it was generated. A stale alias file is how the
// two paths quietly stop being the same thing.
func TestTheCompatibilityLayerCarriesTheCurrentAPI(t *testing.T) {
	comp := legacy.AssessCompatibilityIn(
		1,
		legacy.AgentUpgradeCapabilities(),
		legacy.GenerationRange{Min: legacy.ProtocolVersion1, Max: legacy.ProtocolVersion1},
	)
	if !comp.ProtocolSupported || !comp.AgentUpgrade {
		t.Fatalf("the compatibility path's assessment disagrees with the contract's: %+v", comp)
	}
	if r := legacy.SupportedGenerationRange(); r.Min == 0 && r.Max == 0 {
		t.Fatalf("SupportedGenerationRange is not wired through the compatibility layer: %+v", r)
	}
}

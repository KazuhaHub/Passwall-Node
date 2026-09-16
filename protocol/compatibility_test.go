package protocol

import (
	"reflect"
	"testing"
)

func TestAssessCompatibilitySeparatesBaseSyncFromOptionalUpgrade(t *testing.T) {
	upgradeCapabilities := AgentUpgradeCapabilities()
	tests := []struct {
		name              string
		reported          int
		capabilities      []string
		effective         int
		protocolSupported bool
		agentUpgrade      bool
		missing           []string
	}{
		{
			name: "legacy omitted version remains v1 sync compatible", reported: 0,
			effective: ProtocolVersion1, protocolSupported: true,
			missing: upgradeCapabilities,
		},
		{
			name: "v1 without optional kind remains sync compatible", reported: ProtocolVersion1,
			capabilities: []string{CapabilityTaskExecutionV1, CapabilityTaskExpiryV1},
			effective:    ProtocolVersion1, protocolSupported: true,
			missing: []string{TaskCapability(TaskKindAgentUpgradeV1)},
		},
		{
			name: "v1 with the complete capability set can upgrade", reported: ProtocolVersion1,
			capabilities: upgradeCapabilities, effective: ProtocolVersion1,
			protocolSupported: true, agentUpgrade: true,
		},
		{
			name: "unreviewed generation fails closed even with capabilities", reported: ProtocolVersion1 + 1,
			capabilities: upgradeCapabilities, effective: ProtocolVersion1 + 1,
			protocolSupported: false, agentUpgrade: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := AssessCompatibility(test.reported, test.capabilities)
			if got.EffectiveProtocolVersion != test.effective || got.ProtocolSupported != test.protocolSupported ||
				got.AgentUpgrade != test.agentUpgrade || !reflect.DeepEqual(got.MissingAgentUpgrade, test.missing) {
				t.Fatalf("compatibility = %+v, want effective=%d supported=%v upgrade=%v missing=%v",
					got, test.effective, test.protocolSupported, test.agentUpgrade, test.missing)
			}
		})
	}
}

func TestAgentUpgradeCapabilitiesReturnsAnIndependentSlice(t *testing.T) {
	first := AgentUpgradeCapabilities()
	first[0] = "changed"
	second := AgentUpgradeCapabilities()
	if second[0] != CapabilityTaskExecutionV1 {
		t.Fatalf("capability policy was mutated through a returned slice: %v", second)
	}
}

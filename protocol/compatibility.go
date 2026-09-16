package protocol

// MinSupportedProtocolVersion and MaxSupportedProtocolVersion bound the wire
// generations that may share /v1/node/sync. ProtocolVersion1 is additive, so
// this range advances only after an explicit compatibility review. A breaking
// generation uses a parallel endpoint instead of silently widening this range.
const (
	MinSupportedProtocolVersion = ProtocolVersion1
	MaxSupportedProtocolVersion = ProtocolVersion1
)

// Compatibility is the control plane's interpretation of one authenticated
// report. It deliberately separates the base sync protocol from optional task
// capabilities: an older agent may remain fully usable for configuration and
// traffic while being ineligible for remote upgrade.
type Compatibility struct {
	ReportedProtocolVersion  int
	EffectiveProtocolVersion int
	ProtocolSupported        bool
	TaskExecution            bool
	TaskExpiry               bool
	AgentUpgrade             bool
	MissingAgentUpgrade      []string
}

// EffectiveProtocolVersion maps the omitted version used by the first v1
// peers to v1. This legacy rule is part of the public wire contract and must be
// removed only with an explicit compatibility-matrix change.
func EffectiveProtocolVersion(reported int) int {
	if reported == 0 {
		return ProtocolVersion1
	}
	return reported
}

// AgentUpgradeCapabilities returns the complete fail-closed capability set
// required before PSP may create an agent.upgrade.v1 task. A new optional
// upgrade generation must introduce a new task capability rather than changing
// the meaning of this list in place.
func AgentUpgradeCapabilities() []string {
	return []string{
		CapabilityTaskExecutionV1,
		CapabilityTaskExpiryV1,
		TaskCapability(TaskKindAgentUpgradeV1),
	}
}

// AssessCompatibility evaluates a durable protocol/capability observation.
// It is intentionally pure so PSP's server DTO, task admission and migration
// tooling can all use the same decision without drifting.
func AssessCompatibility(reported int, capabilities []string) Compatibility {
	effective := EffectiveProtocolVersion(reported)
	result := Compatibility{
		ReportedProtocolVersion:  reported,
		EffectiveProtocolVersion: effective,
		ProtocolSupported: effective >= MinSupportedProtocolVersion &&
			effective <= MaxSupportedProtocolVersion,
	}
	present := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		present[capability] = struct{}{}
	}
	_, result.TaskExecution = present[CapabilityTaskExecutionV1]
	_, result.TaskExpiry = present[CapabilityTaskExpiryV1]
	for _, required := range AgentUpgradeCapabilities() {
		if _, ok := present[required]; !ok {
			result.MissingAgentUpgrade = append(result.MissingAgentUpgrade, required)
		}
	}
	result.AgentUpgrade = result.ProtocolSupported && len(result.MissingAgentUpgrade) == 0
	return result
}

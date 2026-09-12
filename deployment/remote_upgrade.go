package deployment

import _ "embed"

// These root-owned units expose one fixed controller, not sudo or arbitrary
// command execution to the non-root agent.
//
//go:embed passwall-node-upgrade.service
var remoteUpgradeService string

//go:embed passwall-node-upgrade.path
var remoteUpgradePath string

func RenderRemoteUpgradeUnits() map[string]string {
	return map[string]string{
		"passwall-node-upgrade.service": remoteUpgradeService,
		"passwall-node-upgrade.path":    remoteUpgradePath,
	}
}

func RemoteUpgradeAssets() map[string]string { return RenderRemoteUpgradeUnits() }

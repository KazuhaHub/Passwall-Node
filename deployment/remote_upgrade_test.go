package deployment

import (
	"strings"
	"testing"
)

func TestRemoteUpgradeUnitsNarrowPrivilege(t *testing.T) {
	assets := RemoteUpgradeAssets()
	if len(assets) != 2 {
		t.Fatal("upgrade must install only the fixed helper and watcher")
	}
	service := assets["passwall-node-upgrade.service"]
	for _, required := range []string{"Type=oneshot\n", "ExecStart=/opt/passwall-node/bin/passwall-node --run-upgrade-helper\n", "Restart=on-failure\n", "NoNewPrivileges=true\n", "ProtectSystem=strict\n", "ReadOnlyPaths=/opt/passwall-node/config/credential /opt/passwall-node/config/environment /opt/passwall-node/data\n"} {
		if !strings.Contains(service, required) {
			t.Fatalf("helper unit omitted required protection %q", required)
		}
	}
	for _, forbidden := range []string{"User=passwall-node", "CAP_SYS_ADMIN", "/bin/sh", "sudo", "EnvironmentFile=", "--credential"} {
		if strings.Contains(service, forbidden) {
			t.Fatalf("helper unexpectedly broad: %q", forbidden)
		}
	}
	watcher := assets["passwall-node-upgrade.path"]
	if !strings.Contains(watcher, "PathChanged=/opt/passwall-node/data/upgrades/request.json\n") || !strings.Contains(watcher, "Unit=passwall-node-upgrade.service\n") {
		t.Fatal("watcher must dispatch one fixed structured request")
	}
	assets["passwall-node-upgrade.service"] = "modified"
	if RemoteUpgradeAssets()["passwall-node-upgrade.service"] == "modified" {
		t.Fatal("caller mutated embedded unit assets")
	}
}

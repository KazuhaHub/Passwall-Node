package agent

import (
	"testing"

	"github.com/KazuhaHub/passwall-node/protocol"
)

func TestValidateCoreSelectionUsesAuditedCatalogAndExplicitRestriction(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		selection protocol.CoreSelection
		wantError bool
	}{
		{name: "legacy zero value"},
		{name: "recommended", selection: protocol.CoreSelection{Engine: "xray", Version: "26.6.27"}},
		{name: "config verified", selection: protocol.CoreSelection{Engine: "xray", Version: "26.7.28"}},
		{name: "restricted confirmed", selection: protocol.CoreSelection{Engine: "xray", Version: "26.9.9", AllowRestrictedReality: true}},
		{name: "restricted unconfirmed", selection: protocol.CoreSelection{Engine: "xray", Version: "26.9.9"}, wantError: true},
		{name: "unrestricted with bypass", selection: protocol.CoreSelection{Engine: "xray", Version: "26.6.27", AllowRestrictedReality: true}, wantError: true},
		{name: "latest", selection: protocol.CoreSelection{Engine: "xray", Version: "latest"}, wantError: true},
		{name: "unlisted", selection: protocol.CoreSelection{Engine: "xray", Version: "26.9.8"}, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateCoreSelection(test.selection)
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError=%v", err, test.wantError)
			}
		})
	}
}

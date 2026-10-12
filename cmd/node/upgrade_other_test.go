//go:build !linux

package main

import (
	"strings"
	"testing"
)

func TestNonLinuxRemoteUpgradeStaysUnavailable(t *testing.T) {
	if remoteUpgradeClient(options{}, "test", nil, nil, nil) != nil {
		t.Fatal("non-Linux binaries must not register a remote upgrade client")
	}
	if err := enableRemoteUpgrade(); err == nil || !strings.Contains(err.Error(), "Linux installation") {
		t.Fatal("non-Linux remote upgrade enablement must remain refused")
	}
}

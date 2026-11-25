#!/usr/bin/env bash

# Run from the module root with the official binary environment already loaded.
set -euo pipefail

results=${1:?usage: test-official-cores.sh RESULTS.json}

go test -json -count=1 -timeout=10m ./internal/core/install \
  -run '^TestOfficial(Xray|SingBox)InstallIntegration$' \
  | tee "$results"
go test -json -count=1 -timeout=10m ./internal/core/xray \
  -run '^(TestCompilerArtifactPassesPinnedXrayValidation|TestCompilerPolicyArtifactPassesPinnedXrayValidation|TestPolicyEnforcedByRealXray|TestRealXrayCountsUsageByDomainByIPAndThroughAnAllowRule|TestRealXrayCountsAnExemptAccountsUsage|TestRealXrayCountsBulkConnectionsWithNothingUnmatched)$' \
  | tee -a "$results"
go test -json -count=1 -timeout=5m ./internal/core/singbox \
  -run '^(TestCompilerArtifactPassesPinnedSingBoxValidation|TestCompilerPolicyArtifactPassesPinnedSingBoxValidation|TestPolicyEnforcedByRealSingBox|TestDaemonAPIWireCompatibilityWithPinnedSingBox|TestRealityHandshakeMatrix)$' \
  | tee -a "$results"
go run ./deployment/coreacceptance check \
  --results "$results"

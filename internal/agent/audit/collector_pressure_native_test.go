//go:build audit_pressure && linux

package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeCollectorPressure(t *testing.T) {
	path := os.Getenv("NODE_COLLECTOR_PRESSURE_METRICS")
	root, rootErr := filepath.EvalSymlinks(os.Getenv("RUNNER_TEMP"))
	dir, dirErr := filepath.EvalSymlinks(filepath.Dir(path))
	if rootErr != nil || dirErr != nil || root != dir || !filepath.IsAbs(path) || filepath.Base(path) != "audit-collector-pressure-metrics.json" || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("GITHUB_REPOSITORY") != "KazuhaHub/Passwall-Node" {
		t.Fatal("collector pressure requires owned evidence on the hosted Linux runner")
	}
	result := testing.Benchmark(BenchmarkCollectorMixedPressure)
	if result.N != 1 {
		t.Fatal("collector pressure must measure one complete benchmark iteration")
	}
	metric := func(name string) uint64 {
		t.Helper()
		value, ok := result.Extra[name]
		if !ok || value < 0 || value >= 1<<53 || value != float64(uint64(value)) {
			t.Fatal("collector pressure lacks a bounded exact measurement")
		}
		return uint64(value)
	}
	type laneEvidence struct {
		Kind       string `json:"kind"`
		Limit      uint64 `json:"key_limit"`
		Keys       uint64 `json:"keys"`
		Rows       uint64 `json:"pending_rows"`
		Bytes      uint64 `json:"pending_bytes"`
		Dropped    uint64 `json:"dropped_events"`
		Unmatched  uint64 `json:"unmatched"`
		Slots      uint64 `json:"slots"`
		Anonymous  uint64 `json:"anonymous_rows"`
		Identified uint64 `json:"identified_rows"`
	}
	report := struct {
		Schema   int            `json:"schema_version"`
		N        int            `json:"iterations"`
		Keys     uint64         `json:"total_keys"`
		Pending  uint64         `json:"pending_count"`
		Bytes    uint64         `json:"pending_bytes"`
		Retained uint64         `json:"retained_heap_bytes"`
		Peak     uint64         `json:"sampled_peak_heap_bytes"`
		Lanes    []laneEvidence `json:"lanes"`
	}{Schema: 1, N: result.N, Keys: metric("keys"), Pending: metric("pending-count"), Bytes: metric("pending-bytes"), Retained: metric("retained-heap-bytes"), Peak: metric("sampled-peak-heap-bytes")}
	for _, kind := range []string{"block", "observe", "trial", "usage"} {
		report.Lanes = append(report.Lanes, laneEvidence{kind, metric(kind + "-key-limit"), metric(kind + "-keys"), metric(kind + "-pending-rows"), metric(kind + "-pending-bytes"), metric(kind + "-dropped-events"), metric(kind + "-unmatched"), metric(kind + "-slots"), metric(kind + "-anonymous-rows"), metric(kind + "-identified-rows")})
	}
	data, err := json.Marshal(report)
	if err != nil || os.WriteFile(path, append(data, '\n'), 0644) != nil {
		t.Fatal("cannot save bounded collector pressure evidence")
	}
}

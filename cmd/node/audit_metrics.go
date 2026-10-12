package main

import (
	"context"
	"encoding/json"
	"github.com/KazuhaHub/passwall-node/v4/internal/agent/audit"
	"github.com/KazuhaHub/passwall-node/v4/internal/agent/auditlog"
	"runtime"
	"time"
)

type auditMetrics struct {
	Schema      int                   `json:"schema_version"`
	HeapAlloc   uint64                `json:"go_heap_alloc_bytes"`
	HeapInuse   uint64                `json:"go_heap_inuse_bytes"`
	HeapObjects uint64                `json:"go_heap_objects"`
	Goroutines  int                   `json:"go_goroutines"`
	Lanes       [4]audit.LanePressure `json:"lanes"`
	AccessLog   auditlog.Pressure     `json:"access_log"`
}

// This optional observer measures the running daemon's whole Go heap. It never
// forces GC, clones private rows or claims a continuous peak/collector-only heap.
func (a *nodeAudit) runMetrics(ctx context.Context) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		var memory runtime.MemStats
		runtime.ReadMemStats(&memory)
		value := auditMetrics{Schema: 2, HeapAlloc: memory.HeapAlloc, HeapInuse: memory.HeapInuse, HeapObjects: memory.HeapObjects, Goroutines: runtime.NumGoroutine(), Lanes: a.collector.Pressure()}
		if a.filter != nil {
			value.AccessLog = a.filter.Pressure()
		}
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		a.logger.Infof("audit_pressure=%s", data)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/KazuhaHub/passwall-node/v4/internal/agent/audit"
	"github.com/KazuhaHub/passwall-protocol/protocol"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAuditMetricsRequiresExplicitFlagAndUsesFixedNumericShape(t *testing.T) {
	defaultOptions, err := parseOptions(nil, &bytes.Buffer{})
	if err != nil || defaultOptions.AuditMetrics {
		t.Fatal("metrics enabled by default")
	}
	selected, err := parseOptions([]string{"--audit-metrics"}, &bytes.Buffer{})
	if err != nil || !selected.AuditMetrics {
		t.Fatal("explicit observer flag ignored")
	}
	c := audit.New(nil)
	c.SetSnapshot(audit.Snapshot{Collect: "hits", Revision: 1, Subjects: map[string]protocol.SubjectKey{"private-person@example": "usr_77"}, Rules: map[string]protocol.RuleAction{"p123": protocol.RuleBlock}})
	c.AddHit(1, "private-person@example", "private-site.example:443", "psp-deny-p123")
	data, err := json.Marshal(auditMetrics{Schema: 1, Lanes: c.Pressure()})
	if err != nil {
		t.Fatal("numeric observer encoding failed")
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil || len(object) != 6 {
		t.Fatal("observer exported unexpected metadata")
	}
	for _, key := range []string{"schema_version", "go_heap_alloc_bytes", "go_heap_inuse_bytes", "go_heap_objects", "go_goroutines", "lanes"} {
		if _, ok := object[key]; !ok {
			t.Fatal("observer numeric field missing")
		}
	}
	for _, private := range []string{"private-person", "private-site", "usr_77", "p123"} {
		if strings.Contains(string(data), private) {
			t.Fatal("observer exported private identity")
		}
	}
	before := c.Pressure()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	a := &nodeAudit{collector: c, logger: newNodeLogger(&bytes.Buffer{})}
	if a.runMetrics(ctx) != nil || !reflect.DeepEqual(before, c.Pressure()) {
		t.Fatal("cancelled observer changed collector state")
	}
}

func TestAuditMetricsLiveSampleReadsRealHeapAndStopsWithLifecycle(t *testing.T) {
	c := audit.New(nil)
	before := c.Pressure()
	ctx, cancel := context.WithCancel(t.Context())
	writer := &auditMetricWriter{cancel: cancel}
	a := &nodeAudit{collector: c, logger: newNodeLogger(writer)}
	done := make(chan error, 1)
	go func() { done <- a.runMetrics(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("observer stopped with error")
		}
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("observer did not stop")
	}
	line := writer.output.String()
	start := strings.Index(line, "audit_pressure=")
	if start < 0 {
		t.Fatal("live numeric sample missing")
	}
	var sample auditMetrics
	if json.Unmarshal([]byte(strings.TrimSpace(line[start+len("audit_pressure="):])), &sample) != nil || sample.Schema != 1 || sample.HeapAlloc == 0 || sample.HeapInuse < sample.HeapAlloc || sample.HeapObjects == 0 || sample.Goroutines == 0 {
		t.Fatal("observer did not measure actual process memory")
	}
	if !reflect.DeepEqual(before, c.Pressure()) {
		t.Fatal("live sample consumed aggregation state")
	}
}

type auditMetricWriter struct {
	output bytes.Buffer
	cancel context.CancelFunc
}

func (w *auditMetricWriter) Write(data []byte) (int, error) {
	n, err := w.output.Write(data)
	w.cancel()
	return n, err
}

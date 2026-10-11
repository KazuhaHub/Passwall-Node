package main

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/agent"
	"github.com/KazuhaHub/passwall-node/v4/internal/agent/audit"
	"github.com/KazuhaHub/passwall-node/v4/internal/agent/auditlog"
	"github.com/KazuhaHub/passwall-node/v4/internal/agent/auditsink"
	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/process"
	coreruntime "github.com/KazuhaHub/passwall-node/v4/internal/core/runtime"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/singbox"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/xray"
	"github.com/KazuhaHub/passwall-node/v4/internal/lifecycle"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

type nodeAudit struct {
	collector *audit.Collector
	sink      *auditsink.Sink
	filter    *auditlog.Filter
	now       func() time.Time
	logger    *nodeLogger
}

func newNodeAudit(dataDir string, now func() time.Time, logger *nodeLogger) (*nodeAudit, error) {
	a := &nodeAudit{collector: audit.New(now), logger: logger, now: now}
	sink, err := auditsink.Listen(dataDir, a.collector)
	if errors.Is(err, auditsink.ErrTokenFile) {
		return nil, err
	}
	if err != nil {
		logger.Warnf("audit hits unavailable: %v", err)
		return a, nil
	}
	a.sink = sink
	return a, nil
}

func nodeCompilerFactory(parsed options, secret string, audit *nodeAudit) coreruntime.CompilerFactory {
	return func(selection protocol.CoreSelection) (agentcore.Compiler, error) {
		switch selection.Engine {
		case "xray":
			compiler := xray.Compiler{APIListen: parsed.XrayAPIListen, CoreVersion: selection.Version, AllowRestrictedReality: selection.AllowRestrictedReality}
			if audit != nil && audit.sink != nil {
				compiler.AuditSocket, compiler.AuditToken = audit.sink.Socket(), audit.sink.Token()
				compiler.AccessLogFiltered = audit.filter != nil
			}
			return compiler, nil
		case "sing-box":
			return singbox.Compiler{APIListen: parsed.SingBoxAPIListen, APISecret: secret}, nil
		default:
			return nil, fmt.Errorf("core engine %q is unsupported", selection.Engine)
		}
	}
}

// Install the actual output path before constructing compilers or advertising
// usage. Shared stdout is never owned by a single sing-box deployment.
func (a *nodeAudit) configureOutput(options *process.Options) error {
	if a.sink == nil {
		return nil
	}
	filter, err := auditlog.New(a.collector, options.Stdout, a.now)
	if err != nil {
		return err
	}
	shared := struct{ io.Writer }{options.Stdout}
	options.StdoutForDeployment = func(d agentcore.Deployment) io.Writer {
		if d.Engine == "xray" {
			return filter.Writer(d.CollectRevision)
		}
		return shared
	}
	a.filter = filter
	return nil
}

func (a *nodeAudit) configureRuntime(options *coreruntime.Options) {
	if a.sink != nil {
		options.OnDeployedAudit = func(s audit.Snapshot) {
			a.collector.SetSnapshot(s)
			if a.filter != nil {
				a.filter.SetCollection(s.Revision, s.Collect == string(protocol.CollectHitsAndUsage))
			}
		}
	}
}
func (a *nodeAudit) configureSync(sync *agent.Synchronizer) {
	if a.sink != nil {
		sync.Reports.Capabilities = append(sync.Reports.Capabilities, protocol.CapabilityAuditHits)
		if a.filter != nil {
			sync.Reports.Capabilities = append(sync.Reports.Capabilities, protocol.CapabilityAuditUsage)
		}
		sync.Audit = a.collector
		sync.OnAuditInvalid = func() { a.logger.Warnf("audit_invalid_dropped=1") }
	}
}
func (a *nodeAudit) service() (lifecycle.Service, bool) {
	if a.sink == nil {
		return lifecycle.Service{}, false
	}
	return lifecycle.Service{Name: "audit hits", Run: a.sink.Run}, true
}

func (a *nodeAudit) usageService() (lifecycle.Service, bool) {
	if a.filter == nil {
		return lifecycle.Service{}, false
	}
	return lifecycle.Service{Name: "audit usage", Run: a.filter.Run}, true
}

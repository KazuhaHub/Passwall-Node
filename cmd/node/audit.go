package main

import (
	"time"

	"fmt"
	"github.com/KazuhaHub/passwall-node/v4/internal/agent"
	"github.com/KazuhaHub/passwall-node/v4/internal/agent/audit"
	"github.com/KazuhaHub/passwall-node/v4/internal/agent/auditsink"
	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	coreruntime "github.com/KazuhaHub/passwall-node/v4/internal/core/runtime"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/singbox"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/xray"
	"github.com/KazuhaHub/passwall-node/v4/internal/lifecycle"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

type nodeAudit struct {
	collector *audit.Collector
	sink      *auditsink.Sink
	logger    *nodeLogger
}

func newNodeAudit(dataDir string, now func() time.Time, logger *nodeLogger) (*nodeAudit, error) {
	return &nodeAudit{collector: audit.New(now), logger: logger}, nil
}

func nodeCompilerFactory(parsed options, secret string, audit *nodeAudit) coreruntime.CompilerFactory {
	return func(selection protocol.CoreSelection) (agentcore.Compiler, error) {
		switch selection.Engine {
		case "xray":
			return xray.Compiler{APIListen: parsed.XrayAPIListen, CoreVersion: selection.Version, AllowRestrictedReality: selection.AllowRestrictedReality}, nil
		case "sing-box":
			return singbox.Compiler{APIListen: parsed.SingBoxAPIListen, APISecret: secret}, nil
		default:
			return nil, fmt.Errorf("core engine %q is unsupported", selection.Engine)
		}
	}
}

func (a *nodeAudit) configureRuntime(options *coreruntime.Options) {}
func (a *nodeAudit) configureSync(sync *agent.Synchronizer)        {}
func (a *nodeAudit) service() (lifecycle.Service, bool)            { return lifecycle.Service{}, false }

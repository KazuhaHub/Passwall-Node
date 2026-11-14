package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/KazuhaHub/passwall-node/v4/internal/agent/auditsink"
	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	coreruntime "github.com/KazuhaHub/passwall-node/v4/internal/core/runtime"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/singbox"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/xray"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// auditReceiver is the hit receiver once it is listening: the socket Xray's
// webhooks post to, and the secret they must present.
type auditReceiver struct {
	Sink   *auditsink.Sink
	Socket string
	// Token is a secret. It is compiled into the Xray configuration and never
	// written to a log.
	Token string
}

// startAuditReceiver listens for rule hits, or says why it cannot and returns
// nil.
//
// NIL IS A LEGITIMATE ANSWER AND THE NODE CARRIES ON. A node that cannot listen
// declares no audit.hits.v1 and writes no webhook, so the panel sees a node that
// does not record, which is true. What the node must never do is declare the
// capability and then not be listening, which is why the declaration is made
// from this function's result and nowhere else.
//
// The token is created only once the path is known to be usable, and is kept
// across restarts: it is in the compiled configuration, so one that changed
// would change the deployment digest and restart the core with every restart of
// the agent.
func startAuditReceiver(dataDir string, warnf func(format string, args ...any)) *auditReceiver {
	socket := filepath.Join(dataDir, "runtime", "audit.sock")
	if len(socket) > auditsink.MaxSocketPathBytes {
		warnf("rule hits will not be recorded: the audit socket path is %d bytes and a unix socket allows %d", len(socket), auditsink.MaxSocketPathBytes)
		return nil
	}
	// Xray reads a webhook url as "<socket path>:<http path>" and splits it at
	// the colon, so a path that contains one cannot be written.
	if strings.Contains(socket, ":") {
		warnf("rule hits will not be recorded: the data directory path contains a colon, which an Xray webhook url cannot carry")
		return nil
	}
	token, err := loadOrCreateSecret(filepath.Join(dataDir, "secrets", "audit-webhook"))
	if err != nil {
		warnf("rule hits will not be recorded: the audit token is unavailable: %v", err)
		return nil
	}
	sink, err := auditsink.New(auditsink.Options{Path: socket, Token: token})
	if err != nil {
		warnf("rule hits will not be recorded: %v", err)
		return nil
	}
	if err := sink.Listen(); err != nil {
		warnf("rule hits will not be recorded: %v", err)
		return nil
	}
	return &auditReceiver{Sink: sink, Socket: socket, Token: token}
}

// compilerFactory builds the compiler for the selected engine. audit is nil on a
// node with no receiver, which is the only way the Xray compiler is given a
// socket. sing-box is given nothing: it has no webhook, stays enforce-only, and
// the panel works that out from the engine.
func compilerFactory(parsed options, singBoxAPISecret string, audit *auditReceiver) coreruntime.CompilerFactory {
	return func(selection protocol.CoreSelection) (agentcore.Compiler, error) {
		switch selection.Engine {
		case "xray":
			compiler := xray.Compiler{
				APIListen: parsed.XrayAPIListen, CoreVersion: selection.Version,
				AllowRestrictedReality: selection.AllowRestrictedReality,
			}
			if audit != nil {
				compiler.AuditSocket, compiler.AuditToken = audit.Socket, audit.Token
			}
			return compiler, nil
		case "sing-box":
			return singbox.Compiler{
				APIListen: parsed.SingBoxAPIListen, APISecret: singBoxAPISecret,
			}, nil
		default:
			return nil, fmt.Errorf("core engine %q is unsupported", selection.Engine)
		}
	}
}

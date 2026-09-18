// Command node is the production Passwall-Node daemon.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"time"

	"github.com/KazuhaHub/passwall-node/corecatalog"
	"github.com/KazuhaHub/passwall-node/internal/agent"
	agentcore "github.com/KazuhaHub/passwall-node/internal/core"
	"github.com/KazuhaHub/passwall-node/internal/core/install"
	"github.com/KazuhaHub/passwall-node/internal/core/process"
	coreruntime "github.com/KazuhaHub/passwall-node/internal/core/runtime"
	"github.com/KazuhaHub/passwall-node/internal/core/singbox"
	"github.com/KazuhaHub/passwall-node/internal/core/xray"
	"github.com/KazuhaHub/passwall-node/internal/host"
	"github.com/KazuhaHub/passwall-node/internal/lifecycle"
	"github.com/KazuhaHub/passwall-node/internal/manage"
	"github.com/KazuhaHub/passwall-node/internal/nodeconfig"
	"github.com/KazuhaHub/passwall-node/internal/state"
	statesqlite "github.com/KazuhaHub/passwall-node/internal/state/sqlite"
	"github.com/KazuhaHub/passwall-node/internal/upgrade"
	buildversion "github.com/KazuhaHub/passwall-node/internal/version"
	"github.com/KazuhaHub/passwall-node/protocol"
)

const defaultXrayAPIListen = "127.0.0.1:10085"
const defaultSingBoxAPIListen = "127.0.0.1:10086"

type options struct {
	Endpoint          string
	AgentID           string
	CredentialFile    string
	DataDir           string
	XrayAPIListen     string
	SingBoxAPIListen  string
	AllowInsecureHTTP bool
	ShowVersion       bool
}

type nodeLogger struct {
	mu  sync.Mutex
	out io.Writer
	now func() time.Time
}

func newNodeLogger(out io.Writer) *nodeLogger {
	return &nodeLogger{out: out, now: time.Now}
}

func (l *nodeLogger) printf(level, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = fmt.Fprintf(l.out, "%s passwall-node level=%s message=%q\n",
		l.now().UTC().Format(time.RFC3339Nano), level, fmt.Sprintf(format, args...))
}

func (l *nodeLogger) Infof(format string, args ...any)  { l.printf("info", format, args...) }
func (l *nodeLogger) Warnf(format string, args ...any)  { l.printf("warn", format, args...) }
func (l *nodeLogger) Errorf(format string, args ...any) { l.printf("error", format, args...) }

func main() {
	if filepath.Base(os.Args[0]) == "pn" {
		if err := manage.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "pn:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		newNodeLogger(os.Stderr).Errorf("%v", err)
		os.Exit(1)
	}
}

func run(arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) == 1 {
		switch arguments[0] {
		case "--upgrade-info":
			return json.NewEncoder(stdout).Encode(upgrade.BuildInfo{Version: buildversion.Version, StateSchema: statesqlite.SupportedSchema, UpgradeContract: upgrade.UpgradeContract})
		case "--run-upgrade-helper":
			ctx, stop := signalContext(context.Background())
			defer stop()
			return upgrade.RunHelper(ctx, upgrade.InstallRoot, statesqlite.SupportedSchema)
		case "--run-docker-upgrade-helper":
			ctx, stop := signalContext(context.Background())
			defer stop()
			return upgrade.RunDockerHelper(ctx, statesqlite.SupportedSchema, stderr)
		case "--enable-remote-upgrade":
			return enableRemoteUpgrade()
		}
	}
	parsed, err := parseOptions(arguments, stderr)
	if err != nil {
		return err
	}
	if parsed.ShowVersion {
		_, err := fmt.Fprintln(stdout, buildversion.String())
		return err
	}
	if err := validateOptions(parsed); err != nil {
		return err
	}
	credential, err := readCredential(parsed.CredentialFile)
	if err != nil {
		return err
	}
	signer, err := agent.NewBearerSigner(credential)
	if err != nil {
		return fmt.Errorf("credential file: %w", err)
	}

	ctx, stop := signalContext(context.Background())
	defer stop()
	logger := newNodeLogger(stderr)
	if err := os.MkdirAll(parsed.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	singBoxAPISecret, err := loadOrCreateSecret(filepath.Join(parsed.DataDir, "secrets", "sing-box-api"))
	if err != nil {
		return err
	}
	store, err := statesqlite.Open(ctx, filepath.Join(parsed.DataDir, "state.db"))
	if err != nil {
		return err
	}
	defer store.Close()

	coreRoot := filepath.Join(parsed.DataDir, "cores")
	installer, err := install.New(install.Options{RootDir: coreRoot})
	if err != nil {
		return err
	}
	initial, err := prepareInitialCore(ctx, store, installer, coreRoot)
	if err != nil {
		return err
	}
	supervisor, err := process.NewSupervisor(process.Options{
		Engine: initial.Engine, Binary: initial.BinaryPath, Version: initial.Version,
		// Preserve the v1 on-disk location across the multi-core upgrade. The
		// directory name is legacy-only; its contents are core-neutral artifacts.
		StateDir: filepath.Join(parsed.DataDir, "runtime", "xray"),
		Commands: coreCommand,
		Stdout:   stdout, Stderr: stderr,
		RequireInitialConfigDigest: true,
		InitialConfigDigest:        initial.ConfigDigest,
	})
	if err != nil {
		return err
	}
	coreRuntime, err := coreruntime.New(coreruntime.Options{
		Store: store, Installer: installer, Supervisor: supervisor,
		CompilerFactory: func(selection protocol.CoreSelection) (agentcore.Compiler, error) {
			switch selection.Engine {
			case "xray":
				return xray.Compiler{
					APIListen: parsed.XrayAPIListen, CoreVersion: selection.Version,
					AllowRestrictedReality: selection.AllowRestrictedReality,
				}, nil
			case "sing-box":
				return singbox.Compiler{
					APIListen: parsed.SingBoxAPIListen, APISecret: singBoxAPISecret,
				}, nil
			default:
				return nil, fmt.Errorf("core engine %q is unsupported", selection.Engine)
			}
		},
	})
	if err != nil {
		return err
	}
	xrayTelemetry, err := xray.NewTelemetry(xray.TelemetryOptions{
		Store: store, Status: supervisor.Status, APIListen: parsed.XrayAPIListen,
	})
	if err != nil {
		return err
	}
	singBoxTelemetry, err := singbox.NewTelemetry(singbox.TelemetryOptions{
		Store: store, Status: supervisor.Status, APIListen: parsed.SingBoxAPIListen,
		APISecret: singBoxAPISecret, OnError: func(err error) { logger.Errorf("%v", err) },
	})
	if err != nil {
		return err
	}
	telemetry := agentcore.TelemetryRouter{
		Status: supervisor.Status,
		Adapters: map[string]agentcore.Telemetry{
			"xray": xrayTelemetry, "sing-box": singBoxTelemetry,
		},
	}
	now := time.Now
	issues := agent.OutboxIssueSink{
		Store: store, Map: agent.DefaultIssueMapper, NowMS: func() int64 { return now().UnixMilli() },
	}
	// These are explicit operational guard margins, not execution TTLs or a
	// measured hardware/SLA guarantee. Individual kinds still need execution,
	// recovery and restore acceptance before production handlers are registered.
	taskClock, clockErr := agent.NewControlPlaneTaskClock(agent.ClockOptions{
		MaxAnchorAge: 30 * time.Second, MaxRoundTrip: 30 * time.Second,
		Uncertainty: time.Second,
	})
	var startClock state.TaskStartClock
	if clockErr != nil {
		logger.Warnf("task start clock unavailable; expiry tasks stay disabled: %v", clockErr)
	} else {
		startClock = taskClock
	}
	var upgradeClient *upgrade.Client
	handlers := map[string]agent.TaskHandler{}
	if startClock != nil {
		upgradeClient = remoteUpgradeClient(parsed, buildversion.Version, startClock, coreRuntime.Converge)
	}
	if upgradeClient != nil {
		handlers[upgrade.TaskKind] = upgradeClient
	}
	taskRegistry, err := agent.NewTaskRegistry(handlers)
	if err != nil {
		return err
	}
	taskWorker, err := agent.NewTaskWorker(agent.TaskWorkerOptions{
		Store: store, Registry: taskRegistry, Now: now, Clock: startClock,
	})
	if err != nil {
		return err
	}
	processor, err := agent.NewProcessor(agent.ProcessorOptions{
		Store: store, Runtime: coreRuntime, Issues: issues,
		SkewToleranceRounds: 3, ObjectIssueTimeout: 5 * time.Minute, Now: now,
		TaskWake: taskWorker.Wake, TaskClock: startClock,
	})
	if err != nil {
		return err
	}
	restarts := func() uint64 { return supervisor.Status().RestartCount }
	runtimeStats := agent.NewRuntimeStats(now, restarts)
	syncer, err := agent.NewHTTPSyncer(parsed.Endpoint, agent.HTTPOptions{
		Signer: signer, AllowInsecureHTTP: parsed.AllowInsecureHTTP,
		UserAgent: "passwall-node/" + buildversion.String(),
		Stats:     runtimeStats,
	})
	if err != nil {
		return err
	}
	observer := &agent.ObservationService{
		Telemetry: telemetry, Store: store, Issues: issues, Status: supervisor.Status, Now: now,
	}
	capabilities := taskWorker.Capabilities()
	// THE CAPABILITY IS DECLARED FROM THE RESULT, NOT FROM THE PLATFORM. A build
	// whose collector could not be constructed must not advertise
	// host.telemetry.v1: the panel would then expect telemetry from a node that
	// will never send any, and "old node" would stop being distinguishable from
	// "node that stopped collecting".
	var hostReporter *agent.HostReporter
	collector, err := host.New(host.Options{
		DataDir: parsed.DataDir, Core: supervisor.ProcessHandle, Runtime: runtimeStats.Observation,
	})
	if err != nil {
		logger.Warnf("host telemetry is unavailable on this platform: %v", err)
	} else if hostReporter, err = agent.NewHostReporter(agent.HostReporterOptions{
		Collector: collector, Issues: issues, Now: now,
	}); err != nil {
		return err
	}
	if hostReporter != nil {
		capabilities = append(capabilities, protocol.CapabilityHostTelemetry)
	}
	synchronizer := agent.Synchronizer{
		Reports: agent.ReportBuilder{
			AgentID: parsed.AgentID, AgentVersion: buildversion.String(),
			Store: store, CoreStatus: supervisor.Status, Now: now,
			Capabilities: capabilities,
		},
		Syncer: syncer, Store: store, Processor: processor, Observer: observer,
		TaskClock: taskClock, OnTaskClockError: func(err error) { logger.Warnf("task start authorization held: %v", err) },
		LocalConverger: coreRuntime,
		Host:           hostReporter,
		Stats:          runtimeStats,
	}
	if upgradeClient != nil {
		synchronizer.OnSynced = func(ctx context.Context) error { return upgradeClient.RecordReady(ctx, store) }
	}
	runner, err := agent.NewRunner(synchronizer, agent.RunnerOptions{OnError: func(err error) {
		logger.Warnf("sync failed; retrying: %v", err)
	}})
	if err != nil {
		return err
	}
	taskWorker.SetResultNotifier(runner.Wake)

	logger.Infof("starting agent_id=%s version=%s endpoint=%s", parsed.AgentID, buildversion.String(), parsed.Endpoint)
	err = lifecycle.Run(ctx,
		lifecycle.Service{Name: "core supervisor", Run: supervisor.Run},
		lifecycle.Service{Name: "sing-box telemetry", Run: singBoxTelemetry.Run},
		lifecycle.Service{Name: "local expiry", Run: func(ctx context.Context) error {
			return coreRuntime.RunExpiryLoop(ctx, func(err error) { logger.Errorf("%v", err) })
		}},
		lifecycle.Service{Name: "task worker", Run: taskWorker.Run},
		lifecycle.Service{Name: "control-plane sync", Run: runner.Run},
	)
	if err == nil {
		logger.Infof("stopped")
	}
	return err
}

func parseOptions(arguments []string, stderr io.Writer) (options, error) {
	var parsed options
	flags := flag.NewFlagSet("passwall-node", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&parsed.Endpoint, "endpoint", "", "absolute PSP /v1/node/sync URL")
	flags.StringVar(&parsed.AgentID, "agent-id", "", "registered PSP node agent ID")
	flags.StringVar(&parsed.CredentialFile, "credential-file", "", "absolute path to the private node credential")
	flags.StringVar(&parsed.DataDir, "data-dir", "", "absolute private state directory")
	flags.StringVar(&parsed.XrayAPIListen, "xray-api-listen", defaultXrayAPIListen, "loopback Xray statistics endpoint")
	flags.StringVar(&parsed.SingBoxAPIListen, "sing-box-api-listen", defaultSingBoxAPIListen, "loopback sing-box telemetry endpoint")
	flags.BoolVar(&parsed.AllowInsecureHTTP, "allow-insecure-http", false, "allow plain HTTP (development only)")
	flags.BoolVar(&parsed.ShowVersion, "version", false, "print build version and exit")
	if err := flags.Parse(arguments); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	return parsed, nil
}

func validateOptions(options options) error {
	if options.Endpoint == "" || options.AgentID == "" || options.CredentialFile == "" || options.DataDir == "" {
		return errors.New("endpoint, agent-id, credential-file and data-dir are required")
	}
	if !filepath.IsAbs(options.CredentialFile) || !filepath.IsAbs(options.DataDir) {
		return errors.New("credential-file and data-dir must be absolute paths")
	}
	if !nodeconfig.ValidAgentID(options.AgentID) {
		return errors.New("agent-id must be 1..64 canonical ASCII characters")
	}
	if strings.TrimSpace(options.Endpoint) != options.Endpoint || strings.TrimSpace(options.XrayAPIListen) != options.XrayAPIListen ||
		strings.TrimSpace(options.SingBoxAPIListen) != options.SingBoxAPIListen {
		return errors.New("endpoint and core API listen addresses must be canonical")
	}
	return nil
}

func readCredential(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect credential file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("credential file must be a regular file, not a symlink")
	}
	if goruntime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("credential file must not be accessible by group or others")
	}
	if info.Size() > protocol.MaxNodeCredentialBytes+2 {
		return "", errors.New("credential file is too large")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read credential file: %w", err)
	}
	contents = bytes.TrimSuffix(contents, []byte("\r\n"))
	contents = bytes.TrimSuffix(contents, []byte("\n"))
	return string(contents), nil
}

func loadOrCreateSecret(secretPath string) (string, error) {
	if !filepath.IsAbs(secretPath) {
		return "", errors.New("secret path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(secretPath), 0o700); err != nil {
		return "", fmt.Errorf("create secrets directory: %w", err)
	}
	if secret, err := readPrivateSecret(secretPath); err == nil {
		return secret, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate local API secret: %w", err)
	}
	secret := hex.EncodeToString(random)
	file, err := os.OpenFile(secretPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return readPrivateSecret(secretPath)
	}
	if err != nil {
		return "", fmt.Errorf("create local API secret: %w", err)
	}
	if _, err := file.WriteString(secret + "\n"); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("write local API secret: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("sync local API secret: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close local API secret: %w", err)
	}
	return secret, nil
}

func readPrivateSecret(secretPath string) (string, error) {
	info, err := os.Lstat(secretPath)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("local API secret must be a regular file, not a symlink")
	}
	if goruntime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("local API secret must not be accessible by group or others")
	}
	if info.Size() > 256 {
		return "", errors.New("local API secret is too large")
	}
	content, err := os.ReadFile(secretPath)
	if err != nil {
		return "", fmt.Errorf("read local API secret: %w", err)
	}
	secret := strings.TrimSpace(string(content))
	if len(secret) < 32 || strings.ContainsAny(secret, " \t\r\n") {
		return "", errors.New("local API secret is invalid")
	}
	return secret, nil
}

type initialCore struct {
	Engine       string
	Version      string
	BinaryPath   string
	ConfigDigest string
}

func prepareInitialCore(ctx context.Context, store state.Store, installer *install.Installer, root string) (initialCore, error) {
	deployment, err := store.CoreDeployment(ctx)
	if errors.Is(err, state.ErrNotFound) {
		release, resolveErr := corecatalog.Recommended("xray")
		if resolveErr != nil {
			return initialCore{}, resolveErr
		}
		asset, assetErr := release.AssetFor(goruntime.GOOS, goruntime.GOARCH)
		if assetErr != nil {
			return initialCore{}, assetErr
		}
		return initialCore{
			Engine:     release.Engine,
			Version:    release.Version,
			BinaryPath: filepath.Join(root, release.Engine, "versions", release.Version, asset.Binary),
		}, nil
	}
	if err != nil {
		return initialCore{}, fmt.Errorf("read last confirmed core deployment: %w", err)
	}
	release, err := corecatalog.Resolve(deployment.Engine, deployment.Version)
	if err != nil {
		return initialCore{}, fmt.Errorf("resolve last confirmed core deployment: %w", err)
	}
	installed, err := installer.Install(ctx, install.Request{
		Engine: deployment.Engine, Version: deployment.Version,
		AcceptRestricted:     release.RequiresConfirmation,
		CurrentConfiguration: deployment.Artifact,
	})
	if err != nil {
		return initialCore{}, fmt.Errorf("verify last confirmed core installation: %w", err)
	}
	return initialCore{
		Engine: installed.Engine, Version: installed.Version,
		BinaryPath: installed.BinaryPath, ConfigDigest: deployment.ConfigDigest,
	}, nil
}

func coreCommand(engine string) (process.Command, error) {
	switch engine {
	case "xray":
		return process.Command{
			RunArgs:      func(configPath string) []string { return []string{"run", "-config", configPath} },
			ValidateArgs: func(configPath string) []string { return []string{"run", "-test", "-config", configPath} },
		}, nil
	case "sing-box":
		return process.Command{
			RunArgs:      func(configPath string) []string { return []string{"run", "-c", configPath} },
			ValidateArgs: func(configPath string) []string { return []string{"check", "-c", configPath} },
		}, nil
	default:
		return process.Command{}, fmt.Errorf("core engine %q is unsupported", engine)
	}
}

// Command node is the production Passwall-Node daemon.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"time"

	"github.com/KazuhaHub/passwall-node/corecatalog"
	"github.com/KazuhaHub/passwall-node/internal/agent"
	agentcore "github.com/KazuhaHub/passwall-node/internal/core"
	"github.com/KazuhaHub/passwall-node/internal/core/install"
	"github.com/KazuhaHub/passwall-node/internal/core/process"
	coreruntime "github.com/KazuhaHub/passwall-node/internal/core/runtime"
	"github.com/KazuhaHub/passwall-node/internal/core/xray"
	"github.com/KazuhaHub/passwall-node/internal/lifecycle"
	"github.com/KazuhaHub/passwall-node/internal/state"
	statesqlite "github.com/KazuhaHub/passwall-node/internal/state/sqlite"
	buildversion "github.com/KazuhaHub/passwall-node/internal/version"
	"github.com/KazuhaHub/passwall-node/protocol"
)

const defaultXrayAPIListen = "127.0.0.1:10085"

type options struct {
	Endpoint          string
	AgentID           string
	CredentialFile    string
	DataDir           string
	XrayAPIListen     string
	AllowInsecureHTTP bool
	ShowVersion       bool
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "passwall-node:", err)
		os.Exit(1)
	}
}

func run(arguments []string, stdout, stderr io.Writer) error {
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
	logger := log.New(stderr, "passwall-node ", log.Ldate|log.Ltime|log.Lmicroseconds|log.LUTC|log.Lmsgprefix)
	if err := os.MkdirAll(parsed.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
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
		Binary: initial.BinaryPath, Version: initial.Version,
		StateDir: filepath.Join(parsed.DataDir, "runtime", "xray"),
		RunArgs: func(configPath string) []string {
			return []string{"run", "-config", configPath}
		},
		ValidateArgs: func(configPath string) []string {
			return []string{"run", "-test", "-config", configPath}
		},
		Stdout: stdout, Stderr: stderr,
		RequireInitialConfigDigest: true,
		InitialConfigDigest:        initial.ConfigDigest,
	})
	if err != nil {
		return err
	}
	coreRuntime, err := coreruntime.New(coreruntime.Options{
		Store: store, Installer: installer, Supervisor: supervisor,
		CompilerFactory: func(selection protocol.CoreSelection) (agentcore.Compiler, error) {
			if selection.Engine != "xray" {
				return nil, fmt.Errorf("core engine %q is unsupported", selection.Engine)
			}
			return xray.Compiler{
				APIListen: parsed.XrayAPIListen, CoreVersion: selection.Version,
				AllowRestrictedReality: selection.AllowRestrictedReality,
			}, nil
		},
	})
	if err != nil {
		return err
	}
	telemetry, err := xray.NewTelemetry(xray.TelemetryOptions{
		Store: store, Status: supervisor.Status, APIListen: parsed.XrayAPIListen,
	})
	if err != nil {
		return err
	}
	now := time.Now
	issues := agent.OutboxIssueSink{
		Store: store, Map: agent.DefaultIssueMapper, NowMS: func() int64 { return now().UnixMilli() },
	}
	processor, err := agent.NewProcessor(agent.ProcessorOptions{
		Store: store, Runtime: coreRuntime, Issues: issues,
		SkewToleranceRounds: 3, ObjectIssueTimeout: 5 * time.Minute, Now: now,
	})
	if err != nil {
		return err
	}
	syncer, err := agent.NewHTTPSyncer(parsed.Endpoint, agent.HTTPOptions{
		Signer: signer, AllowInsecureHTTP: parsed.AllowInsecureHTTP,
		UserAgent: "passwall-node/" + buildversion.String(),
	})
	if err != nil {
		return err
	}
	observer := &agent.ObservationService{
		Telemetry: telemetry, Store: store, Issues: issues, Status: supervisor.Status, Now: now,
	}
	synchronizer := agent.Synchronizer{
		Reports: agent.ReportBuilder{
			AgentID: parsed.AgentID, AgentVersion: buildversion.String(),
			Store: store, CoreStatus: supervisor.Status, Now: now,
		},
		Syncer: syncer, Store: store, Processor: processor, Observer: observer,
		LocalConverger: coreRuntime,
	}
	runner, err := agent.NewRunner(synchronizer, agent.RunnerOptions{OnError: func(err error) {
		logger.Printf("sync failed; retrying: %v", err)
	}})
	if err != nil {
		return err
	}

	logger.Printf("starting agent_id=%s version=%s endpoint=%s", parsed.AgentID, buildversion.String(), parsed.Endpoint)
	err = lifecycle.Run(ctx,
		lifecycle.Service{Name: "core supervisor", Run: supervisor.Run},
		lifecycle.Service{Name: "local expiry", Run: func(ctx context.Context) error {
			return coreRuntime.RunExpiryLoop(ctx, func(err error) { logger.Printf("%v", err) })
		}},
		lifecycle.Service{Name: "control-plane sync", Run: runner.Run},
	)
	if err == nil {
		logger.Printf("stopped")
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
	if len(options.AgentID) > 64 || !validAgentID(options.AgentID) {
		return errors.New("agent-id must be 1..64 canonical ASCII characters")
	}
	if strings.TrimSpace(options.Endpoint) != options.Endpoint || strings.TrimSpace(options.XrayAPIListen) != options.XrayAPIListen {
		return errors.New("endpoint and xray-api-listen must be canonical")
	}
	return nil
}

func validAgentID(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' {
			continue
		}
		if index > 0 && (character == '_' || character == '-' || character == '.' || character == ':') {
			continue
		}
		return false
	}
	return value != ""
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

type initialCore struct {
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
		Version: installed.Version, BinaryPath: installed.BinaryPath, ConfigDigest: deployment.ConfigDigest,
	}, nil
}

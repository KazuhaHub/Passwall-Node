// Package manage implements the local pn management command. The released
// passwall-node binary dispatches here when it is invoked through the pn link,
// keeping daemon and management versions in lockstep.
package manage

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
	_ "modernc.org/sqlite"

	"github.com/KazuhaHub/passwall-node/internal/nodeconfig"
	buildversion "github.com/KazuhaHub/passwall-node/internal/version"
)

const (
	serviceName = "passwall-node.service"
	serviceUser = "passwall-node"
)

type paths struct {
	root        string
	binary      string
	config      string
	credential  string
	environment string
	version     string
	data        string
	state       string
	unitSource  string
	unit        string
	pnLink      string
}

func productionPaths() paths {
	root := "/opt/passwall-node"
	return paths{
		root: root, binary: filepath.Join(root, "bin", "passwall-node"),
		config: filepath.Join(root, "config"), credential: filepath.Join(root, "config", "credential"),
		environment: filepath.Join(root, "config", "environment"), version: filepath.Join(root, "config", "version"),
		data: filepath.Join(root, "data"), state: filepath.Join(root, "data", "state.db"),
		unitSource: filepath.Join(root, serviceName), unit: filepath.Join("/etc/systemd/system", serviceName),
		pnLink: "/usr/local/bin/pn",
	}
}

type commandRunner interface {
	Run(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, name string, args ...string) error
	Output(ctx context.Context, name string, args ...string) ([]byte, error)
}

type osRunner struct{}

func (osRunner) Run(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin, command.Stdout, command.Stderr = stdin, stdout, stderr
	return command.Run()
}

func (osRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

type app struct {
	in      io.Reader
	out     io.Writer
	errOut  io.Writer
	reader  *bufio.Reader
	paths   paths
	runner  commandRunner
	now     func() time.Time
	euid    func() int
	chown   func(string, int, int) error
	owner   func() (int, int, error)
	secret  func(string) (string, error)
	systemd string
	journal string
	context func() (context.Context, context.CancelFunc)
}

func newApp(in io.Reader, out, errOut io.Writer) *app {
	a := &app{
		in: in, out: out, errOut: errOut, reader: bufio.NewReader(in), paths: productionPaths(),
		runner: osRunner{}, now: time.Now, euid: effectiveUID, chown: os.Chown,
		context: func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 30*time.Second)
		},
	}
	a.owner = serviceOwner
	a.secret = func(prompt string) (string, error) { return readTerminalSecret(prompt, out) }
	return a
}

// Run executes pn. With no arguments it opens the interactive management menu.
func Run(arguments []string, in io.Reader, out, errOut io.Writer) error {
	return newApp(in, out, errOut).run(arguments)
}

func (a *app) run(arguments []string) error {
	if runtime.GOOS != "linux" {
		if len(arguments) == 1 && (arguments[0] == "version" || arguments[0] == "--version") {
			_, err := fmt.Fprintln(a.out, buildversion.String())
			return err
		}
		return errors.New("pn management is supported on Linux/systemd hosts only")
	}
	if len(arguments) == 0 {
		return a.menu()
	}
	switch arguments[0] {
	case "help", "--help", "-h":
		a.printHelp()
		return nil
	case "version", "--version", "-v":
		_, err := fmt.Fprintln(a.out, buildversion.String())
		return err
	case "status":
		return a.printStatus(true)
	case "start", "stop", "restart":
		return a.serviceAction(arguments[0])
	case "logs":
		follow := len(arguments) > 1 && arguments[1] == "--follow"
		if len(arguments) > 1 && !follow {
			return fmt.Errorf("usage: pn logs [--follow]")
		}
		return a.logs(follow)
	case "doctor":
		return a.doctor()
	case "connect":
		if len(arguments) != 1 {
			return errors.New("pn connect takes no arguments; credentials are entered interactively")
		}
		return a.connect(false)
	case "rebind":
		if len(arguments) != 1 {
			return errors.New("pn rebind takes no arguments; credentials are entered interactively")
		}
		return a.connect(true)
	case "config":
		return a.showConfig()
	case "paths":
		a.printPaths()
		return nil
	case "upgrade":
		return a.upgradeGuidance()
	case "backup":
		return a.backup()
	case "restore":
		return errors.New("automatic restore is intentionally unavailable; inspect the private backup and restore it during a planned maintenance window")
	case "repair":
		return a.repair()
	case "uninstall":
		return a.uninstall()
	default:
		return fmt.Errorf("unknown command %q; run pn help", arguments[0])
	}
}

func (a *app) printHelp() {
	fmt.Fprintln(a.out, `Usage: pn [command]

Without a command, pn opens the interactive menu.

Commands:
  status                 Show service, panel sync and core state
  start|stop|restart     Control the systemd service
  logs [--follow]        Show recent logs or follow them
  doctor                 Validate the local installation
  connect                Configure an unconfigured installation
  rebind                 Replace identity and reset old runtime state safely
  config                 Show connection settings with the secret redacted
  upgrade                Explain local and PSP-managed upgrade choices
  backup                 Create a consistent private config and state snapshot
  repair                 Repair the unit and pn link from local trusted files
  uninstall              Disable the service and retain a recoverable copy
  paths                   Show managed paths
  version                 Show the Passwall Node version
  help                    Show this help`)
}

func (a *app) menu() error {
	for {
		fmt.Fprintln(a.out)
		if err := a.printStatus(false); err != nil {
			fmt.Fprintf(a.out, " [WARN] Status details unavailable: %v\n", err)
		}
		fmt.Fprintln(a.out, `────────────────────────────────────────────
 Service
   1) Service controls
   2) View logs
   3) Run diagnostics
 Maintenance
   4) Upgrade
   5) Backup and restore
   6) Installation management
 Other
   7) Advanced options
   8) Help
   0) Exit`)
		choice, err := a.prompt("Select an option")
		if err != nil {
			return err
		}
		switch choice {
		case "0", "q", "quit", "exit":
			return nil
		case "1":
			if err := a.serviceMenu(); err != nil {
				a.printMenuError(err)
			}
		case "2":
			if err := a.logs(false); err != nil {
				a.printMenuError(err)
			}
		case "3":
			if err := a.doctor(); err != nil {
				a.printMenuError(err)
			}
		case "4":
			if err := a.upgradeGuidance(); err != nil {
				a.printMenuError(err)
			}
		case "5":
			if err := a.backup(); err != nil {
				a.printMenuError(err)
			}
		case "6":
			if err := a.installationMenu(); err != nil {
				a.printMenuError(err)
			}
		case "7":
			if err := a.advancedMenu(); err != nil {
				a.printMenuError(err)
			}
		case "8":
			a.printHelp()
		default:
			fmt.Fprintln(a.out, " Invalid selection.")
		}
	}
}

func (a *app) serviceMenu() error {
	fmt.Fprintln(a.out, `
 Service controls
   1) Start
   2) Stop
   3) Restart
   4) Show status
   0) Back`)
	choice, err := a.prompt("Select an option")
	if err != nil {
		return err
	}
	switch choice {
	case "0":
		return nil
	case "1":
		return a.serviceAction("start")
	case "2":
		return a.serviceAction("stop")
	case "3":
		return a.serviceAction("restart")
	case "4":
		return a.printStatus(true)
	default:
		return errors.New("invalid selection")
	}
}

func (a *app) installationMenu() error {
	fmt.Fprintln(a.out, `
 Installation management
   1) Verify installation
   2) Repair service and pn link
   3) Uninstall (recoverable)
   0) Back`)
	choice, err := a.prompt("Select an option")
	if err != nil {
		return err
	}
	switch choice {
	case "0":
		return nil
	case "1":
		return a.doctor()
	case "2":
		return a.repair()
	case "3":
		return a.uninstall()
	default:
		return errors.New("invalid selection")
	}
}

func (a *app) advancedMenu() error {
	fmt.Fprintln(a.out, `
 Advanced options
   1) Show panel connection
   2) Connect an unconfigured installation
   3) Rebind to another PSP identity
   4) Show managed paths
   5) Show remote-upgrade guidance
   0) Back`)
	choice, err := a.prompt("Select an option")
	if err != nil {
		return err
	}
	switch choice {
	case "0":
		return nil
	case "1":
		return a.showConfig()
	case "2":
		return a.connect(false)
	case "3":
		return a.connect(true)
	case "4":
		a.printPaths()
		return nil
	case "5":
		return a.upgradeGuidance()
	default:
		return errors.New("invalid selection")
	}
}

func (a *app) prompt(label string) (string, error) {
	fmt.Fprintf(a.out, " %s: ", label)
	line, err := a.reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value := strings.TrimSpace(line)
	if value == "" && errors.Is(err, io.EOF) {
		return "", io.EOF
	}
	return value, nil
}

func (a *app) printMenuError(err error) {
	fmt.Fprintf(a.out, " [FAIL] %v\n", err)
}

type serviceState struct {
	active, sub string
	pid         int
}

func (a *app) systemctlPath() (string, error) {
	if a.systemd != "" {
		return a.systemd, nil
	}
	for _, candidate := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", errors.New("systemctl was not found in a trusted system path")
}

func (a *app) journalctlPath() (string, error) {
	if a.journal != "" {
		return a.journal, nil
	}
	for _, candidate := range []string{"/usr/bin/journalctl", "/bin/journalctl"} {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", errors.New("journalctl was not found in a trusted system path")
}

func (a *app) getServiceState() (serviceState, error) {
	systemctl, err := a.systemctlPath()
	if err != nil {
		return serviceState{}, err
	}
	ctx, cancel := a.context()
	defer cancel()
	output, err := a.runner.Output(ctx, systemctl, "show", serviceName, "--property=ActiveState,SubState,MainPID", "--value")
	if err != nil {
		return serviceState{}, err
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 3 {
		return serviceState{}, errors.New("systemd returned an unexpected service state")
	}
	pid, _ := strconv.Atoi(lines[2])
	return serviceState{active: lines[0], sub: lines[1], pid: pid}, nil
}

func (a *app) serviceAction(action string) error {
	if err := a.requireRoot(); err != nil {
		return err
	}
	systemctl, err := a.systemctlPath()
	if err != nil {
		return err
	}
	ctx, cancel := a.context()
	defer cancel()
	if err := a.runner.Run(ctx, a.in, a.out, a.errOut, systemctl, action, serviceName); err != nil {
		return fmt.Errorf("systemctl %s: %w", action, err)
	}
	fmt.Fprintf(a.out, " [OK] Service %s completed.\n", action)
	return nil
}

func (a *app) logs(follow bool) error {
	journalctl, err := a.journalctlPath()
	if err != nil {
		return err
	}
	arguments := []string{"--unit", serviceName, "--lines", "100", "--no-pager", "--output", "short-iso"}
	if follow {
		arguments = append(arguments, "--follow")
	}
	ctx := context.Background()
	if !follow {
		var cancel context.CancelFunc
		ctx, cancel = a.context()
		defer cancel()
	}
	return a.runner.Run(ctx, a.in, a.out, a.errOut, journalctl, arguments...)
}

type connectionState struct {
	endpoint, agentID, credential string
}

func (a *app) readConnection() (connectionState, error) {
	environment, err := readRegularPrivateFile(a.paths.environment, 4096, true)
	if err != nil {
		return connectionState{}, err
	}
	endpoint, agentID, err := nodeconfig.ParseEnvironmentFile(environment)
	if err != nil {
		return connectionState{}, err
	}
	credential, err := readRegularPrivateFile(a.paths.credential, 258, true)
	if err != nil {
		return connectionState{}, err
	}
	credential = bytes.TrimSuffix(credential, []byte("\r\n"))
	credential = bytes.TrimSuffix(credential, []byte("\n"))
	connection := nodeconfig.Connection{Endpoint: endpoint, AgentID: agentID, Credential: string(credential)}
	if err := nodeconfig.Validate(connection); err != nil {
		return connectionState{}, err
	}
	return connectionState{endpoint: endpoint, agentID: agentID, credential: string(credential)}, nil
}

func readRegularPrivateFile(path string, limit int64, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file, not a symlink", path)
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must not be accessible by group or others", path)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s is unexpectedly large", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf("%s changed while opening", path)
	}
	contents, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > limit {
		return nil, fmt.Errorf("%s is unexpectedly large", path)
	}
	return contents, nil
}

func (a *app) printStatus(details bool) error {
	fmt.Fprintf(a.out, " Passwall Node %s\n", buildversion.String())
	fmt.Fprintln(a.out, "────────────────────────────────────────────")
	state, serviceErr := a.getServiceState()
	if serviceErr != nil {
		fmt.Fprintf(a.out, " [WARN] Service state unavailable: %v\n", serviceErr)
	} else if state.active == "active" && state.sub == "running" && state.pid > 0 {
		fmt.Fprintf(a.out, " [OK] Service Running (PID %d)\n", state.pid)
	} else {
		fmt.Fprintf(a.out, " [WARN] Service %s/%s\n", state.active, state.sub)
	}
	connection, connectionErr := a.readConnection()
	if connectionErr != nil {
		fmt.Fprintln(a.out, " [WARN] Panel Not configured")
	} else {
		lastSync, engine, coreVersion := a.readRuntimeSummary()
		if lastSync.IsZero() {
			fmt.Fprintln(a.out, " [WARN] Panel Configured; no completed sync yet")
		} else {
			fmt.Fprintf(a.out, " [OK] Panel Last sync %s\n", relativeTime(a.now(), lastSync))
		}
		if engine == "" {
			fmt.Fprintln(a.out, " [WARN] Core Not deployed yet")
		} else {
			fmt.Fprintf(a.out, " [OK] Core %s %s\n", engine, coreVersion)
		}
		if details {
			fmt.Fprintf(a.out, "      Endpoint %s\n      Agent ID %s\n", connection.endpoint, connection.agentID)
		}
	}
	fmt.Fprintf(a.out, "      Channel %s\n", deployChannel(buildversion.Version))
	return nil
}

// deployChannel names the published channel of the running binary, as far as it
// can be known.
//
// IT CANNOT BE KNOWN FROM THE VERSION STRING. The hyphen test is a LEGACY rule —
// right for the v-prefixed form, where a hyphen has always marked a pre-release —
// and it says nothing at all about a product version, which is three integers
// with no hyphen. Worse, the same artefact is promoted from testing to stable
// WITHOUT being rebuilt, so a channel stamped at build time would go stale the
// moment it was promoted: a binary genuinely cannot know its channel after the
// fact.
//
// So the answer is whatever the version string actually carries, and unknown when
// it carries nothing. Printing "Stable" for a fact nobody established is the
// failure this avoids — an operator reading it would believe a release had been
// approved.
func deployChannel(version string) string {
	switch {
	case version == "" || version == "dev":
		return "Unknown"
	case strings.HasPrefix(version, "v"):
		if strings.Contains(version, "-") {
			return "Beta"
		}
		return "Stable"
	default:
		// A product-scheme version: three integers, no hyphen, no channel in it.
		return "Unknown"
	}
}

func (a *app) readRuntimeSummary() (lastSync time.Time, engine, version string) {
	info, err := os.Lstat(a.paths.state)
	if err != nil || !info.Mode().IsRegular() {
		return time.Time{}, "", ""
	}
	abs, err := filepath.Abs(a.paths.state)
	if err != nil {
		return time.Time{}, "", ""
	}
	database, err := sql.Open("sqlite", "file:"+filepath.ToSlash(abs)+"?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(1000)")
	if err != nil {
		return time.Time{}, "", ""
	}
	defer database.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var accepted sql.NullInt64
	if err := database.QueryRowContext(ctx, `SELECT MAX(accepted_at_ms) FROM stream_documents`).Scan(&accepted); err == nil && accepted.Valid {
		lastSync = time.UnixMilli(accepted.Int64)
	}
	_ = database.QueryRowContext(ctx, `SELECT engine, version FROM core_deployment LIMIT 1`).Scan(&engine, &version)
	return lastSync, engine, version
}

func relativeTime(now, then time.Time) string {
	age := now.Sub(then)
	if age < 0 {
		return "just now"
	}
	if age < time.Minute {
		return fmt.Sprintf("%ds ago", int(age.Seconds()))
	}
	if age < time.Hour {
		return fmt.Sprintf("%dm ago", int(age.Minutes()))
	}
	if age < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(age.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(age.Hours()/24))
}

func (a *app) showConfig() error {
	connection, err := a.readConnection()
	if err != nil {
		return fmt.Errorf("connection is not configured: %w", err)
	}
	fmt.Fprintf(a.out, " PSP endpoint: %s\n Agent ID:     %s\n Credential:   configured (%d bytes, hidden)\n",
		connection.endpoint, connection.agentID, len(connection.credential))
	return nil
}

func (a *app) readConnectionPrompt() (nodeconfig.Connection, error) {
	fmt.Fprintln(a.out, "\n Enter the values shown by PSP. The credential is hidden and is never added to shell history.")
	endpoint, err := a.prompt("PSP sync endpoint")
	if err != nil {
		return nodeconfig.Connection{}, err
	}
	agentID, err := a.prompt("Agent ID")
	if err != nil {
		return nodeconfig.Connection{}, err
	}
	credential, err := a.secret(" Node credential: ")
	if err != nil {
		return nodeconfig.Connection{}, err
	}
	connection := nodeconfig.Connection{Endpoint: endpoint, AgentID: agentID, Credential: credential}
	if err := nodeconfig.Validate(connection); err != nil {
		return nodeconfig.Connection{}, err
	}
	fmt.Fprintf(a.out, "\n Endpoint: %s\n Agent ID: %s\n Credential: hidden (%d bytes)\n", endpoint, agentID, len(credential))
	return connection, nil
}

func (a *app) connect(rebind bool) error {
	if err := a.requireRoot(); err != nil {
		return err
	}
	if err := a.validateInstallSkeleton(); err != nil {
		return err
	}
	if err := validateManagedUnit(a.paths.unit); err != nil {
		return fmt.Errorf("systemd unit is not managed by Passwall Node: %w", err)
	}
	_, existingErr := a.readConnection()
	if !rebind && existingErr == nil {
		return errors.New("this installation is already configured; use pn rebind to replace its identity")
	}
	if rebind && existingErr != nil {
		return errors.New("no valid existing identity was found; use pn connect")
	}
	if !rebind {
		environmentExists := pathExists(a.paths.environment)
		credentialExists := pathExists(a.paths.credential)
		if environmentExists || credentialExists {
			return errors.New("partial connection files exist; run pn doctor and inspect them before continuing")
		}
	}
	connection, err := a.readConnectionPrompt()
	if err != nil {
		return err
	}
	confirmationLabel := "Configure and start Passwall Node? [y/N]"
	if rebind {
		confirmationLabel = "Type REBIND to replace the identity and reset runtime state"
	}
	confirmation, err := a.prompt(confirmationLabel)
	if err != nil {
		return err
	}
	if (!rebind && !strings.EqualFold(confirmation, "y") && !strings.EqualFold(confirmation, "yes")) || (rebind && confirmation != "REBIND") {
		return errors.New("configuration cancelled")
	}
	if rebind {
		return a.applyRebind(connection)
	}
	if err := a.writeConnection(connection); err != nil {
		// A first-time connect starts from an explicitly verified empty state.
		// Do not strand half a connection that would block the next attempt.
		_ = os.Remove(a.paths.environment)
		_ = os.Remove(a.paths.credential)
		return err
	}
	if err := a.enableAndStart(); err != nil {
		return fmt.Errorf("connection saved, but service startup failed: %w", err)
	}
	fmt.Fprintln(a.out, " [OK] Connection saved and Passwall Node started.")
	fmt.Fprintln(a.out, " Verify the first heartbeat, core state and proxy traffic in PSP.")
	return nil
}

func (a *app) applyRebind(connection nodeconfig.Connection) (resultErr error) {
	systemctl, err := a.systemctlPath()
	if err != nil {
		return err
	}
	previousState, err := a.getServiceState()
	if err != nil {
		return fmt.Errorf("read service state before rebind: %w", err)
	}
	wasRunning := previousState.active == "active"
	ctx, cancel := a.context()
	if err := a.runner.Run(ctx, a.in, a.out, a.errOut, systemctl, "stop", serviceName); err != nil {
		cancel()
		return fmt.Errorf("stop service before rebind: %w", err)
	}
	cancel()

	var oldEnvironment, oldCredential []byte
	var oldData string
	dataMoved := false
	connectionMayHaveChanged := false
	defer func() {
		if resultErr == nil {
			return
		}
		var rollbackErrors []error
		if dataMoved {
			if err := os.RemoveAll(a.paths.data); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("remove replacement state: %w", err))
			}
			if err := os.Rename(oldData, a.paths.data); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("restore previous state: %w", err))
			}
		}
		if connectionMayHaveChanged {
			if err := atomicWrite(a.paths.environment, oldEnvironment, 0o600); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("restore environment: %w", err))
			}
			if err := atomicWrite(a.paths.credential, oldCredential, 0o600); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("restore credential: %w", err))
			}
			if err := a.chownManagedPath(a.paths.environment); err != nil {
				rollbackErrors = append(rollbackErrors, err)
			}
			if err := a.chownManagedPath(a.paths.credential); err != nil {
				rollbackErrors = append(rollbackErrors, err)
			}
		}
		if wasRunning {
			ctxRestart, cancelRestart := a.context()
			if err := a.runner.Run(ctxRestart, a.in, a.out, a.errOut, systemctl, "start", serviceName); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("restart previous service: %w", err))
			}
			cancelRestart()
		}
		if len(rollbackErrors) != 0 {
			resultErr = errors.Join(resultErr, fmt.Errorf("automatic rollback was incomplete: %w", errors.Join(rollbackErrors...)))
		}
	}()

	stamp := a.now().UTC().Format("20060102T150405Z")
	backup := filepath.Join(a.paths.root, "backups", "rebind-"+stamp)
	if err := ensureRealPrivateDirectory(filepath.Dir(backup)); err != nil {
		return fmt.Errorf("create rebind backup directory: %w", err)
	}
	if err := os.Mkdir(backup, 0o700); err != nil {
		return fmt.Errorf("create rebind backup: %w", err)
	}
	oldEnvironment, err = os.ReadFile(a.paths.environment)
	if err != nil {
		return err
	}
	oldCredential, err = os.ReadFile(a.paths.credential)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(backup, "environment"), oldEnvironment, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(backup, "credential"), oldCredential, 0o600); err != nil {
		return err
	}
	oldData = filepath.Join(backup, "data")
	if err := os.Rename(a.paths.data, oldData); err != nil {
		return fmt.Errorf("move old runtime state into backup: %w", err)
	}
	dataMoved = true
	if err := os.Mkdir(a.paths.data, 0o700); err != nil {
		return err
	}
	if err := a.chownManagedPath(a.paths.data); err != nil {
		return err
	}
	connectionMayHaveChanged = true
	if err := a.writeConnection(connection); err != nil {
		return err
	}
	ctxStart, cancelStart := a.context()
	defer cancelStart()
	if err := a.runner.Run(ctxStart, a.in, a.out, a.errOut, systemctl, "start", serviceName); err != nil {
		return fmt.Errorf("start rebound service: %w", err)
	}
	fmt.Fprintf(a.out, " [OK] Rebound and started. Previous identity and state: %s\n", backup)
	return nil
}

func (a *app) writeConnection(connection nodeconfig.Connection) error {
	if err := nodeconfig.Validate(connection); err != nil {
		return err
	}
	if err := atomicWrite(a.paths.credential, []byte(connection.Credential+"\n"), 0o600); err != nil {
		return fmt.Errorf("write credential: %w", err)
	}
	if err := atomicWrite(a.paths.environment, []byte(nodeconfig.EnvironmentFile(connection)), 0o600); err != nil {
		return fmt.Errorf("write environment: %w", err)
	}
	if err := a.chownManagedPath(a.paths.credential); err != nil {
		return err
	}
	if err := a.chownManagedPath(a.paths.environment); err != nil {
		return err
	}
	return nil
}

func atomicWrite(path string, contents []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s must be a real directory", directory)
	}
	if target, err := os.Lstat(path); err == nil && target.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to replace symlink %s", path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".pn-write-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
}

func (a *app) chownManagedPath(path string) error {
	uid, gid, err := a.owner()
	if err != nil {
		return err
	}
	if err := a.chown(path, uid, gid); err != nil {
		return fmt.Errorf("set ownership on %s: %w", path, err)
	}
	return nil
}

func (a *app) enableAndStart() error {
	systemctl, err := a.systemctlPath()
	if err != nil {
		return err
	}
	ctx, cancel := a.context()
	defer cancel()
	if err := a.runner.Run(ctx, a.in, a.out, a.errOut, systemctl, "daemon-reload"); err != nil {
		return err
	}
	ctxStart, cancelStart := a.context()
	defer cancelStart()
	return a.runner.Run(ctxStart, a.in, a.out, a.errOut, systemctl, "enable", "--now", serviceName)
}

func (a *app) validateInstallSkeleton() error {
	for _, check := range []struct {
		path       string
		directory  bool
		executable bool
	}{
		{a.paths.root, true, false}, {filepath.Dir(a.paths.binary), true, false}, {a.paths.config, true, false},
		{a.paths.data, true, false}, {a.paths.binary, false, true}, {a.paths.unitSource, false, false},
	} {
		info, err := os.Lstat(check.path)
		if err != nil {
			return fmt.Errorf("installation is incomplete: %s: %w", check.path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || check.directory != info.IsDir() || (!check.directory && !info.Mode().IsRegular()) {
			return fmt.Errorf("installation path has an unsafe type: %s", check.path)
		}
		if check.executable && info.Mode()&0o111 == 0 {
			return fmt.Errorf("installation binary is not executable: %s", check.path)
		}
	}
	return nil
}

func serviceOwner() (int, int, error) {
	account, err := user.Lookup(serviceUser)
	if err != nil {
		return 0, 0, fmt.Errorf("look up %s account: %w", serviceUser, err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid == 0 {
		return 0, 0, errors.New("passwall-node account has an invalid UID")
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return 0, 0, errors.New("passwall-node account has an invalid GID")
	}
	return uid, gid, nil
}

func (a *app) doctor() error {
	fmt.Fprintln(a.out, " Passwall Node diagnostics")
	failed := false
	check := func(name string, err error) {
		if err != nil {
			failed = true
			fmt.Fprintf(a.out, " [FAIL] %-22s %v\n", name, err)
		} else {
			fmt.Fprintf(a.out, " [OK]   %s\n", name)
		}
	}
	check("Installation layout", a.validateInstallSkeleton())
	check("Managed systemd unit", validateManagedUnit(a.paths.unit))
	_, connectionErr := a.readConnection()
	check("Panel connection files", connectionErr)
	_, serviceErr := a.getServiceState()
	check("systemd service", serviceErr)
	check("pn command link", a.validatePNLink())
	if failed {
		return errors.New("one or more diagnostic checks failed")
	}
	fmt.Fprintln(a.out, " [OK] Diagnostics completed.")
	return nil
}

func (a *app) validatePNLink() error {
	info, err := os.Lstat(a.paths.pnLink)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return errors.New("pn path is not the managed symlink")
	}
	target, err := os.Readlink(a.paths.pnLink)
	if err != nil {
		return err
	}
	if target != a.paths.binary {
		return fmt.Errorf("pn points to %s", target)
	}
	return nil
}

func (a *app) repair() error {
	if err := a.requireRoot(); err != nil {
		return err
	}
	if err := a.validateInstallSkeleton(); err != nil {
		return err
	}
	if pathExists(a.paths.unit) {
		if err := validateManagedUnit(a.paths.unit); err != nil {
			return fmt.Errorf("existing systemd unit is not managed by Passwall Node: %w", err)
		}
	}
	if pathExists(a.paths.pnLink) {
		if err := a.validatePNLink(); err != nil {
			return errors.New("existing pn command is not managed by Passwall Node; it was not replaced")
		}
	}
	unitContents, err := os.ReadFile(a.paths.unitSource)
	if err != nil {
		return err
	}
	if err := atomicWrite(a.paths.unit, unitContents, 0o644); err != nil {
		return err
	}
	if !pathExists(a.paths.pnLink) {
		if err := os.Symlink(a.paths.binary, a.paths.pnLink); err != nil {
			return fmt.Errorf("create pn command link: %w", err)
		}
	}
	systemctl, err := a.systemctlPath()
	if err != nil {
		return err
	}
	ctx, cancel := a.context()
	defer cancel()
	if err := a.runner.Run(ctx, a.in, a.out, a.errOut, systemctl, "daemon-reload"); err != nil {
		return err
	}
	fmt.Fprintln(a.out, " [OK] Service unit and pn command link repaired.")
	return nil
}

func (a *app) uninstall() error {
	if err := a.requireRoot(); err != nil {
		return err
	}
	if err := a.validateInstallSkeleton(); err != nil {
		return err
	}
	if err := validateManagedUnit(a.paths.unit); err != nil {
		return fmt.Errorf("refusing to remove an unmanaged systemd unit: %w", err)
	}
	if err := a.validatePNLink(); err != nil {
		return fmt.Errorf("refusing to remove an unmanaged pn command: %w", err)
	}
	confirmation, err := a.prompt("Type UNINSTALL to disable the service and move the installation to a recoverable backup")
	if err != nil {
		return err
	}
	if confirmation != "UNINSTALL" {
		return errors.New("uninstall cancelled")
	}
	systemctl, err := a.systemctlPath()
	if err != nil {
		return err
	}
	ctx, cancel := a.context()
	defer cancel()
	if err := a.runner.Run(ctx, a.in, a.out, a.errOut, systemctl, "disable", "--now", serviceName); err != nil {
		return fmt.Errorf("disable service: %w", err)
	}
	if err := os.Remove(a.paths.unit); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := a.validatePNLink(); err == nil {
		if err := os.Remove(a.paths.pnLink); err != nil {
			return err
		}
	}
	backup := a.paths.root + ".uninstalled-" + a.now().UTC().Format("20060102T150405Z")
	if err := os.Rename(a.paths.root, backup); err != nil {
		return fmt.Errorf("retain installation backup: %w", err)
	}
	ctxReload, cancelReload := a.context()
	defer cancelReload()
	_ = a.runner.Run(ctxReload, a.in, a.out, a.errOut, systemctl, "daemon-reload")
	fmt.Fprintf(a.out, " [OK] Service uninstalled. Recoverable files retained at %s\n", backup)
	return nil
}

func validateManagedUnit(path string) error {
	contents, err := readRegularPrivateFile(path, 64*1024, false)
	if err != nil {
		return err
	}
	text := string(contents)
	for _, required := range []string{
		"User=passwall-node\n",
		"Group=passwall-node\n",
		"EnvironmentFile=/opt/passwall-node/config/environment\n",
		"ExecStart=/opt/passwall-node/bin/passwall-node ",
		"--credential-file /opt/passwall-node/config/credential ",
		"--data-dir /opt/passwall-node/data\n",
	} {
		if !strings.Contains(text, required) {
			return fmt.Errorf("%s is missing the managed service contract", path)
		}
	}
	return nil
}

func (a *app) upgradeGuidance() error {
	fmt.Fprintln(a.out, ` Passwall Node upgrades
 [OK] Recommended: issue an upgrade from PSP. It is version-pinned,
      authenticated, transactional and reports its result back to PSP.
 [INFO] The public GitHub installer is for a fresh, unconfigured installation;
        it never overwrites an existing configured node.`)
	return nil
}

func (a *app) backup() (resultErr error) {
	if err := a.requireRoot(); err != nil {
		return err
	}
	if err := a.validateInstallSkeleton(); err != nil {
		return err
	}
	state, err := a.getServiceState()
	if err != nil {
		return fmt.Errorf("read service state before backup: %w", err)
	}
	systemctl, err := a.systemctlPath()
	if err != nil {
		return err
	}
	wasRunning := state.active == "active"
	if wasRunning {
		ctx, cancel := a.context()
		err = a.runner.Run(ctx, a.in, a.out, a.errOut, systemctl, "stop", serviceName)
		cancel()
		if err != nil {
			return fmt.Errorf("stop service for backup: %w", err)
		}
	}
	defer func() {
		if !wasRunning {
			return
		}
		ctx, cancel := a.context()
		err := a.runner.Run(ctx, a.in, a.out, a.errOut, systemctl, "start", serviceName)
		cancel()
		if err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("restart service after backup: %w", err))
		}
	}()

	backupRoot := filepath.Join(a.paths.root, "backups")
	if err := ensureRealPrivateDirectory(backupRoot); err != nil {
		return fmt.Errorf("create backup directory: %w", err)
	}
	backupPath := filepath.Join(backupRoot, "manual-"+a.now().UTC().Format("20060102T150405.000000000Z"))
	if err := os.Mkdir(backupPath, 0o700); err != nil {
		return fmt.Errorf("create backup snapshot: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(backupPath)
		}
	}()
	for _, source := range []string{a.paths.config, a.paths.data} {
		if err := copyPrivateTree(source, filepath.Join(backupPath, filepath.Base(source))); err != nil {
			return fmt.Errorf("copy %s: %w", source, err)
		}
	}
	if err := copyPrivateTree(a.paths.unitSource, filepath.Join(backupPath, serviceName)); err != nil {
		return fmt.Errorf("copy service definition: %w", err)
	}
	complete = true
	fmt.Fprintf(a.out, " [OK] Private backup created at %s\n", backupPath)
	fmt.Fprintln(a.out, " Keep it protected: it contains the long-lived node credential and runtime state.")
	return nil
}

func copyPrivateTree(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symbolic link %s", source)
	}
	if info.IsDir() {
		if err := os.Mkdir(destination, 0o700); err != nil {
			return err
		}
		entries, err := os.ReadDir(source)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := copyPrivateTree(filepath.Join(source, entry.Name()), filepath.Join(destination, entry.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing non-regular file %s", source)
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	openedInfo, err := input.Stat()
	if err != nil {
		return err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return fmt.Errorf("source changed while opening %s", source)
	}
	mode := os.FileMode(0o600)
	if openedInfo.Mode().Perm()&0o100 != 0 {
		mode = 0o700
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	copyErr := error(nil)
	if _, err := io.Copy(output, input); err != nil {
		copyErr = err
	} else if err := output.Sync(); err != nil {
		copyErr = err
	}
	if err := output.Close(); copyErr == nil {
		copyErr = err
	}
	if copyErr != nil {
		_ = os.Remove(destination)
	}
	return copyErr
}

func ensureRealPrivateDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s must be a real directory", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s must not be accessible by group or others", path)
	}
	return nil
}

func (a *app) printPaths() {
	fmt.Fprintf(a.out, ` Installation: %s
 Binary:       %s
 Connection:   %s
 Credential:   %s
 State:        %s
 Service unit: %s
 Command link: %s
`, a.paths.root, a.paths.binary, a.paths.environment, a.paths.credential, a.paths.data, a.paths.unit, a.paths.pnLink)
}

func (a *app) requireRoot() error {
	if a.euid() != 0 {
		return errors.New("this operation changes the system installation; run pn as root")
	}
	return nil
}

func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func readTerminalSecret(prompt string, out io.Writer) (string, error) {
	terminal, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("a terminal is required to enter the node credential")
	}
	defer terminal.Close()
	if _, err := fmt.Fprint(out, prompt); err != nil {
		return "", err
	}
	secret, err := term.ReadPassword(int(terminal.Fd()))
	if _, writeErr := fmt.Fprintln(out); err == nil && writeErr != nil {
		err = writeErr
	}
	if err != nil {
		return "", err
	}
	return string(secret), nil
}

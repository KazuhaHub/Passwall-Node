package manage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/KazuhaHub/passwall-node/v4/corecatalog"
	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/host"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// DoctorSchemaVersion is the shape of the doctor's JSON output. It is a version
// of its own so a consumer can tell a field it does not know from a field that
// is missing.
const DoctorSchemaVersion = 1

// DoctorStatus is one check's outcome.
//
// WARNING AND FAILED ARE DIFFERENT QUESTIONS. A warning is "this works but is
// not what it should be"; a failed check is "this is broken". Only failures
// change the exit code, because only failures mean the node cannot do its job —
// and a diagnostic that exits non-zero for a cosmetic finding is one nobody
// runs twice.
type DoctorStatus string

const (
	DoctorOK          DoctorStatus = "ok"
	DoctorWarning     DoctorStatus = "warning"
	DoctorFailed      DoctorStatus = "failed"
	DoctorUnavailable DoctorStatus = "unavailable"
)

// maxSummaryBytes bounds one check's summary. The value reaches a screen and a
// log line, and a truncated summary is more useful than an unbounded one that a
// consumer has to defend against.
const maxSummaryBytes = 512

// Stable check codes. They are output surface, and a consumer may key on them,
// so a published code is never renamed — a changed meaning gets a new code.
//
// THE VALUES LIVE IN protocol BECAUSE THE SAME CODES CROSS THE WIRE in a
// diagnostics result. Two copies of one vocabulary drift; these are aliases.
const (
	CheckInstallationLayout        = protocol.CheckCodeInstallationLayout
	CheckCredentialPermissions     = protocol.CheckCodeCredentialPermissions
	CheckDataDirAccess             = protocol.CheckCodeDataDirAccess
	CheckStateSQLiteOpen           = protocol.CheckCodeStateSQLiteOpen
	CheckStateSQLiteQuickCheck     = protocol.CheckCodeStateSQLiteQuickCheck
	CheckCoreSelection             = protocol.CheckCodeCoreSelection
	CheckCoreBinaryDigest          = protocol.CheckCodeCoreBinaryDigest
	CheckCoreConfirmedConfigDigest = protocol.CheckCodeCoreConfirmedConfigDigest
	CheckCollectorHost             = protocol.CheckCodeCollectorHost
	CheckCollectorProcess          = protocol.CheckCodeCollectorProcess
)

// DoctorCheck is one check's result.
//
// EVERY CHECK PRODUCES EXACTLY ONE, INCLUDING THE ONES THAT DO NOT APPLY: an
// item that is missing from the output is indistinguishable from one the
// running binary does not know about, and the caller cannot tell "not
// applicable here" from "you are running an older doctor".
type DoctorCheck struct {
	Code    string       `json:"code"`
	Status  DoctorStatus `json:"status"`
	Summary string       `json:"summary"`
}

// DoctorReport is the whole diagnostic.
type DoctorReport struct {
	SchemaVersion int                       `json:"schema_version"`
	CollectedAtMS int64                     `json:"collected_at_ms"`
	Host          *protocol.HostObservation `json:"host"`
	Checks        []DoctorCheck             `json:"checks"`
}

// Failed reports whether any check failed, which is what the exit code follows.
func (r DoctorReport) Failed() bool {
	for _, check := range r.Checks {
		if check.Status == DoctorFailed {
			return true
		}
	}
	return false
}

// DoctorOptions are the doctor's inputs.
//
// THERE ARE NO DEFAULTS FOR THE PATHS. The daemon has none either — the data
// directory and the credential are supplied on its command line — so a doctor
// that invented them could report a clean bill of health for a layout nothing is
// actually using.
type DoctorOptions struct {
	DataDir        string
	CredentialFile string
	InstallRoot    string
	// Collector is nil on a platform with no host collector, which is a
	// legitimate answer rather than an error.
	Collector host.Collector
	Core      func() (agentcore.ProcessHandle, bool)
	Now       func() time.Time
}

// RunDoctor performs the local checks.
//
// IT CONNECTS TO NOTHING AND CHANGES NOTHING. It opens no socket, starts no
// core, runs no migration, does not touch permissions, and never reads the
// credential's CONTENTS — only its mode and type. A diagnostic that could alter
// what it inspects is one that cannot be run on a machine in trouble.
func RunDoctor(ctx context.Context, options DoctorOptions) DoctorReport {
	now := options.Now
	if now == nil {
		now = time.Now
	}
	// The collector runs ONCE, and its result serves both the host section and
	// the collector.host check. Running it twice could report a sample that is
	// not the one in the report.
	observation, collectErr := runCollector(ctx, options)

	checks := []DoctorCheck{
		checkInstallationLayout(options),
		checkCredentialPermissions(options),
		checkDataDirAccess(options),
		checkCollectorHost(options, observation, collectErr),
		checkCollectorProcess(options),
	}
	checks = append(checks, inspectState(ctx, options)...)
	// The bound is applied in ONE place, at assembly, so a future check cannot
	// forget it — the summaries are the part of this output a person reads and a
	// log line stores, and neither should have to defend against a long one.
	for index := range checks {
		checks[index].Summary = truncateSummary(checks[index].Summary)
	}
	sort.Slice(checks, func(left, right int) bool { return checks[left].Code < checks[right].Code })
	return DoctorReport{
		SchemaVersion: DoctorSchemaVersion,
		CollectedAtMS: now().UTC().UnixMilli(),
		Host:          observation,
		Checks:        checks,
	}
}

// runCollector runs the same collector the agent uses, so the doctor cannot
// disagree with what the node would report in production.
func runCollector(ctx context.Context, options DoctorOptions) (*protocol.HostObservation, error) {
	if options.Collector == nil {
		return nil, errors.New("no host collector on this platform")
	}
	observation, err := options.Collector.Collect(ctx)
	if err != nil {
		return nil, err
	}
	return &observation, nil
}

func checkCollectorHost(options DoctorOptions, observation *protocol.HostObservation, collectErr error) DoctorCheck {
	const code = CheckCollectorHost
	if options.Collector == nil {
		return DoctorCheck{Code: code, Status: DoctorUnavailable,
			Summary: "this platform has no host collector"}
	}
	if collectErr != nil {
		return DoctorCheck{Code: code, Status: DoctorFailed,
			Summary: "the host collector could not produce a sample"}
	}
	unavailable := len(observation.Unavailable)
	return DoctorCheck{Code: code, Status: doctorStatusFor(unavailable), Summary: fmt.Sprintf(
		"collected scope=%s/%s with %d sections unavailable",
		observation.Scope.Deployment, observation.Scope.ResourceScope, unavailable)}
}

// doctorStatusFor downgrades a check to a warning when something was readable
// but incomplete. A partial answer is worth reporting and is not a failure.
func doctorStatusFor(unavailable int) DoctorStatus {
	if unavailable > 0 {
		return DoctorWarning
	}
	return DoctorOK
}

func checkCollectorProcess(options DoctorOptions) DoctorCheck {
	const code = CheckCollectorProcess
	if options.Core == nil {
		return DoctorCheck{Code: code, Status: DoctorUnavailable,
			Summary: "no core supervisor is available to this command"}
	}
	handle, running := options.Core()
	if !running {
		// A core that is not running is a state, not a fault: the doctor may well
		// be run on a node whose core is deliberately stopped.
		return DoctorCheck{Code: code, Status: DoctorUnavailable, Summary: "no core process is running"}
	}
	if !handle.Verifiable() {
		return DoctorCheck{Code: code, Status: DoctorWarning,
			Summary: "a core is running but this platform cannot verify which process it is"}
	}
	return DoctorCheck{Code: code, Status: DoctorOK,
		Summary: "the running core carries a verifiable process identity"}
}

// checkInstallationLayout inspects the on-disk layout.
//
// IT RECOGNISES A LAYOUT RATHER THAN REQUIRING ONE. The agent runs from a systemd
// install, from a container, and from a hand-run binary, and only the first two
// have a managed layout to check. A layout that is absent is reported as such,
// not as a failure — the doctor does not get to decide the node was installed
// wrongly.
func checkInstallationLayout(options DoctorOptions) DoctorCheck {
	const code = CheckInstallationLayout
	if options.DataDir == "" {
		return DoctorCheck{Code: code, Status: DoctorFailed, Summary: "no data directory was supplied"}
	}
	info, err := os.Stat(options.DataDir)
	if err != nil {
		return DoctorCheck{Code: code, Status: DoctorFailed, Summary: "the data directory is not readable"}
	}
	if !info.IsDir() {
		return DoctorCheck{Code: code, Status: DoctorFailed, Summary: "the data directory is not a directory"}
	}

	recognised := "none"
	var missing []string
	root := options.InstallRoot
	if root != "" {
		if rootInfo, err := os.Stat(root); err == nil && rootInfo.IsDir() {
			recognised = "systemd"
			for _, entry := range []string{"bin", "config"} {
				if _, err := os.Stat(filepath.Join(root, entry)); err != nil {
					missing = append(missing, entry)
				}
			}
		}
	}
	if recognised == "none" {
		if _, err := os.Stat(upgradeDockerBinaryPath); err == nil {
			recognised = "docker"
		}
	}
	if len(missing) > 0 {
		return DoctorCheck{Code: code, Status: DoctorWarning, Summary: fmt.Sprintf(
			"the %s layout is missing: %s", recognised, strings.Join(missing, ", "))}
	}
	return DoctorCheck{Code: code, Status: DoctorOK,
		Summary: "the data directory is usable; recognised layout: " + recognised}
}

// upgradeDockerBinaryPath mirrors the container layout's binary location. It is
// duplicated as a constant rather than imported so the doctor does not depend on
// the upgrade package.
const upgradeDockerBinaryPath = "/usr/local/bin/passwall-node"

// checkCredentialPermissions inspects the credential's TYPE AND MODE, never its
// contents.
//
// Reading it would put a live secret into a diagnostic that is meant to be
// pasted into a bug report, and its length and permissions are the whole
// question anyway.
func checkCredentialPermissions(options DoctorOptions) DoctorCheck {
	const code = CheckCredentialPermissions
	if options.CredentialFile == "" {
		return DoctorCheck{Code: code, Status: DoctorUnavailable,
			Summary: "no credential file was supplied"}
	}
	// Lstat, not Stat: a symlink is refused for the same reason the daemon
	// refuses one, and following it would answer a different question.
	info, err := os.Lstat(options.CredentialFile)
	if err != nil {
		return DoctorCheck{Code: code, Status: DoctorFailed, Summary: "the credential file is not readable"}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return DoctorCheck{Code: code, Status: DoctorFailed, Summary: "the credential is a symbolic link"}
	}
	if !info.Mode().IsRegular() {
		return DoctorCheck{Code: code, Status: DoctorFailed, Summary: "the credential is not a regular file"}
	}
	if info.Mode().Perm()&0o077 != 0 {
		return DoctorCheck{Code: code, Status: DoctorFailed,
			Summary: fmt.Sprintf("the credential is readable beyond its owner (mode %04o)", info.Mode().Perm())}
	}
	return DoctorCheck{Code: code, Status: DoctorOK, Summary: "the credential is a private regular file"}
}

// checkDataDirAccess proves the data directory is writable by creating a probe.
//
// O_CREATE|O_EXCL WITH A RANDOM NAME, so it cannot collide with anything and
// cannot silently adopt an existing file. It is removed immediately, and the
// name never reaches the output: a diagnostic that leaves files behind, or
// reports the names it created, is one that makes the situation it was called to
// investigate worse.
func checkDataDirAccess(options DoctorOptions) DoctorCheck {
	const code = CheckDataDirAccess
	if options.DataDir == "" {
		return DoctorCheck{Code: code, Status: DoctorFailed, Summary: "no data directory was supplied"}
	}
	probe := filepath.Join(options.DataDir, fmt.Sprintf(".doctor-probe-%d", time.Now().UnixNano()))
	file, err := os.OpenFile(probe, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return DoctorCheck{Code: code, Status: DoctorFailed, Summary: "the data directory is not writable"}
	}
	// The cleanup runs on every path below, including the failures, so a probe
	// that could not be synced is still removed.
	defer func() { _ = os.Remove(probe) }()
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return DoctorCheck{Code: code, Status: DoctorFailed, Summary: "a file in the data directory could not be synced"}
	}
	if err := file.Close(); err != nil {
		return DoctorCheck{Code: code, Status: DoctorFailed, Summary: "a file in the data directory could not be closed"}
	}
	if err := os.Remove(probe); err != nil {
		return DoctorCheck{Code: code, Status: DoctorFailed, Summary: "a test file in the data directory could not be removed"}
	}
	return DoctorCheck{Code: code, Status: DoctorOK, Summary: "the data directory is writable"}
}

// stateSnapshot is what the state database inspection produced.
type stateSnapshot struct {
	opened        bool
	engine        string
	version       string
	configDigest  string
	deploymentErr error
}

// inspectState opens the state database READ-ONLY and reports what it found.
//
// A MISSING DATABASE IS NOT A FAILURE. A node that has never completed a sync
// has no state file, and that is a fact about the node rather than a fault in
// it. A database that exists and cannot be opened is different: something is
// there and it is not usable.
func inspectState(ctx context.Context, options DoctorOptions) []DoctorCheck {
	checks := []DoctorCheck{
		{Code: CheckStateSQLiteOpen, Status: DoctorUnavailable, Summary: "no data directory was supplied"},
		{Code: CheckStateSQLiteQuickCheck, Status: DoctorUnavailable, Summary: "the state database was not opened"},
		{Code: CheckCoreSelection, Status: DoctorUnavailable, Summary: "the state database was not read"},
		{Code: CheckCoreBinaryDigest, Status: DoctorUnavailable, Summary: "no core is selected"},
		{Code: CheckCoreConfirmedConfigDigest, Status: DoctorUnavailable, Summary: "the state database was not read"},
	}
	if options.DataDir == "" {
		return checks
	}
	path := filepath.Join(options.DataDir, stateDatabaseName)
	if _, err := os.Stat(path); err != nil {
		checks[0] = DoctorCheck{Code: CheckStateSQLiteOpen, Status: DoctorUnavailable,
			Summary: "the state database has not been created yet"}
		return checks
	}
	// Read-only, and NO MIGRATION. The daemon's own open applies schema
	// migrations; a diagnostic that did the same would modify the thing it was
	// asked to inspect, and would do it while the agent it is diagnosing may be
	// running.
	database, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		checks[0] = DoctorCheck{Code: CheckStateSQLiteOpen, Status: DoctorFailed,
			Summary: "the state database could not be opened"}
		return checks
	}
	defer database.Close()
	if err := database.PingContext(ctx); err != nil {
		checks[0] = DoctorCheck{Code: CheckStateSQLiteOpen, Status: DoctorFailed,
			Summary: "the state database could not be opened read-only"}
		return checks
	}
	checks[0] = DoctorCheck{Code: CheckStateSQLiteOpen, Status: DoctorOK,
		Summary: "the state database opens read-only"}

	checks[1] = checkQuickCheck(ctx, database)

	snapshot := readDeployment(ctx, database)
	checks[2], checks[3], checks[4] = coreChecks(options, snapshot)
	return checks
}

const stateDatabaseName = "state.db"

func checkQuickCheck(ctx context.Context, database *sql.DB) DoctorCheck {
	const code = CheckStateSQLiteQuickCheck
	var result string
	// quick_check scans for structural damage without the expensive index
	// comparison integrity_check performs. On a node whose disk is suspect, the
	// cheap answer that returns is worth more than the thorough one that does
	// not.
	if err := database.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&result); err != nil {
		return DoctorCheck{Code: code, Status: DoctorFailed, Summary: "the state database did not answer a consistency check"}
	}
	if result != "ok" {
		// The result is a list of problems and can be long; only the count
		// reaches the output, since it is a diagnostic, not a data dump.
		return DoctorCheck{Code: code, Status: DoctorFailed,
			Summary: fmt.Sprintf("the state database reported %d consistency problems", strings.Count(result, "\n")+1)}
	}
	return DoctorCheck{Code: code, Status: DoctorOK, Summary: "the state database passed its consistency check"}
}

// readDeployment reads the confirmed deployment.
//
// It reads the columns the doctor reports and NOT the artifact, config or roster
// bodies: those are the node's configuration, and a diagnostic that carried them
// would be one nobody could safely share.
func readDeployment(ctx context.Context, database *sql.DB) stateSnapshot {
	snapshot := stateSnapshot{opened: true}
	row := database.QueryRowContext(ctx,
		`SELECT engine, version, config_digest FROM core_deployment WHERE id = 1`)
	if err := row.Scan(&snapshot.engine, &snapshot.version, &snapshot.configDigest); err != nil {
		snapshot.deploymentErr = err
	}
	return snapshot
}

func coreChecks(options DoctorOptions, snapshot stateSnapshot) (selection, binaryDigest, configDigest DoctorCheck) {
	selection = DoctorCheck{Code: CheckCoreSelection, Status: DoctorUnavailable,
		Summary: "no core deployment has been confirmed yet"}
	binaryDigest = DoctorCheck{Code: CheckCoreBinaryDigest, Status: DoctorUnavailable,
		Summary: "no core is selected"}
	configDigest = DoctorCheck{Code: CheckCoreConfirmedConfigDigest, Status: DoctorUnavailable,
		Summary: "no core deployment has been confirmed yet"}
	if snapshot.deploymentErr != nil {
		return selection, binaryDigest, configDigest
	}
	selection = DoctorCheck{Code: CheckCoreSelection, Status: DoctorOK,
		Summary: fmt.Sprintf("core %s %s is selected", snapshot.engine, snapshot.version)}

	if !wellFormedDigest(snapshot.configDigest) {
		configDigest = DoctorCheck{Code: CheckCoreConfirmedConfigDigest, Status: DoctorFailed,
			Summary: "the confirmed configuration digest is not a sha256 digest"}
	} else {
		configDigest = DoctorCheck{Code: CheckCoreConfirmedConfigDigest, Status: DoctorOK,
			Summary: "a confirmed configuration digest is recorded"}
	}
	return selection, inspectCoreBinary(options, snapshot), configDigest
}

func wellFormedDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

// inspectCoreBinary hashes the installed core and compares it with what the
// installation recorded.
//
// The comparison is against the INSTALLER'S OWN RECORD, not the catalog's
// archive digest: the catalog publishes the digest of a compressed archive, and
// comparing that to an extracted binary would fail on every healthy node.
func inspectCoreBinary(options DoctorOptions, snapshot stateSnapshot) DoctorCheck {
	const code = CheckCoreBinaryDigest
	if snapshot.engine == "" || snapshot.version == "" {
		return DoctorCheck{Code: code, Status: DoctorUnavailable, Summary: "no core is selected"}
	}
	if options.DataDir == "" {
		return DoctorCheck{Code: code, Status: DoctorUnavailable, Summary: "no data directory was supplied"}
	}
	release, err := corecatalog.Resolve(snapshot.engine, snapshot.version)
	if err != nil {
		return DoctorCheck{Code: code, Status: DoctorUnavailable,
			Summary: "the selected core version is not in this binary's catalog"}
	}
	asset, err := release.AssetFor(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return DoctorCheck{Code: code, Status: DoctorUnavailable,
			Summary: "the catalog has no asset for this platform"}
	}
	directory := filepath.Join(options.DataDir, "cores", snapshot.engine, "versions", snapshot.version)
	metadataPath := filepath.Join(directory, "metadata.json")
	raw, err := os.ReadFile(metadataPath)
	if err != nil {
		return DoctorCheck{Code: code, Status: DoctorUnavailable,
			Summary: "the installed core has no installation record"}
	}
	var record struct {
		BinarySHA256 string `json:"binary_sha256"`
	}
	if err := json.Unmarshal(raw, &record); err != nil || !wellFormedDigest(record.BinarySHA256) {
		return DoctorCheck{Code: code, Status: DoctorFailed,
			Summary: "the installed core's installation record is unreadable"}
	}
	binaryPath := filepath.Join(directory, asset.Binary)
	actual, err := digestFile(binaryPath)
	if err != nil {
		return DoctorCheck{Code: code, Status: DoctorFailed, Summary: "the installed core binary is missing or unreadable"}
	}
	if actual != record.BinarySHA256 {
		return DoctorCheck{Code: code, Status: DoctorFailed,
			Summary: "the installed core binary does not match the digest it was installed with"}
	}
	return DoctorCheck{Code: code, Status: DoctorOK, Summary: "the installed core binary matches its recorded digest"}
}

// truncateSummary enforces the output bound without splitting a rune.
//
// It cuts on a boundary rather than by bytes: a summary is rendered to a person,
// and half a multi-byte character is mojibake rather than a truncated word.
func truncateSummary(summary string) string {
	if len(summary) <= maxSummaryBytes {
		return summary
	}
	const suffix = "…"
	cut := maxSummaryBytes - len(suffix)
	for cut > 0 && !utf8.RuneStart(summary[cut]) {
		cut--
	}
	return summary[:cut] + suffix
}

func digestFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

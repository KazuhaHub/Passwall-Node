package manage

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentcore "github.com/KazuhaHub/passwall-node/internal/core"
)

// everyStableCode is the set the first version must always report, in the order
// the output sorts them.
var everyStableCode = []string{
	CheckCollectorHost,
	CheckCollectorProcess,
	CheckCoreBinaryDigest,
	CheckCoreConfirmedConfigDigest,
	CheckCoreSelection,
	CheckCredentialPermissions,
	CheckDataDirAccess,
	CheckInstallationLayout,
	CheckStateSQLiteOpen,
	CheckStateSQLiteQuickCheck,
}

// AN ITEM THAT IS MISSING IS INDISTINGUISHABLE FROM ONE THIS BINARY DOES NOT
// KNOW ABOUT. A caller cannot tell "not applicable here" from "you are running
// an older doctor", which is why every code is always present — as unavailable,
// if nothing else.
func TestDoctorReportsEveryStableCodeExactlyOnceInOrder(t *testing.T) {
	report := RunDoctor(t.Context(), DoctorOptions{DataDir: t.TempDir()})
	if len(report.Checks) != len(everyStableCode) {
		t.Fatalf("got %d checks, want %d", len(report.Checks), len(everyStableCode))
	}
	seen := map[string]int{}
	for index, check := range report.Checks {
		if check.Code != everyStableCode[index] {
			t.Fatalf("check %d is %q, want %q", index, check.Code, everyStableCode[index])
		}
		if check.Summary == "" {
			t.Fatalf("%s has no summary", check.Code)
		}
		if len(check.Summary) > maxSummaryBytes {
			t.Fatalf("%s summary is %d bytes", check.Code, len(check.Summary))
		}
		switch check.Status {
		case DoctorOK, DoctorWarning, DoctorFailed, DoctorUnavailable:
		default:
			t.Fatalf("%s has an unknown status %q", check.Code, check.Status)
		}
		seen[check.Code]++
	}
	for code, count := range seen {
		if count != 1 {
			t.Fatalf("%s appears %d times", code, count)
		}
	}
}

// SECRETS MUST NOT REACH A DIAGNOSTIC THAT IS MEANT TO BE SHARED. The credential
// is the one live secret this command has access to, and it never reads the
// contents — but the guarantee has to be tested, not assumed, because the
// tempting fix for a confusing support case is to start reading it.
func TestDoctorOutputNeverCarriesTheCredentialOrItsContents(t *testing.T) {
	const secret = "pspn_THE_ACTUAL_SECRET_VALUE_0123456789ABCDEF"
	dataDir := t.TempDir()
	credentialPath := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(credentialPath, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	endpoint := "https://panel.example/private-prefix/v1/node/sync?token=" + secret

	report := RunDoctor(t.Context(), DoctorOptions{
		DataDir: dataDir, CredentialFile: credentialPath,
	})
	var jsonOutput, textOutput bytes.Buffer
	if err := WriteDoctorJSON(&jsonOutput, report); err != nil {
		t.Fatal(err)
	}
	if err := WriteDoctorText(&textOutput, report); err != nil {
		t.Fatal(err)
	}
	for name, output := range map[string]string{"json": jsonOutput.String(), "text": textOutput.String()} {
		for _, forbidden := range []string{secret, "pspn_", endpoint, "token="} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("%s output carries %q:\n%s", name, forbidden, output)
			}
		}
	}
	// The permissions check still ran, and reported on the FILE rather than its
	// contents.
	for _, check := range report.Checks {
		if check.Code == CheckCredentialPermissions && check.Status != DoctorOK {
			t.Fatalf("credential permissions = %q: %s", check.Status, check.Summary)
		}
	}
}

// The probe is created, synced, closed and removed. A diagnostic that left files
// behind, or that reported the name it created, would make the situation it was
// called to investigate worse.
func TestTheDataDirectoryProbeLeavesNothingBehind(t *testing.T) {
	dataDir := t.TempDir()
	report := RunDoctor(t.Context(), DoctorOptions{DataDir: dataDir})
	if status := statusOf(report, CheckDataDirAccess); status != DoctorOK {
		t.Fatalf("data_dir.access = %q", status)
	}
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("the probe was left behind: %v", names)
	}
	// And its name never appears in any summary.
	for _, check := range report.Checks {
		if strings.Contains(check.Summary, "probe") {
			t.Fatalf("%s names the probe: %s", check.Code, check.Summary)
		}
	}
}

func TestAnUnwritableDataDirectoryFailsTheAccessCheck(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write to a read-only directory")
	}
	dataDir := t.TempDir()
	if err := os.Chmod(dataDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dataDir, 0o700) })

	report := RunDoctor(t.Context(), DoctorOptions{DataDir: dataDir})
	if status := statusOf(report, CheckDataDirAccess); status != DoctorFailed {
		t.Fatalf("data_dir.access = %q, want failed", status)
	}
	if !report.Failed() {
		t.Fatal("a failing check did not mark the report as failed")
	}
}

// THE CHECK MUST NOT MODIFY WHAT IT INSPECTS. The daemon's own open applies
// schema migrations; a doctor that did the same would rewrite a database it was
// asked to describe, on a node whose agent may be running.
func TestDoctorDoesNotMigrateTheStateDatabase(t *testing.T) {
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "state.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	report := RunDoctor(t.Context(), DoctorOptions{DataDir: dataDir})
	if status := statusOf(report, CheckStateSQLiteOpen); status != DoctorOK {
		t.Fatalf("state.sqlite_open = %q", status)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("the doctor changed the state database: %d bytes before, %d after", len(before), len(after))
	}
	// A database with no schema in it has no deployment to report.
	if status := statusOf(report, CheckCoreSelection); status != DoctorUnavailable {
		t.Fatalf("core.selection = %q on an empty database", status)
	}
}

// A missing state database is a fact about a node that has never synced, not a
// fault in it.
func TestAMissingStateDatabaseIsNotAFailure(t *testing.T) {
	report := RunDoctor(t.Context(), DoctorOptions{DataDir: t.TempDir()})
	if status := statusOf(report, CheckStateSQLiteOpen); status != DoctorUnavailable {
		t.Fatalf("state.sqlite_open = %q, want unavailable", status)
	}
	if status := statusOf(report, CheckStateSQLiteQuickCheck); status != DoctorUnavailable {
		t.Fatalf("state.sqlite_quick_check = %q, want unavailable", status)
	}
	if report.Failed() {
		t.Fatal("a node with no state yet was reported as failing")
	}
}

// A file that exists but is not a database is a real failure: something is
// there, and it is not usable.
func TestAnUnreadableStateDatabaseFails(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "state.db"), []byte("this is not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := RunDoctor(t.Context(), DoctorOptions{DataDir: dataDir})
	status := statusOf(report, CheckStateSQLiteQuickCheck)
	if status != DoctorFailed && status != DoctorUnavailable {
		// An unparseable file can be refused at open or at the check, depending
		// on how far the driver gets. Either is honest; reporting OK is not.
		t.Fatalf("state.sqlite_quick_check = %q for a corrupt file", status)
	}
}

func TestCredentialPermissionsInspectsTypeAndModeWithoutReading(t *testing.T) {
	directory := t.TempDir()
	private := filepath.Join(directory, "private")
	if err := os.WriteFile(private, []byte("pspn_x"), 0o600); err != nil {
		t.Fatal(err)
	}
	worldReadable := filepath.Join(directory, "world")
	if err := os.WriteFile(worldReadable, []byte("pspn_x"), 0o644); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "link")
	if err := os.Symlink(private, symlink); err != nil {
		t.Fatal(err)
	}
	aDirectory := filepath.Join(directory, "adir")
	if err := os.Mkdir(aDirectory, 0o700); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		path string
		want DoctorStatus
	}{
		{"a private regular file", private, DoctorOK},
		{"a group or world readable file", worldReadable, DoctorFailed},
		{"a symlink", symlink, DoctorFailed},
		{"a directory", aDirectory, DoctorFailed},
		{"a missing file", filepath.Join(directory, "absent"), DoctorFailed},
		{"no path supplied", "", DoctorUnavailable},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			report := RunDoctor(t.Context(), DoctorOptions{
				DataDir: t.TempDir(), CredentialFile: testCase.path,
			})
			if status := statusOf(report, CheckCredentialPermissions); status != testCase.want {
				t.Fatalf("credential.permissions = %q, want %q", status, testCase.want)
			}
		})
	}
}

// A stopped core is a state, not a fault: the doctor may well be run on a node
// whose core is deliberately down.
func TestAStoppedCoreIsNotAFailure(t *testing.T) {
	report := RunDoctor(t.Context(), DoctorOptions{
		DataDir: t.TempDir(),
		Core:    func() (agentcore.ProcessHandle, bool) { return agentcore.ProcessHandle{}, false },
	})
	if status := statusOf(report, CheckCollectorProcess); status != DoctorUnavailable {
		t.Fatalf("collector.process = %q, want unavailable", status)
	}
	if report.Failed() {
		t.Fatal("a stopped core was reported as a failure")
	}
}

// The layout check recognises a layout rather than requiring one: the agent runs
// from a systemd install, from a container and from a hand-run binary, and only
// the first two have a managed layout at all.
func TestInstallationLayoutRecognisesRatherThanRequires(t *testing.T) {
	// A data directory with no managed layout beside it is still usable.
	report := RunDoctor(t.Context(), DoctorOptions{DataDir: t.TempDir()})
	if status := statusOf(report, CheckInstallationLayout); status != DoctorOK {
		t.Fatalf("installation.layout = %q for a hand-run layout", status)
	}

	// A managed layout that is incomplete is worth reporting and is not fatal.
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	report = RunDoctor(t.Context(), DoctorOptions{DataDir: t.TempDir(), InstallRoot: root})
	if status := statusOf(report, CheckInstallationLayout); status != DoctorWarning {
		t.Fatalf("installation.layout = %q for an incomplete managed layout", status)
	}
}

// A data directory that is not readable at all is a failure, and every other
// check degrades rather than panicking on the missing tree.
func TestAMissingDataDirectoryFailsWithoutBreakingTheOtherChecks(t *testing.T) {
	report := RunDoctor(t.Context(), DoctorOptions{
		DataDir: filepath.Join(t.TempDir(), "absent"),
	})
	if status := statusOf(report, CheckInstallationLayout); status != DoctorFailed {
		t.Fatalf("installation.layout = %q", status)
	}
	if len(report.Checks) != len(everyStableCode) {
		t.Fatalf("a failed check dropped another: %d checks", len(report.Checks))
	}
}

func TestJSONOutputIsOneDocument(t *testing.T) {
	report := RunDoctor(t.Context(), DoctorOptions{DataDir: t.TempDir()})
	var output bytes.Buffer
	if err := WriteDoctorJSON(&output, report); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&output)
	var decoded DoctorReport
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != DoctorSchemaVersion {
		t.Fatalf("schema version = %d", decoded.SchemaVersion)
	}
	// Nothing may follow the document: a caller pipes this into a parser.
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		t.Fatal("the JSON output carried more than one document")
	}
}

func statusOf(report DoctorReport, code string) DoctorStatus {
	for _, check := range report.Checks {
		if check.Code == code {
			return check.Status
		}
	}
	return ""
}

package manage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/corecatalog"
)

// seedCoreInstallation lays out a data directory the way the daemon leaves it:
// a confirmed deployment of the recommended sing-box in state.db, and that
// version published under cores/ with the record the installer writes beside it.
// It returns the binary's path.
func seedCoreInstallation(t *testing.T, dataDir string, asset corecatalog.Asset, release corecatalog.Release) string {
	t.Helper()
	database, err := sql.Open("sqlite", "file:"+filepath.Join(dataDir, stateDatabaseName))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec(`CREATE TABLE core_deployment (
		id INTEGER PRIMARY KEY CHECK (id = 1), engine TEXT NOT NULL, version TEXT NOT NULL, config_digest TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	configDigest := sha256.Sum256([]byte("config"))
	if _, err := database.Exec(`INSERT INTO core_deployment (id, engine, version, config_digest) VALUES (1, ?, ?, ?)`,
		release.Engine, release.Version, hex.EncodeToString(configDigest[:])); err != nil {
		t.Fatal(err)
	}

	versionDir := filepath.Join(dataDir, "cores", release.Engine, "versions", release.Version)
	binaryPath := filepath.Join(versionDir, filepath.FromSlash(asset.Binary))
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("fake core binary")
	if err := os.WriteFile(binaryPath, content, 0o755); err != nil {
		t.Fatal(err)
	}
	binaryDigest := sha256.Sum256(content)
	// The installer's record: install.json, in internal/core/install's format.
	record, err := json.Marshal(map[string]any{
		"schema_version": 1, "engine": release.Engine, "version": release.Version,
		"source_url": asset.URL, "archive_sha256": asset.SHA256,
		"binary_sha256": hex.EncodeToString(binaryDigest[:]), "installed_at": time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(versionDir, "install.json"), record, 0o600); err != nil {
		t.Fatal(err)
	}
	return binaryPath
}

// The digest check reads the record the installer actually writes, and finds
// the binary of the variant that record names — including the libc variant
// HostLibc would not pick today, which the installer keeps using.
func TestCoreBinaryDigestReadsTheInstallersRecord(t *testing.T) {
	release, err := corecatalog.Recommended("sing-box")
	if err != nil {
		t.Fatal(err)
	}
	var assets []corecatalog.Asset
	for _, asset := range release.Assets {
		if asset.OS == runtime.GOOS && asset.Arch == runtime.GOARCH {
			assets = append(assets, asset)
		}
	}
	if len(assets) == 0 {
		t.Skipf("the catalog has no sing-box asset for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	for _, asset := range assets {
		t.Run("libc="+asset.Libc, func(t *testing.T) {
			dataDir := t.TempDir()
			binaryPath := seedCoreInstallation(t, dataDir, asset, release)

			report := RunDoctor(t.Context(), DoctorOptions{DataDir: dataDir})
			if check := checkOf(report, CheckCoreBinaryDigest); check.Status != DoctorOK {
				t.Fatalf("core.binary_digest = %q (%s), want ok", check.Status, check.Summary)
			}

			if err := os.WriteFile(binaryPath, []byte("tampered"), 0o755); err != nil {
				t.Fatal(err)
			}
			report = RunDoctor(t.Context(), DoctorOptions{DataDir: dataDir})
			if check := checkOf(report, CheckCoreBinaryDigest); check.Status != DoctorFailed {
				t.Fatalf("core.binary_digest = %q (%s) after tampering, want failed", check.Status, check.Summary)
			}
		})
	}
}

func checkOf(report DoctorReport, code string) DoctorCheck {
	for _, check := range report.Checks {
		if check.Code == code {
			return check
		}
	}
	return DoctorCheck{}
}

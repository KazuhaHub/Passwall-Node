package sqlite

import (
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalStateURIReopensTheSameEscapedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state # % & +.db")
	u, err := url.Parse(sqliteDSN(path))
	if err != nil || u.Scheme != "file" || u.Host != "" || !strings.HasPrefix(u.Path, "/") {
		t.Fatal("local state path became an authority or relative URI")
	}
	store, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(t.Context(), "CREATE TABLE path_probe (value TEXT); INSERT INTO path_probe VALUES ('preserved')"); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	var value string
	if err := reopened.db.QueryRowContext(t.Context(), "SELECT value FROM path_probe").Scan(&value); err != nil || value != "preserved" {
		t.Fatalf("state did not survive reopening: %q, %v", value, err)
	}
}

//go:build !windows

package sqlite

import (
	"fmt"
	"os"
	"path/filepath"
)

// Keep the existing POSIX bootstrap and permission semantics unchanged.
func prepareStateFile(path string) (func() error, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create state database: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close state database bootstrap handle: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("protect state database: %w", err)
	}
	return nil, nil
}

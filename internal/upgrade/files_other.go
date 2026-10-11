//go:build !windows

package upgrade

import (
	"errors"
	"fmt"
	"os"
)

func ensurePrivateDirectory(dir string) error {
	if info, err := os.Lstat(dir); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			return errors.New("upgrade directory must be a private real directory")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Mkdir(dir, 0700)
}

func ensureReleaseStagingRoot(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create upgrade staging root: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("upgrade staging root must be a private non-linked directory")
	}
	return nil
}

func checkDocumentDirectory(_ string, _ os.FileMode) (func(), error) {
	return nil, nil
}

func replaceDocumentFile(from, to, dir string) error {
	if err := os.Rename(from, to); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

package upgrade

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func atomicHelperDocument(dir, name string, document any, gid uint32) error {
	data, err := json.Marshal(document)
	if err != nil {
		return err
	}
	return atomicHelperFile(dir, name, strings.NewReader(string(data)), 0640, gid)
}

func atomicHelperFile(dir, name string, source io.Reader, mode os.FileMode, gid uint32) error {
	if filepath.Base(name) != name {
		return errors.New("helper file name is not canonical")
	}
	if info, err := os.Lstat(filepath.Join(dir, name)); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("helper refuses a linked or foreign target")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(dir, ".activate-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Chown(helperOwnerID(), int(gid)); err != nil {
		f.Close()
		return err
	}
	if _, err := io.Copy(f, io.LimitReader(source, (256<<20)+1)); err != nil {
		f.Close()
		return err
	}
	if info, err := f.Stat(); err != nil || info.Size() > 256<<20 {
		f.Close()
		return errors.New("helper file exceeds safe limit")
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

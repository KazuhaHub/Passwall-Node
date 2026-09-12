package upgrade

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Private JSON documents are bounded and confined to an owned root. Observed
// symlinks are refused; os.Root provides containment even across path races,
// not a claim that Lstat alone prevents every in-root symlink race.
func ReadDocument(root, name string, target any) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("upgrade root must be a real directory")
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer r.Close()
	parts := strings.Split(filepath.Clean(name), string(filepath.Separator))
	for i := range parts {
		info, err := r.Lstat(filepath.Join(parts[:i+1]...))
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("upgrade paths must not be symlinks")
		}
	}
	f, err := r.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 32<<10 {
		return errors.New("upgrade document must be a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, (32<<10)+1))
	if err != nil {
		return err
	}
	return DecodeStrict(data, target)
}

// AtomicDocument is only called with owned, checked private directories and a
// canonical basename. Sync the containing directory as well as the file.
func AtomicDocument(dir, name string, document any, mode os.FileMode) error {
	if filepath.Base(name) != name {
		return errors.New("upgrade document name is not canonical")
	}
	data, err := json.Marshal(document)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".upgrade-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func BinaryDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 256<<20 {
		return "", errors.New("invalid upgrade binary")
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

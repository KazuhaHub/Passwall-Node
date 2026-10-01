//go:build unix

package upgrade

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// errFlockUnsupported is a filesystem that cannot take an flock at all. It is
// not a failure of the updater: the handover is switched off, and the updater
// runs alone and unlocked exactly as it did before the handover existed.
var errFlockUnsupported = errors.New("the filesystem under the updater lock does not support flock")

// updaterLock is the kernel lock that elects the one updater allowed to act.
//
// AN flock, BECAUSE IT DIES WITH ITS HOLDER. A predecessor or successor that is
// SIGKILLed, or whose container is removed, releases it with its last
// descriptor; nothing has to notice the death and clean up, and nothing stale
// can be left behind for the next process to misread. It belongs to the open
// file description, so two descriptors exclude each other even within one
// process, and two containers that bind-mount the same host directory share it.
type updaterLock struct {
	file *os.File
	// flock is unix.Flock. A test substitutes it to play a filesystem that
	// refuses the call.
	flock func(fd int, how int) error
}

// openUpdaterLock opens, creating if needed, the lock file in the updater
// directory. It never takes the lock; tryLock does.
//
// THE FILE IS ROOT'S ALONE, and that is not tidiness. Taking an flock needs only
// a descriptor, a read-only one included, so a lock the agent could open is a
// lock the agent could hold, and then no updater would ever act again. The
// directory around it is already root-only; the file is checked as well, so a
// lock that predates that directory's repair is not trusted on the directory's
// word. It is opened without following a link, refused unless it is a regular
// file owned by root, and its mode and group are put back to 0600 root's.
func openUpdaterLock(dir string, rootUID, rootGID uint32) (*updaterLock, error) {
	file, err := os.OpenFile(filepath.Join(dir, updaterLockName), os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("updater lock cannot be opened: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	uid, gid, ok := dockerFileOwner(info)
	if !info.Mode().IsRegular() || !ok || uid != rootUID {
		file.Close()
		return nil, errors.New("updater lock is not a regular file owned by root")
	}
	if gid != rootGID {
		if err := file.Chown(int(rootUID), int(rootGID)); err != nil {
			file.Close()
			return nil, err
		}
	}
	if info.Mode().Perm() != 0600 {
		if err := file.Chmod(0600); err != nil {
			file.Close()
			return nil, err
		}
	}
	return &updaterLock{file: file, flock: unix.Flock}, nil
}

// tryLock takes the lock without waiting. It reports false with no error while
// another process holds it, and errFlockUnsupported when the filesystem cannot
// take one at all.
func (l *updaterLock) tryLock() (bool, error) {
	err := l.flock(int(l.file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.EWOULDBLOCK):
		return false, nil
	case flockUnsupported(err):
		return false, fmt.Errorf("%w: %w", errFlockUnsupported, err)
	default:
		return false, fmt.Errorf("updater lock: %w", err)
	}
}

// isFile reports whether info, read by path, is the file this descriptor has
// open.
func (l *updaterLock) isFile(info os.FileInfo) bool {
	held, err := l.file.Stat()
	return err == nil && os.SameFile(held, info)
}

// close releases the lock, if this descriptor held it, by closing it.
func (l *updaterLock) close() error {
	return l.file.Close()
}

// flockUnsupported names the errnos a kernel uses for a filesystem that does not
// do flock: ENOLCK from a network filesystem without a lock manager, EOPNOTSUPP
// (ENOTSUP on BSDs) and ENOSYS from FUSE and similar, and EINVAL from a file type
// that cannot be locked.
func flockUnsupported(err error) bool {
	return errors.Is(err, unix.ENOLCK) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP) ||
		errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL)
}

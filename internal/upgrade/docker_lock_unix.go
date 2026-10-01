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
//
// NEITHER THE FILE NOR THE DIRECTORY IS REACHED THROUGH A LINK. The directory is
// opened first, refusing a link, and the lock is opened inside that descriptor,
// refusing one again.
func openUpdaterLock(dir string, rootUID, rootGID uint32) (*updaterLock, error) {
	parent, err := os.OpenFile(dir, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("updater lock cannot be opened: %w", err)
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), updaterLockName, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, fmt.Errorf("updater lock cannot be opened: %w", err)
	}
	file := os.NewFile(uintptr(fd), filepath.Join(dir, updaterLockName))
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

// prepareUpdaterDir makes <control>/updater a real directory, root's alone,
// 0700, creating it if needed; see ensureUpdaterDir for why.
//
// IT WORKS ON DESCRIPTORS, NOT PATHS. The control directory is opened, refusing a
// link, and checked through that descriptor before anything is created in it:
// it has to be root's, and writable by nobody else, or someone else could swap
// what the updater is about to change for a link to anything at all. The updater
// directory is then made and opened inside that descriptor, again refusing a
// link, and its owner and mode are read and put right through its own
// descriptor, so a chown or a chmod can never land anywhere else. Nothing is
// changed in a control directory that fails the check: the handover is off, and
// the control directory is prepareControl's, as it always was.
func prepareUpdaterDir(control string, rootUID, rootGID uint32) error {
	parent, err := os.OpenFile(control, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("the control directory cannot be opened: %w", err)
	}
	defer parent.Close()
	info, err := parent.Stat()
	if err != nil {
		return err
	}
	if uid, _, ok := dockerFileOwner(info); !ok || uid != rootUID || info.Mode().Perm()&0022 != 0 {
		return errors.New("the control directory is not root's alone: someone else could write it")
	}
	created := true
	if err := unix.Mkdirat(int(parent.Fd()), DockerUpdaterDir, 0700); errors.Is(err, unix.EEXIST) {
		created = false
	} else if err != nil {
		return err
	}
	fd, err := unix.Openat(int(parent.Fd()), DockerUpdaterDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		return errors.New("updater directory is not a real directory")
	} else if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(fd), filepath.Join(control, DockerUpdaterDir))
	defer dir.Close()
	if info, err = dir.Stat(); err != nil {
		return err
	}
	uid, gid, ok := dockerFileOwner(info)
	if !ok || (!created && uid != rootUID) {
		return errors.New("updater directory is not owned by root")
	}
	if created || gid != rootGID {
		if err := dir.Chown(int(rootUID), int(rootGID)); err != nil {
			return err
		}
	}
	if info.Mode().Perm() != 0700 {
		return dir.Chmod(0700)
	}
	return nil
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

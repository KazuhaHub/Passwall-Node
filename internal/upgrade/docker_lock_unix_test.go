//go:build unix

package upgrade

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func updaterLockOwner() (uint32, uint32) {
	return uint32(os.Geteuid()), uint32(os.Getegid())
}

// ONE LOCK, ONE ACTOR. flock belongs to an open file description, so two
// descriptors opened separately exclude each other even inside one process —
// which is also how the handover's two in-process controllers will share it.
func TestUpdaterLockExcludesASecondHolder(t *testing.T) {
	dir := t.TempDir()
	uid, gid := updaterLockOwner()
	first, err := openUpdaterLock(dir, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	defer first.close()
	second, err := openUpdaterLock(dir, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	defer second.close()
	if held, err := first.tryLock(); !held || err != nil {
		t.Fatalf("the first holder: held=%v err=%v", held, err)
	}
	if held, err := second.tryLock(); held || err != nil {
		t.Fatalf("a second holder while the first holds it: held=%v err=%v, want busy", held, err)
	}
	if err := first.close(); err != nil {
		t.Fatal(err)
	}
	if held, err := second.tryLock(); !held || err != nil {
		t.Fatalf("after the first holder closed: held=%v err=%v", held, err)
	}
	info, err := os.Stat(filepath.Join(dir, "lock"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("lock file mode = %v (%v), want 0600", info.Mode().Perm(), err)
	}
}

// A HOLDER THAT DIES WITHOUT CLEANING UP STILL RELEASES THE LOCK. The kernel
// drops it with the process's last descriptor, so a predecessor that is SIGKILLed
// after it commits does not leave its successor waiting on a lock nobody holds.
func TestUpdaterLockReleasedWhenHolderDies(t *testing.T) {
	dir := t.TempDir()
	child := exec.Command(os.Args[0], "-test.run=^TestUpdaterLockHolderProcess$", "-test.count=1")
	child.Env = append(os.Environ(), updaterLockHolderEnv+"="+dir)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	held := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "held" {
				held <- nil
				return
			}
		}
		held <- errors.New("the holder exited without taking the lock")
	}()
	select {
	case err := <-held:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the holder never took the lock")
	}

	uid, gid := updaterLockOwner()
	lock, err := openUpdaterLock(dir, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.close()
	if ok, err := lock.tryLock(); ok || err != nil {
		t.Fatalf("the lock was free while another process held it: ok=%v err=%v", ok, err)
	}
	if err := child.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	if ok, err := lock.tryLock(); !ok || err != nil {
		t.Fatalf("the lock was not released by its holder's death: ok=%v err=%v", ok, err)
	}
}

const updaterLockHolderEnv = "PN_UPDATER_LOCK_HOLDER_DIR"

// TestUpdaterLockHolderProcess is the process TestUpdaterLockReleasedWhenHolderDies
// kills: it takes the lock, says so, and waits to be killed.
func TestUpdaterLockHolderProcess(t *testing.T) {
	dir := os.Getenv(updaterLockHolderEnv)
	if dir == "" {
		t.Skip("runs only as the lock holder TestUpdaterLockReleasedWhenHolderDies starts")
	}
	uid, gid := updaterLockOwner()
	lock, err := openUpdaterLock(dir, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := lock.tryLock(); !ok || err != nil {
		t.Fatalf("held=%v err=%v", ok, err)
	}
	os.Stdout.WriteString("held\n")
	time.Sleep(time.Minute)
}

// THE LOCK IS ROOT'S ALONE. Taking an flock needs only a descriptor, and a
// read-only one will do, so a lock the agent could open is a lock the agent
// could hold: every updater would wait on it forever. So the lock file is never
// followed through a link, never anything but a regular file, never owned by
// anyone but root, and never left readable by its group or by others.
func TestUpdaterLockRefusesSymlinkAndNonRootOwner(t *testing.T) {
	uid, gid := updaterLockOwner()

	t.Run("a symlink is not followed", func(t *testing.T) {
		dir, elsewhere := t.TempDir(), t.TempDir()
		target := filepath.Join(elsewhere, "target")
		if err := os.Symlink(target, filepath.Join(dir, "lock")); err != nil {
			t.Fatal(err)
		}
		if lock, err := openUpdaterLock(dir, uid, gid); err == nil {
			lock.close()
			t.Fatal("a symlinked lock was opened")
		}
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the symlink's target was created: %v", err)
		}
	})

	t.Run("a lock owned by anyone but root is refused", func(t *testing.T) {
		dir := t.TempDir()
		if lock, err := openUpdaterLock(dir, uid+1, gid); err == nil {
			lock.close()
			t.Fatalf("a lock owned by uid %d was accepted as root's (%d)", uid, uid+1)
		}
	})

	t.Run("anything but a regular file is refused", func(t *testing.T) {
		dir := t.TempDir()
		if err := unix.Mkfifo(filepath.Join(dir, "lock"), 0600); err != nil {
			t.Fatal(err)
		}
		if lock, err := openUpdaterLock(dir, uid, gid); err == nil {
			lock.close()
			t.Fatal("a FIFO was accepted as the lock")
		}
	})

	t.Run("a lock its group could read is closed to it", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "lock")
		if err := os.WriteFile(path, nil, 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		lock, err := openUpdaterLock(dir, uid, gid)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.close()
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("lock mode = %v (%v), want 0600", info.Mode().Perm(), err)
		}
	})
}

// A FILESYSTEM WITHOUT flock CANNOT ELECT ONE ACTOR, so it gets no handover.
// The errnos a kernel uses for "this filesystem does not do that" are told apart
// from the one that means "someone else holds it" and from a genuine failure:
// only the first set switches the handover off, leaving the updater running
// exactly as it does today, alone.
func TestUnsupportedFlockDisablesHandover(t *testing.T) {
	uid, gid := updaterLockOwner()
	for _, tc := range []struct {
		errno       syscall.Errno
		busy        bool
		unsupported bool
	}{
		{errno: unix.ENOLCK, unsupported: true},
		{errno: unix.EOPNOTSUPP, unsupported: true},
		{errno: unix.ENOTSUP, unsupported: true},
		{errno: unix.ENOSYS, unsupported: true},
		{errno: unix.EINVAL, unsupported: true},
		{errno: unix.EWOULDBLOCK, busy: true},
		{errno: unix.EBADF},
	} {
		t.Run(strconv.Itoa(int(tc.errno))+" "+tc.errno.Error(), func(t *testing.T) {
			lock, err := openUpdaterLock(t.TempDir(), uid, gid)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.close()
			lock.flock = func(int, int) error { return tc.errno }
			held, err := lock.tryLock()
			if held {
				t.Fatal("an injected failure was reported as holding the lock")
			}
			switch {
			case tc.busy:
				if err != nil {
					t.Fatalf("a held lock reported %v, want busy with no error", err)
				}
			case tc.unsupported:
				if !errors.Is(err, errFlockUnsupported) {
					t.Fatalf("tryLock = %v, want errFlockUnsupported", err)
				}
			default:
				if err == nil || errors.Is(err, errFlockUnsupported) {
					t.Fatalf("tryLock = %v, want a failure that is not 'unsupported'", err)
				}
			}
		})
	}
}

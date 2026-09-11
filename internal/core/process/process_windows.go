//go:build windows

package process

import (
	"errors"
	"os"
	"os/exec"

	"golang.org/x/sys/windows"
)

func configureCommand(command *exec.Cmd) {
	command.SysProcAttr = &windows.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
}

// Windows has no universally reliable graceful signal for a detached console
// child. Xray persists no mutable state, so terminating the process before the
// atomic config switch is the safe cross-service behavior here.
func signalProcess(command *exec.Cmd) error { return command.Process.Kill() }

func killProcess(command *exec.Cmd) error { return command.Process.Kill() }

func processGone(err error) bool { return errors.Is(err, os.ErrProcessDone) }

func replaceFile(source, target string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func syncDirectory(string) error { return nil }

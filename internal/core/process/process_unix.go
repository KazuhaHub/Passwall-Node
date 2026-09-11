//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package process

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func configureCommand(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func signalProcess(command *exec.Cmd) error {
	return syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
}

func killProcess(command *exec.Cmd) error {
	return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
}

func processGone(err error) bool {
	return errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH)
}

func replaceFile(source, target string) error { return os.Rename(source, target) }

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

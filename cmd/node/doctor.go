package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/KazuhaHub/passwall-node/v4/internal/host"
	"github.com/KazuhaHub/passwall-node/v4/internal/manage"
	"github.com/KazuhaHub/passwall-node/v4/internal/upgrade"
)

// Exit codes. The doctor's contract distinguishes the three, and a caller
// scripting it — a repair playbook, a support script — has to be able to tell
// "this node has a problem" from "the doctor could not run".
const (
	exitCodeDoctorCheckFailed = 1
	exitCodeDoctorUsage       = 2
)

// exitCodeError attaches a process exit code to a failure.
type exitCodeError struct {
	code int
	err  error
}

func (e *exitCodeError) Error() string { return e.err.Error() }
func (e *exitCodeError) Unwrap() error { return e.err }

// exitCodeFor maps a returned error to a process exit code. Everything but the
// doctor uses the default, which is what the daemon has always done.
func exitCodeFor(err error) int {
	var coded *exitCodeError
	if errors.As(err, &coded) {
		return coded.code
	}
	return 1
}

// runDoctor implements the doctor subcommand.
//
// IT IS DISPATCHED BEFORE THE DAEMON'S FLAG PARSING, like the other special
// entries. `doctor` is not a mode of the daemon: letting the daemon's parser see
// its arguments would make every daemon flag appear applicable to a command that
// must not start anything.
//
// The two paths are REQUIRED WITH NO DEFAULT. The daemon has no default for
// either, and a doctor that invented one would report a clean bill of health for
// a directory nothing is actually using.
func runDoctor(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	jsonOutput := flags.Bool("json", false, "write one JSON document to stdout")
	dataDir := flags.String("data-dir", "", "absolute path to the agent's data directory (required)")
	credentialFile := flags.String("credential-file", "", "absolute path to the credential (optional)")
	if err := flags.Parse(arguments); err != nil {
		return &exitCodeError{code: exitCodeDoctorUsage, err: err}
	}
	if flags.NArg() != 0 {
		return &exitCodeError{code: exitCodeDoctorUsage, err: errors.New("doctor takes no positional arguments")}
	}
	if *dataDir == "" || !filepath.IsAbs(*dataDir) {
		return &exitCodeError{code: exitCodeDoctorUsage,
			err: errors.New("--data-dir is required and must be an absolute path")}
	}
	if *credentialFile != "" && !filepath.IsAbs(*credentialFile) {
		return &exitCodeError{code: exitCodeDoctorUsage,
			err: errors.New("--credential-file must be an absolute path")}
	}

	// A platform with no collector is a legitimate answer, and the check reports
	// it as unavailable rather than the command failing. The doctor's job is to
	// describe the node, and "this platform cannot collect" is a description.
	var collector host.Collector
	if built, err := host.New(host.Options{DataDir: *dataDir}); err == nil {
		collector = built
	}

	report := manage.RunDoctor(context.Background(), manage.DoctorOptions{
		DataDir:        *dataDir,
		CredentialFile: *credentialFile,
		InstallRoot:    upgrade.InstallRoot,
		Collector:      collector,
	})

	if *jsonOutput {
		// Stdout carries ONE JSON document and nothing else, so it can be piped
		// into a parser. The failure notice below goes to stderr, because mixing
		// it in would produce output no parser accepts.
		if err := manage.WriteDoctorJSON(stdout, report); err != nil {
			return &exitCodeError{code: exitCodeDoctorUsage, err: err}
		}
	} else if err := manage.WriteDoctorText(stdout, report); err != nil {
		return &exitCodeError{code: exitCodeDoctorUsage, err: err}
	}

	if failures := countFailures(report); failures > 0 {
		return &exitCodeError{code: exitCodeDoctorCheckFailed, err: fmt.Errorf(
			"doctor found %d failing checks", failures)}
	}
	return nil
}

func countFailures(report manage.DoctorReport) int {
	failures := 0
	for _, check := range report.Checks {
		if check.Status == manage.DoctorFailed {
			failures++
		}
	}
	return failures
}

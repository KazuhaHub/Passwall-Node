// Command coreacceptance prepares exact official binaries for the executable
// integration tests and rejects incomplete or skipped go test JSON evidence.
// It is a CI/local acceptance fixture, not a production core updater.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "core acceptance:", err)
		os.Exit(1)
	}
}

func run(arguments []string, output, diagnostic io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("expected prepare or check command")
	}
	switch arguments[0] {
	case "prepare":
		flags := flag.NewFlagSet("prepare", flag.ContinueOnError)
		flags.SetOutput(diagnostic)
		directory := flags.String("directory", "", "absolute private fixture directory")
		environmentFile := flags.String("env-file", "", "absolute GitHub environment file to append")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("prepare does not accept positional arguments")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		return prepare(ctx, *directory, *environmentFile, output)
	case "check":
		flags := flag.NewFlagSet("check", flag.ContinueOnError)
		flags.SetOutput(diagnostic)
		results := flags.String("results", "", "go test -json evidence file")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || *results == "" {
			return errors.New("check requires only --results FILE")
		}
		file, err := os.Open(*results)
		if err != nil {
			return err
		}
		defer file.Close()
		if err := checkResults(file); err != nil {
			return err
		}
		_, err = fmt.Fprintln(output, "Verified all 8 executable acceptance leaves and both parent tests: run + pass, no skips or missing evidence.")
		return err
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

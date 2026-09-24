// Command verify-release checks a release manifest's detached signature with
// the public key compiled into every agent.
//
// It holds no key and needs none, which is why it can run anywhere: verifying an
// Ed25519 signature takes only the public half. promote.yml runs it before a
// release is offered on the stable channel, because the public installer checks
// archives against SHA256SUMS.txt alone, and an asset replaced together with its
// manifest passes that. Native auto-upgrade already refuses such a release on
// this same check; promotion now refuses it first.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/KazuhaHub/passwall-node/v4/internal/releaseauth"
)

const (
	// The upgrade path's own bound for the manifest it downloads.
	maxManifest  = 256 << 10
	maxSignature = 1 << 10
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("verify-release", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifestPath := flags.String("manifest", "", "path to SHA256SUMS.txt")
	signaturePath := flags.String("signature", "", "path to SHA256SUMS.txt.sig")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *manifestPath == "" || *signaturePath == "" {
		return errors.New("verify-release requires -manifest and -signature")
	}
	manifest, err := readBoundedRegular(*manifestPath, maxManifest)
	if err != nil {
		return fmt.Errorf("read release manifest: %w", err)
	}
	signature, err := readBoundedRegular(*signaturePath, maxSignature)
	if err != nil {
		return fmt.Errorf("read release signature: %w", err)
	}
	if err := releaseauth.VerifyManifest(manifest, signature); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "release manifest signature verified with the compiled public key")
	return err
}

func readBoundedRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("input must be a non-empty bounded regular file")
	}
	return os.ReadFile(path)
}

// Command publish-core-catalog writes the reviewed core catalog as the document a
// release publishes.
//
// PSP CONSUMES THIS DOCUMENT, so the panel's core selector and its enforcement
// boundary stop depending on this module. Which cores may be installed — the
// tier, the evidence matrix behind it, the REALITY compatibility table, the
// per-asset digests — is not derivable from any API: it is the output of
// acceptance testing, and it has to be published as data.
//
// THE DOCUMENT IS THE VALIDATED ONE. It is produced by `corecatalog.Load`, so it
// has passed every review check the compiled catalog passes — one recommended
// release per engine, restricted implies confirmation, assets covering all six
// targets, handshake evidence agreeing with each REALITY conclusion, URLs inside
// the matching official release. The panel does not repeat those checks: it
// verifies the release signature, which is this project attesting that the
// document was produced here, and it would be a second copy of the review to
// re-derive them. A generator that marshalled a catalog of its own would sign
// something no check ever saw, which is why the load happens first and nothing
// else can reach the output.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/KazuhaHub/passwall-node/v4/corecatalog"
)

// maxDocumentBytes bounds what a review document may weigh. The catalog has a
// handful of releases; this is a guard against a runaway generator rather than a
// limit anyone should approach.
const maxDocumentBytes = 256 << 10

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	outputPath := flag.String("output", "", "path to write the published core catalog document")
	flag.Parse()
	if flag.NArg() != 0 || *outputPath == "" {
		return errors.New("publish-core-catalog requires -output")
	}
	if filepath.Clean(*outputPath) != *outputPath {
		return errors.New("core catalog output path must be canonical")
	}
	catalog, err := corecatalog.Load()
	if err != nil {
		return fmt.Errorf("read the reviewed core catalog: %w", err)
	}
	// INDENTED, and not for looks: this document is what a release publishes, and
	// the format is also the form a person reviews when a core is added or a tier
	// moves. A digest over compact JSON would still be verifiable and would make
	// that review a diff of one very long line.
	//
	// The encoding is deterministic — every field in the catalog is a struct or a
	// slice, never a map — so the same review produces the same bytes, and the
	// digest SHA256SUMS.txt records for it is reproducible.
	body, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		return fmt.Errorf("encode core catalog document: %w", err)
	}
	body = append(body, '\n')
	if len(body) > maxDocumentBytes {
		return errors.New("core catalog document is implausibly large")
	}
	if err := os.WriteFile(*outputPath, body, 0o644); err != nil {
		return fmt.Errorf("write core catalog document: %w", err)
	}
	return nil
}

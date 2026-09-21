package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KazuhaHub/passwall-node/v4/corecatalog"
)

// The document is tested by RUNNING the command that ships, because what has to
// be true is a property of the FILE a release publishes, not of a helper beside
// it: the panel consumes these bytes and trusts them on the strength of a
// signature over them.
var publishBinary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "publish-core-catalog")
	if err != nil {
		panic(err)
	}
	publishBinary = filepath.Join(dir, "publish-core-catalog")
	build := exec.Command("go", "build", "-o", publishBinary, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		os.RemoveAll(dir)
		panic("building publish-core-catalog: " + err.Error())
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func runPublish(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(publishBinary, args...)
	var stderr, stdout bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout
	err := cmd.Run()
	if err == nil {
		return 0, stdout.String(), stderr.String()
	}
	exit, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("running publish-core-catalog: %v", err)
	}
	return exit.ExitCode(), stdout.String(), stderr.String()
}

// THE PUBLISHED DOCUMENT IS THE REVIEWED ONE, AND THAT IS TESTED BY REVIEWING IT.
//
// The panel does not re-run this project's review checks — it verifies the
// release signature, which is this project attesting that the document came from
// here. That makes the signature a claim about a document, and the claim is only
// worth what the document is worth: so what ships has to be readable by the same
// path, `corecatalog.Parse`, that applies every check to the compiled catalog.
//
// This case round-trips it. A document that would fail any one of them — a second
// recommended release on an engine, a restricted release that does not require
// confirmation, an asset set missing a target, handshake evidence that disagrees
// with a REALITY conclusion, a URL outside the matching official release, or a
// field this build does not know — makes Parse fail here, before it can be signed.
func TestThePublishedDocumentPassesEveryReviewCheck(t *testing.T) {
	output := filepath.Join(t.TempDir(), "core-catalog.json")
	if code, _, stderr := runPublish(t, "-output", output); code != 0 {
		t.Fatalf("publishing the core catalog failed (exit %d): %s", code, stderr)
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	published, err := corecatalog.Parse(body)
	if err != nil {
		t.Fatalf("the published document does not survive the review checks the compiled catalog passes: %v", err)
	}

	// AND IT IS THE SAME CATALOG THIS BUILD SHIPS, field for field. Without this
	// the case would pass on any document that happened to be valid — including a
	// stale one committed beside the catalog this binary actually reads.
	shipped, err := corecatalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !equalCatalogs(t, published, shipped) {
		t.Fatal("the published document is not the catalog this build ships")
	}

	// A RELEASE PUBLISHES A REVIEW, NOT A PRIVATE FORMAT. The panel decodes this
	// with unknown fields refused, so a field added here and not there would be a
	// document every existing panel refuses — discovered at the node, at install
	// time. Reading the keys back is how that is caught at the publisher.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	for key := range raw {
		switch key {
		case "schema_version", "updated_at", "releases":
		default:
			t.Fatalf("the published document carries an unknown top-level field %q", key)
		}
	}
}

func equalCatalogs(t *testing.T, a, b corecatalog.Catalog) bool {
	t.Helper()
	left, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	right, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(left, right)
}

// The output path is publisher input, and a command that writes wherever it is
// told is a command a typo can point at the wrong file.
func TestTheOutputPathIsRequiredAndMustBeCanonical(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"-output", ""},
		{"-output", "./core-catalog.json"},
		{"-output", "dist/../core-catalog.json"},
		{"-output", "/tmp/../core-catalog.json"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			code, stdout, stderr := runPublish(t, args...)
			if code == 0 {
				t.Fatalf("publish-core-catalog %v was accepted", args)
			}
			if strings.TrimSpace(stderr) == "" {
				t.Fatal("a refusal must say why")
			}
			if strings.TrimSpace(stdout) != "" {
				t.Fatalf("a refusal printed %q on stdout", stdout)
			}
		})
	}
}

// THE DOCUMENT IS DETERMINISTIC, and that is a property the release depends on:
// SHA256SUMS.txt records one digest for it, so a second run producing different
// bytes would publish a manifest the signature was not made over. Marshalling a
// struct is order-stable; a map anywhere in the catalog would not be.
func TestTheDocumentIsByteForByteReproducible(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.json")
	second := filepath.Join(dir, "second.json")
	for _, output := range []string{first, second} {
		if code, _, stderr := runPublish(t, "-output", output); code != 0 {
			t.Fatalf("publishing failed: %s", stderr)
		}
	}
	a, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("two runs over the same catalog produced different bytes, so no digest of this document is meaningful")
	}
}

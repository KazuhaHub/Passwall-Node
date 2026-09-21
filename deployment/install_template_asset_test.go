package deployment

import (
	"os"
	"strings"
	"testing"
)

// THE INSTALL TEMPLATE IS PUBLISHED AS ITS OWN SIGNED ASSET.
//
// The panel renders this script for the install command it hands an operator —
// PSP downloads, verifies and renders it, and never executes it. It needs the
// exact bytes a release published rather than a copy compiled into the Node Go
// module, because that copy is what keeps the Node module in the panel's
// dependency graph, which is the dependency X07 removes.
//
// THE ORDER IS THE WHOLE PROPERTY. `sha256sum -- *` hashes whatever is in dist/
// when it runs, and the release signature covers that manifest and nothing else.
// A copy made AFTER it produces an asset the signature does not cover: published,
// downloadable, and unverifiable by the one consumer that needs to verify it.
func TestTheReleasePublishesTheInstallTemplateUnderItsOwnSignature(t *testing.T) {
	raw, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)

	const published = `cp deployment/install.sh "dist/passwall-node-install-template.sh"`
	copied := strings.Index(text, published)
	if copied < 0 {
		t.Fatalf("the release does not publish the install template as an asset; a consumer that renders it would have to compile it in again")
	}
	// THE COMMAND, NOT THE PHRASE. Searching for `sha256sum -- *` found the
	// comment above it that names the command, which sits before the copy and made
	// this assertion fire on a file that was already correct.
	hashed := strings.Index(text, "(cd dist && sha256sum -- * > SHA256SUMS.txt)")
	if hashed < 0 {
		t.Fatal("the release no longer writes a checksum manifest")
	}
	if copied > hashed {
		t.Fatal("the template is copied into dist/ AFTER the checksum manifest is written, so the release signature does not cover it")
	}
}

// EVERY PLACEHOLDER THE TEMPLATE CARRIES IS ONE THE RENDERER FILLS.
//
// The template is a contract between two repositories now: it is published as an
// asset and rendered elsewhere, so a placeholder added here and not substituted
// there ships a script with `@@SOMETHING@@` in it. The template's own sentinel
// check turns that into a refusal at RUN time, on a host the operator has already
// trusted it on — this turns it into a failure here instead.
//
// THE REVERSE DIRECTION IS NOT CHECKED, and does not need to be: substituting a
// string the template does not contain is a no-op, not a defect.
func TestTheTemplateCarriesNoPlaceholderTheRendererLeavesBehind(t *testing.T) {
	rendered, err := RenderLinux(installationOptions())
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(rendered, "\n") {
		// The sentinel check names the marker itself, so it is the one line that is
		// allowed to contain it.
		if strings.Contains(line, "@@") && !strings.Contains(line, `*@@*`) {
			t.Fatalf("a placeholder was not substituted: %s", strings.TrimSpace(line))
		}
	}
}

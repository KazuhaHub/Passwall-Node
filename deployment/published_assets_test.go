package deployment

import (
	"os"
	"strings"
	"testing"
)

// THE RELEASE PUBLISHES ASSETS THE PANEL CONSUMES, AND THEY ARE SIGNED WITH
// EVERYTHING ELSE.
//
// The panel needs these bytes rather than copies compiled into the Node Go
// module, because those copies are what keep the module in the panel's dependency
// graph — the dependency X07 removes. The install template is the script PSP
// renders for the command it hands an operator; the core catalog is the reviewed
// data behind the panel's core selector and its enforcement boundary, which no
// API can derive and which therefore has to ship as data.
//
// THE ORDER IS THE WHOLE PROPERTY, AND IT IS THE SAME FOR BOTH. `sha256sum -- *`
// hashes whatever is in dist/ when it runs, and the release signature covers that
// manifest and nothing else. An asset placed there AFTER it is published,
// downloadable, and unverifiable by the one consumer that needs to verify it —
// which is worse than not publishing it, because it looks like it worked.
func TestTheReleasePublishesEveryConsumedAssetUnderItsOwnSignature(t *testing.T) {
	raw, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)

	// THE COMMAND, NOT THE PHRASE. Searching for `sha256sum -- *` found the comment
	// above it that names the command, which sits before the publish steps and made
	// this assertion fire on a file that was already correct.
	hashed := strings.Index(text, "(cd dist && sha256sum -- * > SHA256SUMS.txt)")
	if hashed < 0 {
		t.Fatal("the release no longer writes a checksum manifest")
	}

	for _, asset := range []struct {
		name      string
		published string
		why       string
	}{
		{
			name:      "the install template",
			published: `cp deployment/install.sh "dist/passwall-node-install-template.sh"`,
			why:       "a consumer that renders it would have to compile it in again",
		},
		{
			name:      "the core catalog",
			published: `go run ./deployment/cmd/publish-core-catalog -output dist/core-catalog.json`,
			why:       "a panel that cannot read it offers no core to install",
		},
	} {
		t.Run(asset.name, func(t *testing.T) {
			at := strings.Index(text, asset.published)
			if at < 0 {
				t.Fatalf("the release does not publish %s; %s", asset.name, asset.why)
			}
			if at > hashed {
				t.Fatalf("%s reaches dist/ AFTER the checksum manifest is written, so the release signature does not cover it", asset.name)
			}
		})
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

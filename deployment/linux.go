// Package deployment renders private, version-pinned deployment assets.
package deployment

import (
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"github.com/KazuhaHub/passwall-node/v4/internal/nodeconfig"
	"github.com/KazuhaHub/passwall-node/v4/releaseid"
)

// The installation modes, and they are what the control plane asked for rather
// than what the script can work out for itself: an existing installation is either
// left alone, given a different release, or replaced. It is a closed set because a
// typo has to fail here rather than fall through to the most permissive branch.
const (
	// ModeInstall is the default: install where there is nothing, and refuse where
	// the release or the identity differs.
	ModeInstall = "install"
	// ModeUpgrade replaces the RELEASE of the installation that is here and keeps its
	// identity. The credential and the endpoint must still match byte for byte; only
	// the version may differ.
	ModeUpgrade = "upgrade"
	// ModeReplace puts a DIFFERENT identity on a host that already has one, which is
	// what a server moving to another control plane needs. The installation that is
	// there is stopped and moved into the backup area whole, so the new identity
	// starts with empty state and the old one is still recoverable by hand.
	//
	// IT IS NOT A SHORTCUT FOR A FAILED UPGRADE. An upgrade keeps the identity and
	// the state and can be rolled back to the previous release; this cannot be,
	// because the state it would be rolled back to belongs to an identity the panel
	// no longer has a row for.
	ModeReplace = "replace"
)

// Options names an already registered identity and an already published release.
// Credential is secret: never log Options or the rendered installation script.
type Options struct {
	Endpoint   string
	AgentID    string
	Credential string
	Version    string
	// Tag is the ADDRESS of the release to install from, when the caller knows it.
	// Empty means "derive it from the version", and the reason it can be stated at
	// all is that a version no longer determines one address: the four releases
	// published before the address changed live at `release/…`, and no version string
	// says which namespace its release went out under. The panel states the tag it
	// published; a caller that has one passes it.
	Tag string
	// Mode is empty for ModeInstall.
	Mode string
}

//go:embed install.sh
var linuxTemplate string

// RenderLinux returns a secret-bearing shell script for Linux/systemd on amd64
// or arm64. Save it mode 0600 and execute the file with sh as root; never pipe a
// credential through command arguments, shell tracing, history or shared logs.
//
// INSTALLATION CHANGES AN EXISTING IDENTITY ONLY WHEN THE CONTROL PLANE SAYS SO IN
// `mode`, AND THEN IN ONE DIRECTION: ModeReplace takes the host over for a
// different identity after moving the one that is there into the backup area, and
// ModeUpgrade changes the RELEASE while keeping the identity and the state in
// place. Every other combination is refused, including a release that differs with
// no mode — an install is always to an empty path or to the identity already there.
func RenderLinux(options Options) (string, error) {
	if !ValidReleaseVersion(options.Version) {
		return "", errors.New("installation requires an explicit MAJOR.MINOR.PATCH release version")
	}
	mode := options.Mode
	if mode == "" {
		mode = ModeInstall
	}
	switch mode {
	case ModeInstall, ModeUpgrade, ModeReplace:
	default:
		return "", fmt.Errorf("installation mode %q is not one this template understands", mode)
	}
	// THE "TEMPLATE IS TOO OLD TO UPGRADE" CHECK IS NOT HERE, because it cannot
	// happen here: this function renders the template compiled into this build, so the
	// two always move together. It belongs where a template can be older than the
	// renderer — the panel, which fetches one from a published release.
	connection := nodeconfig.Connection{Endpoint: options.Endpoint, AgentID: options.AgentID, Credential: options.Credential}
	if err := nodeconfig.Validate(connection); err != nil {
		return "", fmt.Errorf("installation connection: %w", err)
	}
	// THE ADDRESS IS STATED OR DERIVED, AND CHECKED AGAINST THE VERSION EITHER WAY.
	// The template downloads from this and writes it into the script, and the release
	// it fetched is checked against the version the caller asked for — so a pair that
	// disagrees would surface as a checksum failure at best, and as an installation
	// of the wrong release at worst.
	//
	// IT IS NOT ALWAYS DERIVABLE. A version no longer determines one address: the four
	// releases published before the namespace changed are addressed as `release/…`,
	// and deriving one for those names a tag nobody published. A caller that knows the
	// address hands it over; a caller that does not gets the current namespace's,
	// which is right for a release about to be published.
	var tag releaseid.Tag
	if options.Tag != "" {
		stated, err := releaseid.ParseReleaseTag(options.Tag)
		if err != nil || stated.VersionString() != options.Version {
			return "", fmt.Errorf("installation release tag %q does not name the release version %q", options.Tag, options.Version)
		}
		tag = stated
	} else {
		derived, err := releaseid.TagForVersion(options.Version)
		if err != nil {
			return "", fmt.Errorf("installation release version: %w", err)
		}
		tag = derived
	}
	return strings.NewReplacer(
		"@@VERSION@@", shellQuote(options.Version),
		"@@TAG@@", shellQuote(tag.Raw),
		"@@MODE@@", shellQuote(mode),
		"@@AGENT_ID@@", shellQuote(options.AgentID),
		"@@ENDPOINT@@", shellQuote(options.Endpoint),
		"@@CREDENTIAL@@", shellQuote(options.Credential),
		"@@ENVIRONMENT@@", shellQuote(nodeconfig.EnvironmentFile(connection)),
	).Replace(linuxTemplate), nil
}

// ValidReleaseVersion is the single release-version rule shared by installation
// and publishing. No floating aliases, leading zeroes, build metadata or tags.
//
// THE NAME IS HISTORICAL AND THE RULE IS NOT. It delegated to the legacy rule
// while the version in this template doubled as the download path, which is the
// one arrangement in which a version has to be its own address. The template now
// takes the tag separately, so the version is checked as a version — and a
// release is addressed by its tag rather than by its name.
func ValidReleaseVersion(value string) bool {
	return releaseid.ValidVersion(value)
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

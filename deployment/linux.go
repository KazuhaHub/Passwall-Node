// Package deployment renders private, version-pinned deployment assets.
package deployment

import (
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"github.com/KazuhaHub/passwall-node/internal/nodeconfig"
	"github.com/KazuhaHub/passwall-node/releaseid"
)

// Options names an already registered identity and an already published release.
// Credential is secret: never log Options or the rendered installation script.
type Options struct {
	Endpoint   string
	AgentID    string
	Credential string
	Version    string
}

//go:embed install.sh
var linuxTemplate string

// RenderLinux returns a secret-bearing shell script for Linux/systemd on amd64
// or arm64. Save it mode 0600 and execute the file with sh as root; never pipe a
// credential through command arguments, shell tracing, history or shared logs.
// Installation never changes an existing identity, credential or release.
func RenderLinux(options Options) (string, error) {
	if !ValidReleaseVersion(options.Version) {
		return "", errors.New("installation requires an explicit MAJOR.MINOR.PATCH release version")
	}
	connection := nodeconfig.Connection{Endpoint: options.Endpoint, AgentID: options.AgentID, Credential: options.Credential}
	if err := nodeconfig.Validate(connection); err != nil {
		return "", fmt.Errorf("installation connection: %w", err)
	}
	// THE TAG IS DERIVED HERE, NOT SENT ALONGSIDE. A caller that had to pass both
	// could pass them out of step, and the template would then download one release
	// and install another — the release it fetched is checked against the version
	// it was told, so the mismatch would surface as a checksum failure at best.
	tag, err := releaseid.TagForVersion(options.Version)
	if err != nil {
		return "", fmt.Errorf("installation release version: %w", err)
	}
	return strings.NewReplacer(
		"@@VERSION@@", shellQuote(options.Version),
		"@@TAG@@", shellQuote(tag.Raw),
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

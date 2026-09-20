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
		return "", errors.New("installation requires an explicit vMAJOR.MINOR.PATCH[-prerelease] release")
	}
	connection := nodeconfig.Connection{Endpoint: options.Endpoint, AgentID: options.AgentID, Credential: options.Credential}
	if err := nodeconfig.Validate(connection); err != nil {
		return "", fmt.Errorf("installation connection: %w", err)
	}
	return strings.NewReplacer(
		"@@VERSION@@", shellQuote(options.Version),
		"@@AGENT_ID@@", shellQuote(options.AgentID),
		"@@ENDPOINT@@", shellQuote(options.Endpoint),
		"@@CREDENTIAL@@", shellQuote(options.Credential),
		"@@ENVIRONMENT@@", shellQuote(nodeconfig.EnvironmentFile(connection)),
	).Replace(linuxTemplate), nil
}

// ValidReleaseVersion is the single release-tag rule shared by installation
// and publishing. No floating aliases, leading zeroes or build metadata.
//
// It is the LEGACY rule and it delegates to the one implementation of it, in
// releaseid. The name is historical: what it validates is a version, and the
// product scheme's versions are deliberately not accepted here. A product
// version is not the path a release lives at, so an installer that took one
// would build a download URL to somewhere that does not exist.
func ValidReleaseVersion(value string) bool {
	return releaseid.ValidLegacyVersion(value)
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

// Package deployment renders private, version-pinned deployment assets.
package deployment

import (
	_ "embed"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/KazuhaHub/passwall-node/internal/nodeconfig"
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

var releaseVersion = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

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
func ValidReleaseVersion(value string) bool {
	if !releaseVersion.MatchString(value) {
		return false
	}
	_, prerelease, exists := strings.Cut(value, "-")
	if !exists {
		return true
	}
	for _, segment := range strings.Split(prerelease, ".") {
		if len(segment) > 1 && segment[0] == '0' && strings.Trim(segment, "0123456789") == "" {
			return false
		}
	}
	return true
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

// Package deployment renders private, version-pinned deployment assets.
package deployment

import (
	_ "embed"
	"errors"
	"net/url"
	"regexp"
	"strings"

	"github.com/KazuhaHub/passwall-node/protocol"
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

var (
	releaseVersion = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
	agentIdentity  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)
)

// RenderLinux returns a secret-bearing shell script for Linux/systemd on amd64
// or arm64. Save it mode 0600 and execute the file with sh as root; never pipe a
// credential through command arguments, shell tracing, history or shared logs.
// Installation never changes an existing identity, credential or release.
func RenderLinux(options Options) (string, error) {
	if !validReleaseVersion(options.Version) {
		return "", errors.New("installation requires an explicit vMAJOR.MINOR.PATCH[-prerelease] release")
	}
	if !agentIdentity.MatchString(options.AgentID) {
		return "", errors.New("installation requires a canonical 1..64 byte agent ID")
	}
	if len(options.Credential) < protocol.MinNodeCredentialBytes || len(options.Credential) > protocol.MaxNodeCredentialBytes {
		return "", errors.New("installation credential has an invalid length")
	}
	for _, character := range []byte(options.Credential) {
		if character < 0x21 || character > 0x7e {
			return "", errors.New("installation credential must be visible ASCII without whitespace")
		}
	}
	u, err := url.Parse(options.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.RawPath != "" || u.String() != options.Endpoint || !strings.HasSuffix(u.Path, "/v1/node/sync") {
		return "", errors.New("installation endpoint must be an absolute HTTPS sync URL without userinfo, query or fragment")
	}
	for _, character := range []byte(options.Endpoint) {
		if character < 0x21 || character > 0x7e || character == '\\' {
			return "", errors.New("installation endpoint must be canonical ASCII")
		}
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return "", errors.New("installation endpoint path must not traverse directories")
		}
	}
	if strings.Contains(u.Path, "//") {
		return "", errors.New("installation endpoint path must be canonical")
	}
	return strings.NewReplacer(
		"@@VERSION@@", shellQuote(options.Version),
		"@@AGENT_ID@@", shellQuote(options.AgentID),
		"@@ENDPOINT@@", shellQuote(options.Endpoint),
		"@@CREDENTIAL@@", shellQuote(options.Credential),
		"@@ENVIRONMENT@@", shellQuote("PSP_NODE_AGENT_ID="+environmentQuote(options.AgentID)+"\nPSP_NODE_ENDPOINT="+environmentQuote(options.Endpoint)+"\n"),
	).Replace(linuxTemplate), nil
}

func validReleaseVersion(value string) bool {
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

// EnvironmentFile is parsed by systemd, not sourced by a shell. Quote only its
// non-secret values; shell metacharacters must remain literal data.
func environmentQuote(value string) string {
	return "\"" + strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(value) + "\""
}

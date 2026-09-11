// Package corecatalog is the shared, reviewable allowlist of proxy-core
// releases that Passwall-Node may install. PSP consumes the same catalog for
// its selector, so the UI and the enforcement boundary cannot drift.
package corecatalog

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

const SchemaVersion = 1

const (
	TierRecommended    = "recommended"
	TierVerified       = "verified"
	TierConfigVerified = "config_verified"
	TierRestricted     = "restricted"

	SupportSupported   = "supported"
	SupportTransformed = "supported_with_transform"
	SupportConditional = "conditional"
	SupportUnsupported = "unsupported"
	SupportUnverified  = "unverified"

	HandshakePass            = "pass"
	HandshakeExpectedFailure = "expected_failure"
)

//go:embed catalog.json
var embedded []byte

type Catalog struct {
	SchemaVersion int       `json:"schema_version"`
	UpdatedAt     time.Time `json:"updated_at"`
	Releases      []Release `json:"releases"`
}

type Release struct {
	Engine               string               `json:"engine"`
	Version              string               `json:"version"`
	Tier                 string               `json:"tier"`
	Prerelease           bool                 `json:"prerelease"`
	Selectable           bool                 `json:"selectable"`
	RequiresConfirmation bool                 `json:"requires_confirmation"`
	PublishedAt          time.Time            `json:"published_at"`
	SourceURL            string               `json:"source_url"`
	Summary              LocalizedText        `json:"summary"`
	Reality              RealityCompatibility `json:"reality"`
	Evidence             Evidence             `json:"evidence"`
	Assets               []Asset              `json:"assets"`
}

type LocalizedText struct {
	EN string `json:"en"`
	ZH string `json:"zh_cn"`
}

type RealityCompatibility struct {
	Xray               string `json:"xray"`
	Mihomo             string `json:"mihomo"`
	SingBox            string `json:"sing_box"`
	URIList            string `json:"uri_list"`
	ServerMinClientVer string `json:"server_min_client_ver,omitempty"`
	MihomoFingerprint  string `json:"mihomo_fingerprint,omitempty"`
	MihomoMLKEM        bool   `json:"mihomo_x25519mlkem768,omitempty"`
}

type Evidence struct {
	SourceAudited   bool                `json:"source_audited"`
	ConfigTested    bool                `json:"config_tested"`
	HandshakeTested bool                `json:"handshake_tested"`
	VerifiedAt      *time.Time          `json:"verified_at,omitempty"`
	Handshakes      []HandshakeEvidence `json:"handshakes,omitempty"`
}

// HandshakeEvidence records the executable client matrix behind a release
// tier. Expected failures are first-class evidence: they keep an unsupported
// client from being silently reclassified as compatible by a prose edit.
type HandshakeEvidence struct {
	Client   string `json:"client"`
	Version  string `json:"version"`
	Platform string `json:"platform"`
	Profile  string `json:"profile"`
	Result   string `json:"result"`
}

type Asset struct {
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Archive string `json:"archive"`
	Binary  string `json:"binary"`
}

func Load() (Catalog, error) {
	var catalog Catalog
	decoder := json.NewDecoder(strings.NewReader(string(embedded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&catalog); err != nil {
		return Catalog{}, fmt.Errorf("decode embedded core catalog: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Catalog{}, errors.New("decode embedded core catalog: trailing JSON value")
		}
		return Catalog{}, fmt.Errorf("decode embedded core catalog trailing value: %w", err)
	}
	if err := validate(catalog); err != nil {
		return Catalog{}, err
	}
	return catalog, nil
}

func List(engine string) ([]Release, error) {
	catalog, err := Load()
	if err != nil {
		return nil, err
	}
	engine = strings.ToLower(strings.TrimSpace(engine))
	result := make([]Release, 0, len(catalog.Releases))
	for _, release := range catalog.Releases {
		if release.Engine == engine && release.Selectable {
			result = append(result, release)
		}
	}
	return result, nil
}

func Resolve(engine, version string) (Release, error) {
	normalized, err := NormalizeVersion(version)
	if err != nil {
		return Release{}, err
	}
	releases, err := List(engine)
	if err != nil {
		return Release{}, err
	}
	for _, release := range releases {
		if release.Version == normalized {
			return release, nil
		}
	}
	return Release{}, fmt.Errorf("%s %s is not in the selectable core catalog", engine, normalized)
}

func Recommended(engine string) (Release, error) {
	releases, err := List(engine)
	if err != nil {
		return Release{}, err
	}
	for _, release := range releases {
		if release.Tier == TierRecommended {
			return release, nil
		}
	}
	return Release{}, fmt.Errorf("%s has no recommended release", engine)
}

func (r Release) AssetFor(goos, goarch string) (Asset, error) {
	for _, asset := range r.Assets {
		if asset.OS == goos && asset.Arch == goarch {
			return asset, nil
		}
	}
	return Asset{}, fmt.Errorf("%s %s has no asset for %s/%s", r.Engine, r.Version, goos, goarch)
}

func NormalizeVersion(raw string) (string, error) {
	value := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(raw), "v"), "V")
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("core version %q must be major.minor.patch", raw)
	}
	for _, part := range parts {
		parsed, err := strconv.Atoi(part)
		if err != nil || parsed < 0 || strconv.Itoa(parsed) != part {
			return "", fmt.Errorf("core version %q is not canonical", raw)
		}
	}
	return value, nil
}

func validate(catalog Catalog) error {
	if catalog.SchemaVersion != SchemaVersion {
		return fmt.Errorf("core catalog schema %d is unsupported", catalog.SchemaVersion)
	}
	if catalog.UpdatedAt.IsZero() || len(catalog.Releases) == 0 {
		return errors.New("core catalog requires updated_at and releases")
	}
	seen := make(map[string]struct{}, len(catalog.Releases))
	recommended := make(map[string]int)
	selectableEngines := make(map[string]struct{})
	for index, release := range catalog.Releases {
		if err := validateRelease(release); err != nil {
			return fmt.Errorf("core catalog release %d: %w", index, err)
		}
		key := release.Engine + "/" + release.Version
		if _, exists := seen[key]; exists {
			return fmt.Errorf("core catalog contains duplicate %s", key)
		}
		seen[key] = struct{}{}
		if release.Selectable && release.Tier == TierRecommended {
			recommended[release.Engine]++
		}
		if release.Selectable {
			selectableEngines[release.Engine] = struct{}{}
		}
	}
	for engine := range selectableEngines {
		count := recommended[engine]
		if count != 1 {
			return fmt.Errorf("core catalog engine %s has %d recommended releases", engine, count)
		}
	}
	return nil
}

func validateRelease(release Release) error {
	if release.Engine == "" || release.Engine != strings.ToLower(release.Engine) {
		return errors.New("engine must be lowercase")
	}
	repository, knownEngine := officialRepository(release.Engine)
	if !knownEngine {
		return fmt.Errorf("unknown core engine %q", release.Engine)
	}
	version, err := NormalizeVersion(release.Version)
	if err != nil || version != release.Version {
		return errors.New("version must be canonical")
	}
	switch release.Tier {
	case TierRecommended, TierVerified, TierConfigVerified, TierRestricted:
	default:
		return fmt.Errorf("unknown tier %q", release.Tier)
	}
	if release.Tier == TierRestricted && !release.RequiresConfirmation {
		return errors.New("restricted release must require confirmation")
	}
	if release.Tier != TierRestricted && release.RequiresConfirmation {
		return errors.New("only a restricted release may require confirmation")
	}
	if release.PublishedAt.IsZero() || release.Summary.EN == "" || release.Summary.ZH == "" {
		return errors.New("published_at and localized summary are required")
	}
	source, err := url.Parse(release.SourceURL)
	wantSourcePath := "/" + repository + "/releases/tag/v" + release.Version
	if err != nil || source.Scheme != "https" || source.Host != "github.com" || source.Path != wantSourcePath || source.RawQuery != "" || source.Fragment != "" || source.User != nil {
		return errors.New("source_url must be the matching official GitHub release")
	}
	if !release.Evidence.SourceAudited || release.Evidence.VerifiedAt == nil {
		return errors.New("source audit evidence and verified_at are required")
	}
	if release.Selectable && !release.Evidence.ConfigTested {
		return errors.New("selectable release requires config validation evidence")
	}
	if (release.Tier == TierRecommended || release.Tier == TierVerified || release.Tier == TierRestricted) && !release.Evidence.HandshakeTested {
		return fmt.Errorf("%s release requires a completed handshake matrix", release.Tier)
	}
	for _, level := range []string{release.Reality.Xray, release.Reality.Mihomo, release.Reality.SingBox, release.Reality.URIList} {
		switch level {
		case SupportSupported, SupportTransformed, SupportConditional, SupportUnsupported, SupportUnverified:
		default:
			return fmt.Errorf("unknown REALITY support level %q", level)
		}
	}
	if release.Reality.MihomoMLKEM && release.Reality.MihomoFingerprint == "" {
		return errors.New("Mihomo ML-KEM requires a pinned fingerprint")
	}
	if err := validateHandshakes(release); err != nil {
		return err
	}
	assets := make(map[string]struct{}, len(release.Assets))
	for _, asset := range release.Assets {
		if err := validateAsset(release, asset); err != nil {
			return err
		}
		target := asset.OS + "/" + asset.Arch
		if _, exists := assets[target]; exists {
			return fmt.Errorf("duplicate asset target %s", target)
		}
		assets[target] = struct{}{}
	}
	wantTargets := []string{"darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64", "windows/amd64", "windows/arm64"}
	sort.Strings(wantTargets)
	gotTargets := make([]string, 0, len(assets))
	for target := range assets {
		gotTargets = append(gotTargets, target)
	}
	sort.Strings(gotTargets)
	if strings.Join(gotTargets, ",") != strings.Join(wantTargets, ",") {
		return fmt.Errorf("assets cover %v, want %v", gotTargets, wantTargets)
	}
	return nil
}

func validateHandshakes(release Release) error {
	handshakes := release.Evidence.Handshakes
	if release.Evidence.HandshakeTested != (len(handshakes) > 0) {
		return errors.New("handshake_tested must match the presence of handshake evidence")
	}
	seen := make(map[string]struct{}, len(handshakes))
	tested := make(map[string]struct{ pass, expectedFailure bool })
	for _, handshake := range handshakes {
		if handshake.Client == "" || handshake.Version == "" || handshake.Platform == "" || handshake.Profile == "" {
			return errors.New("handshake evidence requires client, version, platform and profile")
		}
		if handshake.Client != "xray" && handshake.Client != "mihomo" && handshake.Client != "sing_box" {
			return fmt.Errorf("unknown handshake client %q", handshake.Client)
		}
		if handshake.Result != HandshakePass && handshake.Result != HandshakeExpectedFailure {
			return fmt.Errorf("unknown handshake result %q", handshake.Result)
		}
		key := strings.Join([]string{handshake.Client, handshake.Version, handshake.Platform, handshake.Profile}, "\x00")
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate handshake evidence for %s %s", handshake.Client, handshake.Version)
		}
		seen[key] = struct{}{}
		state := tested[handshake.Client]
		state.pass = state.pass || handshake.Result == HandshakePass
		state.expectedFailure = state.expectedFailure || handshake.Result == HandshakeExpectedFailure
		tested[handshake.Client] = state
	}
	for client, support := range map[string]string{
		"xray": release.Reality.Xray, "mihomo": release.Reality.Mihomo, "sing_box": release.Reality.SingBox,
	} {
		result := tested[client]
		switch support {
		case SupportSupported, SupportTransformed, SupportConditional:
			if release.Evidence.HandshakeTested && !result.pass {
				return fmt.Errorf("%s support requires passing handshake evidence", client)
			}
		case SupportUnsupported:
			if release.Evidence.HandshakeTested && (!result.expectedFailure || result.pass) {
				return fmt.Errorf("%s unsupported status requires expected-failure evidence", client)
			}
		}
	}
	return nil
}

func validateAsset(release Release, asset Asset) error {
	if (asset.OS != "linux" && asset.OS != "darwin" && asset.OS != "windows") ||
		(asset.Arch != "amd64" && asset.Arch != "arm64") {
		return fmt.Errorf("unsupported asset target %s/%s", asset.OS, asset.Arch)
	}
	if (asset.Archive != "zip" && asset.Archive != "tar.gz") || !validArchiveMember(asset.Binary) {
		return errors.New("asset must use a supported archive and a safe binary path")
	}
	decoded, err := hex.DecodeString(asset.SHA256)
	if err != nil || len(decoded) != sha256Size {
		return errors.New("asset sha256 must contain 64 lowercase hexadecimal characters")
	}
	if asset.SHA256 != strings.ToLower(asset.SHA256) {
		return errors.New("asset sha256 must be lowercase")
	}
	location, err := url.Parse(asset.URL)
	if err != nil {
		return errors.New("asset URL must belong to the matching official release")
	}
	repository, knownEngine := officialRepository(release.Engine)
	wantPrefix := "/" + repository + "/releases/download/v" + release.Version + "/"
	assetName := strings.TrimPrefix(location.Path, wantPrefix)
	if location.Scheme != "https" || location.Host != "github.com" || !strings.HasPrefix(location.Path, wantPrefix) ||
		assetName == "" || strings.Contains(assetName, "/") || location.RawQuery != "" || location.Fragment != "" || location.User != nil {
		return errors.New("asset URL must belong to the matching official release")
	}
	if !knownEngine {
		return fmt.Errorf("unknown core engine %q", release.Engine)
	}
	if asset.Archive == "zip" && !strings.HasSuffix(assetName, ".zip") ||
		asset.Archive == "tar.gz" && !strings.HasSuffix(assetName, ".tar.gz") {
		return errors.New("asset URL suffix does not match its archive type")
	}
	return nil
}

func validArchiveMember(member string) bool {
	return member != "" && !strings.Contains(member, "\\") && !path.IsAbs(member) &&
		path.Clean(member) == member && member != "." && member != ".." && !strings.HasPrefix(member, "../")
}

func officialRepository(engine string) (string, bool) {
	switch engine {
	case "xray":
		return "XTLS/Xray-core", true
	case "sing-box":
		return "SagerNet/sing-box", true
	default:
		return "", false
	}
}

const sha256Size = 32

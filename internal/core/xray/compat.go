package xray

import (
	"errors"
	"fmt"
	"strings"

	"github.com/KazuhaHub/passwall-node/corecatalog"
)

type RealityCompatibility string

const (
	RealityBroad              RealityCompatibility = "broad"
	RealityNeedsMinClientZero RealityCompatibility = "needs_min_client_zero"
	RealityRestrictedClients  RealityCompatibility = "restricted_clients"
)

// RealityCompatibilityFor classifies an exact release from the shared audited
// catalog. Unknown releases fail closed instead of inheriting a range guess.
func RealityCompatibilityFor(version string) (RealityCompatibility, error) {
	release, err := corecatalog.Resolve("xray", version)
	if err != nil {
		return "", err
	}
	switch {
	case release.Reality.ServerMinClientVer != "":
		return RealityNeedsMinClientZero, nil
	case release.Tier == corecatalog.TierRestricted:
		return RealityRestrictedClients, nil
	case release.Reality.Mihomo == corecatalog.SupportSupported && release.Reality.SingBox == corecatalog.SupportSupported:
		return RealityBroad, nil
	}
	return "", fmt.Errorf("Xray %s has no recognized REALITY policy", release.Version)
}

func (c Compiler) resolveCoreRelease() (corecatalog.Release, error) {
	version := strings.TrimSpace(c.CoreVersion)
	if version == "" {
		return corecatalog.Recommended("xray")
	}
	return corecatalog.Resolve("xray", version)
}

func (c Compiler) applyRealityCompatibility(release corecatalog.Release, stream map[string]any) error {
	security, _ := stream["security"].(string)
	if !strings.EqualFold(strings.TrimSpace(security), "reality") {
		return nil
	}
	compatibility, err := RealityCompatibilityFor(release.Version)
	if err != nil {
		return fmt.Errorf("xray version %q: %w", release.Version, err)
	}
	switch compatibility {
	case RealityBroad:
		return nil
	case RealityNeedsMinClientZero:
		settings, err := objectField(stream, "realitySettings")
		if err != nil {
			return err
		}
		// This is a compatibility widening, never an authorization widening:
		// REALITY's cryptographic authentication remains unchanged. It only
		// avoids treating third-party version encodings as outdated Xray builds.
		settings["minClientVer"] = release.Reality.ServerMinClientVer
		return nil
	case RealityRestrictedClients:
		if c.AllowRestrictedReality {
			return nil
		}
		return &RejectedError{
			Code: realityClientRejected,
			Err:  fmt.Errorf("Xray %s REALITY compatibility is %s; Mihomo requires chrome plus support-x25519mlkem768 and sing-box is unsupported", release.Version, compatibility),
		}
	default:
		return errors.New("unknown REALITY compatibility classification")
	}
}

// RejectedError is local to the compiler because importing agent.RejectedError
// would reverse the core boundary. The caller promotes Code into the roster or
// config object state without parsing human-readable text.
type RejectedError struct {
	Code string
	Err  error
}

func (e *RejectedError) Error() string {
	if e == nil {
		return "xray compatibility rejected"
	}
	return fmt.Sprintf("%s: %v", e.Code, e.Err)
}

func (e *RejectedError) Unwrap() error { return e.Err }

func objectField(parent map[string]any, key string) (map[string]any, error) {
	value, exists := parent[key]
	if !exists || value == nil {
		result := make(map[string]any)
		parent[key] = result
		return result, nil
	}
	result, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a JSON object", key)
	}
	return result, nil
}

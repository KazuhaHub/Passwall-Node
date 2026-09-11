package corecatalog

import "testing"

func TestEmbeddedCatalogIsValid(t *testing.T) {
	t.Parallel()
	catalog, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Releases) != 4 {
		t.Fatalf("release count = %d, want 4", len(catalog.Releases))
	}
}

func TestRecommendedSingBoxCarriesExecutableMatrixAndOfficialAssets(t *testing.T) {
	t.Parallel()
	release, err := Recommended("sing-box")
	if err != nil {
		t.Fatal(err)
	}
	if release.Version != "1.14.0" || !release.Evidence.ConfigTested || !release.Evidence.HandshakeTested || len(release.Evidence.Handshakes) != 3 {
		t.Fatalf("unexpected recommended sing-box release: %#v", release)
	}
	asset, err := release.AssetFor("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if asset.Archive != "tar.gz" || asset.Binary != "sing-box-1.14.0-linux-amd64/sing-box" {
		t.Fatalf("unexpected sing-box asset: %#v", asset)
	}
}

func TestRecommendedXrayIsBroadCompatibilityBaseline(t *testing.T) {
	t.Parallel()
	release, err := Recommended("xray")
	if err != nil {
		t.Fatal(err)
	}
	if release.Version != "26.6.27" || release.Reality.Mihomo != SupportSupported || release.Reality.SingBox != SupportSupported || !release.Evidence.HandshakeTested {
		t.Fatalf("unexpected recommended release: %#v", release)
	}
}

func TestVerifiedCandidateCarriesExecutableHandshakeEvidence(t *testing.T) {
	t.Parallel()
	release, err := Resolve("xray", "26.7.28")
	if err != nil {
		t.Fatal(err)
	}
	if release.Tier != TierVerified || len(release.Evidence.Handshakes) != 3 {
		t.Fatalf("unexpected verified release: %#v", release)
	}
}

func TestCatalogRejectsHandshakeClaimWithoutEvidence(t *testing.T) {
	t.Parallel()
	catalog, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	catalog.Releases[0].Evidence.Handshakes = nil
	if err := validate(catalog); err == nil {
		t.Fatal("catalog accepted handshake_tested without executable evidence")
	}
}

func TestCatalogRejectsUnsupportedClientWithoutExpectedFailure(t *testing.T) {
	t.Parallel()
	catalog, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	restricted := &catalog.Releases[2]
	for index := range restricted.Evidence.Handshakes {
		if restricted.Evidence.Handshakes[index].Client == "sing_box" {
			restricted.Evidence.Handshakes[index].Result = HandshakePass
		}
	}
	if err := validate(catalog); err == nil {
		t.Fatal("catalog accepted unsupported sing-box with passing evidence")
	}
}

func TestResolveRejectsLatestAndUnknownVersions(t *testing.T) {
	t.Parallel()
	for _, version := range []string{"latest", "26.9.8", "26.10.0"} {
		if _, err := Resolve("xray", version); err == nil {
			t.Fatalf("version %q unexpectedly resolved", version)
		}
	}
}

func TestResolveAcceptsLeadingVAndSelectsPlatformAsset(t *testing.T) {
	t.Parallel()
	release, err := Resolve("xray", "v26.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if !release.RequiresConfirmation || release.Reality.MihomoFingerprint != "chrome" || !release.Reality.MihomoMLKEM {
		t.Fatalf("restricted metadata = %#v", release)
	}
	asset, err := release.AssetFor("linux", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	if asset.SHA256 != "3e38d72dfc5eb65c91df0e5583e9b6676c32232041da47de6ae73946b526d66c" {
		t.Fatalf("unexpected asset: %#v", asset)
	}
}

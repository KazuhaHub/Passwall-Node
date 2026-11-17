package corecatalog

import (
	"strings"
	"testing"
)

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
	asset, err := release.AssetFor("linux", "amd64", LibcGlibc)
	if err != nil {
		t.Fatal(err)
	}
	if asset.Archive != "tar.gz" || asset.Binary != "sing-box-1.14.0-linux-amd64/sing-box" {
		t.Fatalf("unexpected sing-box asset: %#v", asset)
	}
}

// THE ALPINE IMAGE IS A MUSL HOST, and sing-box's plain Linux build is linked
// against glibc: exec of it there fails with ENOENT before it prints a version.
// Every Linux target therefore has to resolve to a different, musl-built asset
// on a musl host, while a glibc host keeps the asset existing installations were
// recorded with.
func TestSingBoxLinuxTargetsResolveByLibc(t *testing.T) {
	t.Parallel()
	release, err := Recommended("sing-box")
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		glibc, err := release.AssetFor("linux", arch, LibcGlibc)
		if err != nil {
			t.Fatal(err)
		}
		musl, err := release.AssetFor("linux", arch, LibcMusl)
		if err != nil {
			t.Fatal(err)
		}
		if glibc.Libc != LibcGlibc || !strings.HasSuffix(glibc.URL, "/sing-box-1.14.0-linux-"+arch+".tar.gz") {
			t.Fatalf("glibc asset for %s = %#v", arch, glibc)
		}
		if musl.Libc != LibcMusl || !strings.HasSuffix(musl.URL, "/sing-box-1.14.0-linux-"+arch+"-musl.tar.gz") ||
			musl.Binary != "sing-box-1.14.0-linux-"+arch+"-musl/sing-box" || musl.SHA256 == glibc.SHA256 {
			t.Fatalf("musl asset for %s = %#v", arch, musl)
		}
		if _, err := release.AssetFor("linux", arch, ""); err == nil {
			t.Fatalf("a linux/%s host with no libc resolved a libc-specific asset", arch)
		}
	}
	if _, err := release.AssetFor("darwin", "arm64", ""); err != nil {
		t.Fatal(err)
	}
}

// Xray's Linux builds are static Go binaries, so one asset serves both libcs.
func TestXrayLinuxAssetsServeEveryLibc(t *testing.T) {
	t.Parallel()
	releases, err := List("xray")
	if err != nil {
		t.Fatal(err)
	}
	for _, release := range releases {
		for _, arch := range []string{"amd64", "arm64"} {
			glibc, glibcErr := release.AssetFor("linux", arch, LibcGlibc)
			musl, muslErr := release.AssetFor("linux", arch, LibcMusl)
			if glibcErr != nil || muslErr != nil || glibc != musl || glibc.Libc != "" {
				t.Fatalf("xray %s linux/%s: %#v %v / %#v %v", release.Version, arch, glibc, glibcErr, musl, muslErr)
			}
		}
	}
}

func TestCatalogRejectsIncompleteOrMisplacedLibcVariants(t *testing.T) {
	t.Parallel()
	singBox := func(catalog *Catalog) *Release {
		for index := range catalog.Releases {
			if catalog.Releases[index].Engine == "sing-box" {
				return &catalog.Releases[index]
			}
		}
		t.Fatal("no sing-box release")
		return nil
	}
	cases := map[string]func(*Release){
		"musl half missing": func(release *Release) {
			kept := release.Assets[:0]
			for _, asset := range release.Assets {
				if asset.Libc != LibcMusl || asset.Arch != "arm64" {
					kept = append(kept, asset)
				}
			}
			release.Assets = kept
		},
		"variant beside a universal asset": func(release *Release) {
			for index := range release.Assets {
				if release.Assets[index].Libc == LibcGlibc && release.Assets[index].Arch == "amd64" {
					release.Assets[index].Libc = ""
				}
			}
		},
		"duplicate variant": func(release *Release) {
			for index := range release.Assets {
				if release.Assets[index].Libc == LibcGlibc && release.Assets[index].Arch == "amd64" {
					release.Assets[index].Libc = LibcMusl
				}
			}
		},
		"unknown libc": func(release *Release) {
			for index := range release.Assets {
				if release.Assets[index].Libc == LibcMusl {
					release.Assets[index].Libc = "uclibc"
				}
			}
		},
		"libc outside linux": func(release *Release) {
			for index := range release.Assets {
				if release.Assets[index].OS == "darwin" {
					release.Assets[index].Libc = LibcGlibc
				}
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			catalog, err := Load()
			if err != nil {
				t.Fatal(err)
			}
			release := singBox(&catalog)
			release.Assets = append([]Asset(nil), release.Assets...)
			mutate(release)
			if err := validate(catalog); err == nil {
				t.Fatal("catalog accepted an invalid libc variant set")
			}
		})
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
	asset, err := release.AssetFor("linux", "arm64", LibcMusl)
	if err != nil {
		t.Fatal(err)
	}
	if asset.SHA256 != "3e38d72dfc5eb65c91df0e5583e9b6676c32232041da47de6ae73946b526d66c" {
		t.Fatalf("unexpected asset: %#v", asset)
	}
}

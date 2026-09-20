package deployment

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The public installer's release resolution, driven against release documents.
//
// IT EXTRACTS THE REAL FUNCTION FROM install.sh rather than restating it. The
// installer is a single file fetched with curl and executed by sh(1) — it cannot
// import a helper, and the resolution logic therefore cannot live anywhere else.
// Running the whole script is not an option either: its first phase demands root
// and a running systemd host, so a test that executed it would be testing the
// host. Sourcing the function is the only way to exercise the shipped code, and
// it deliberately does not get to drift from it.
func resolveFunctions(t *testing.T) string {
	t.Helper()
	script, err := os.ReadFile("../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	// The trusted download prefix is an assignment rather than a function, and it
	// is extracted for the same reason the functions are: a test that restated it
	// would keep passing after install.sh changed which repository it trusts.
	prefix := ""
	for _, line := range strings.Split(string(script), "\n") {
		if strings.HasPrefix(line, "release_repository_prefix=") {
			prefix = line
			break
		}
	}
	if prefix == "" {
		t.Fatal("install.sh does not declare the trusted download prefix; the test cannot drive the shipped resolution")
	}
	out = append(out, prefix)
	for _, name := range []string{"fail", "one_line", "resolve_release"} {
		body, ok := shellFunction(string(script), name)
		if !ok {
			t.Fatalf("install.sh has no %s function; the test cannot drive the shipped resolution", name)
		}
		out = append(out, body)
	}
	return strings.Join(out, "\n\n")
}

// shellFunction returns a top-level shell function definition verbatim, from its
// `name() {` line to the closing brace in column zero. Parsing by the closing
// brace rather than by line count keeps this honest when the function grows.
func shellFunction(script, name string) (string, bool) {
	lines := strings.Split(script, "\n")
	start := -1
	for i, line := range lines {
		if line == name+"() {" {
			start = i
			break
		}
	}
	if start < 0 {
		return "", false
	}
	for i := start + 1; i < len(lines); i++ {
		if lines[i] == "}" {
			return strings.Join(lines[start:i+1], "\n"), true
		}
	}
	return "", false
}

// driver builds a script that sources the extracted functions and resolves one
// release document, printing what it selected. A refusal exits non-zero with the
// installer's own message, which is what the refusal cases assert on.
func driver(t *testing.T, document string, arch string) *exec.Cmd {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "resolve.sh")
	body := "set -eu\nphase_number=2\nphase_name='Resolve a published release'\n\n" +
		resolveFunctions(t) + "\n\nresolve_release \"$1\" \"$2\"\n" +
		"printf 'tag=%s\\nversion=%s\\narchive=%s\\nmanifest=%s\\n' " +
		"\"$release_tag\" \"$version\" \"$release_archive_url\" \"$release_manifest_url\"\n"
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := filepath.Join(dir, "releases.json")
	if err := os.WriteFile(doc, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	return exec.Command("sh", script, doc, arch)
}

const downloadPrefix = "https://github.com/KazuhaHub/Passwall-Node/releases/download/"

// releaseDocument renders one release the way the GitHub API does: pretty
// printed, top level object first, assets last.
// releaseDocumentAt is one release with a stated publication time. The time is what
// chooses the release now, so a fixture without one describes a document the
// resolver refuses — and a fixture that gave them all the same instant would test
// the tie-break rather than the choice.
func releaseDocumentAt(tag, publishedAt string, assets ...string) string {
	var b strings.Builder
	b.WriteString("[\n  {\n")
	b.WriteString(`    "url": "https://api.github.com/repos/KazuhaHub/Passwall-Node/releases/1",` + "\n")
	b.WriteString(`    "tag_name": "` + tag + `",` + "\n")
	b.WriteString(`    "published_at": "` + publishedAt + `",` + "\n")
	b.WriteString(`    "name": "Passwall Node ` + tag + `",` + "\n")
	b.WriteString("    \"assets\": [\n")
	for i, asset := range assets {
		comma := ","
		if i == len(assets)-1 {
			comma = ""
		}
		b.WriteString("      {\n")
		b.WriteString(`        "name": "` + asset + `",` + "\n")
		b.WriteString(`        "browser_download_url": "` + downloadPrefix + tag + "/" + asset + `"` + "\n")
		b.WriteString("      }" + comma + "\n")
	}
	b.WriteString("    ]\n  }\n]\n")
	return b.String()
}

func releaseDocument(tag string, assets ...string) string {
	return releaseDocumentAt(tag, "2026-09-20T07:08:15Z", assets...)
}

func TestResolveReleaseSelectsTheCanonicalArchive(t *testing.T) {
	for _, tc := range []struct {
		name      string
		tag       string
		arch      string
		assets    []string
		wantVer   string
		wantAsset string
	}{
		{
			name: "legacy tag, whose version is the tag",
			tag:  "v0.0.1-beta12", arch: "amd64",
			assets:    []string{"passwall-node_v0.0.1-beta12_linux_amd64.tar.gz", "passwall-node_v0.0.1-beta12_linux_arm64.tar.gz", "SHA256SUMS.txt"},
			wantVer:   "v0.0.1-beta12",
			wantAsset: "passwall-node_v0.0.1-beta12_linux_amd64.tar.gz",
		},
		{
			name: "product tag, whose version is not the tag",
			tag:  "release/4.0.0", arch: "arm64",
			assets:    []string{"passwall-node_4.0.0_linux_amd64.tar.gz", "passwall-node_4.0.0_linux_arm64.tar.gz", "SHA256SUMS.txt"},
			wantVer:   "4.0.0",
			wantAsset: "passwall-node_4.0.0_linux_arm64.tar.gz",
		},
		{
			// A FOURTH SEGMENT IS A VERSION IN THIS PROJECT, so the installer has to
			// recognise the name it produces — the canonical name carries whatever
			// the release is stamped with, and a pattern that stopped at three
			// would refuse a release the publisher considers valid.
			name: "product tag with a fourth segment",
			tag:  "release/4.0.0.1", arch: "amd64",
			assets:    []string{"passwall-node_4.0.0.1_linux_amd64.tar.gz", "SHA256SUMS.txt"},
			wantVer:   "4.0.0.1",
			wantAsset: "passwall-node_4.0.0.1_linux_amd64.tar.gz",
		},
		{
			name: "the other platform's archive is not a candidate",
			tag:  "release/4.0.0", arch: "arm64",
			assets:    []string{"passwall-node_4.0.0_linux_amd64.tar.gz", "passwall-node_4.1.0_linux_arm64.tar.gz", "SHA256SUMS.txt"},
			wantVer:   "4.1.0",
			wantAsset: "passwall-node_4.1.0_linux_arm64.tar.gz",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, err := driver(t, releaseDocument(tc.tag, tc.assets...), tc.arch).CombinedOutput()
			if err != nil {
				t.Fatalf("resolution refused a valid release: %v\n%s", err, output)
			}
			for _, want := range []string{
				"tag=" + tc.tag,
				"version=" + tc.wantVer,
				"archive=" + downloadPrefix + tc.tag + "/" + tc.wantAsset,
				"manifest=" + downloadPrefix + tc.tag + "/SHA256SUMS.txt",
			} {
				if !strings.Contains(string(output), want) {
					t.Errorf("resolution did not select %q:\n%s", want, output)
				}
			}
		})
	}
}

func TestResolveReleaseRefusesAmbiguousOrMissingArchives(t *testing.T) {
	for _, tc := range []struct {
		name     string
		tag      string
		arch     string
		assets   []string
		wantWord string
	}{
		{
			// Two canonical names for one platform: picking either is picking by an
			// order nobody stated.
			name: "two archives for the requested platform",
			tag:  "release/4.0.0", arch: "amd64",
			assets:   []string{"passwall-node_4.0.0_linux_amd64.tar.gz", "passwall-node_4.1.0_linux_amd64.tar.gz", "SHA256SUMS.txt"},
			wantWord: "exactly one",
		},
		{
			name: "no archive for the requested platform",
			tag:  "release/4.0.0", arch: "arm64",
			assets:   []string{"passwall-node_4.0.0_linux_amd64.tar.gz", "SHA256SUMS.txt"},
			wantWord: "exactly one",
		},
		{
			// A non-canonical name is not an archive to install, however plausible.
			name: "the archive name is not canonical",
			tag:  "release/4.0.0", arch: "amd64",
			assets:   []string{"passwall-node_4.0_linux_amd64.tar.gz", "SHA256SUMS.txt"},
			wantWord: "exactly one",
		},
		{
			name: "no checksum manifest",
			tag:  "release/4.0.0", arch: "amd64",
			assets:   []string{"passwall-node_4.0.0_linux_amd64.tar.gz"},
			wantWord: "SHA256SUMS.txt",
		},
		{
			name: "two checksum manifests",
			tag:  "release/4.0.0", arch: "amd64",
			assets:   []string{"passwall-node_4.0.0_linux_amd64.tar.gz", "SHA256SUMS.txt", "SHA256SUMS.txt"},
			wantWord: "SHA256SUMS.txt",
		},
		{
			name: "the release document describes no assets",
			tag:  "release/4.0.0", arch: "amd64",
			assets:   nil,
			wantWord: "no downloadable assets",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, err := driver(t, releaseDocument(tc.tag, tc.assets...), tc.arch).CombinedOutput()
			if err == nil {
				t.Fatalf("resolution accepted a release it must refuse:\n%s", output)
			}
			if !strings.Contains(string(output), tc.wantWord) {
				t.Errorf("refusal did not explain %q:\n%s", tc.wantWord, output)
			}
		})
	}
}

// THE ADDRESS IS CHECKED, NOT CONSTRUCTED. Every candidate URL has to address a
// download in this repository before any name is read from it, so a document
// that points somewhere else yields nothing to select rather than something to
// fetch. This is the property that makes reading the version out of the URL safe.
func TestResolveReleaseRefusesAssetsFromAnotherOrigin(t *testing.T) {
	document := releaseDocument("release/4.0.0",
		"passwall-node_4.0.0_linux_amd64.tar.gz", "SHA256SUMS.txt")
	elsewhere := strings.ReplaceAll(document,
		downloadPrefix, "https://github.com/Attacker/Passwall-Node/releases/download/")
	output, err := driver(t, elsewhere, "amd64").CombinedOutput()
	if err == nil {
		t.Fatalf("resolution accepted assets from another repository:\n%s", output)
	}
	if !strings.Contains(string(output), "this repository") {
		t.Errorf("refusal did not say the origin was wrong:\n%s", output)
	}

	// A lookalike host must not pass a prefix test either.
	suffix := strings.ReplaceAll(document, downloadPrefix,
		"https://github.com/KazuhaHub/Passwall-Node/releases/download.evil.com/")
	output, err = driver(t, suffix, "amd64").CombinedOutput()
	if err == nil {
		t.Fatalf("resolution accepted a lookalike download path:\n%s", output)
	}
}

// A tag that disagrees with the address it advertises describes a release other
// than the one it links to, and the tag is what the operator sees.
func TestResolveReleaseRefusesATagThatDoesNotAddressItsAssets(t *testing.T) {
	document := strings.Replace(releaseDocument("release/4.0.0",
		"passwall-node_4.0.0_linux_amd64.tar.gz", "SHA256SUMS.txt"),
		`"tag_name": "release/4.0.0"`, `"tag_name": "release/9.9.9"`, 1)
	output, err := driver(t, document, "amd64").CombinedOutput()
	if err == nil {
		t.Fatalf("resolution accepted a tag that addresses nothing:\n%s", output)
	}
	if !strings.Contains(string(output), "does not address") {
		t.Errorf("refusal did not name the tag/address disagreement:\n%s", output)
	}
}

// THE PAGE IS NOT IN PUBLICATION ORDER, AND THE NEWEST IS CHOSEN BY TIME.
//
// This used to refuse a document describing two releases, because the resolver
// assumed `releases[0]` was the newest and two releases would let one release's
// assets be selected against another's tag. Against the live API that assumption
// was wrong — a release published two hours later sat at index 1 — so the newest
// is now chosen by its own publication time, and the assets are scoped by the tag
// that chose it.
func TestResolveReleaseChoosesTheNewestByPublicationTime(t *testing.T) {
	older := releaseDocumentAt("v0.0.1-beta11", "2026-09-18T10:31:27Z",
		"passwall-node_v0.0.1-beta11_linux_amd64.tar.gz", "SHA256SUMS.txt")
	newer := releaseDocumentAt("release/4.0.0", "2026-09-20T09:01:33Z",
		"passwall-node_4.0.0_linux_amd64.tar.gz", "SHA256SUMS.txt")

	// The newer one SECOND, which is the arrangement the live API served.
	output, err := driver(t, older+newer, "amd64").CombinedOutput()
	if err != nil {
		t.Fatalf("a page of releases was refused instead of ordered: %v\n%s", err, output)
	}
	for _, want := range []string{
		"tag=release/4.0.0",
		"version=4.0.0",
		"archive=" + downloadPrefix + "release/4.0.0/passwall-node_4.0.0_linux_amd64.tar.gz",
	} {
		if !strings.Contains(string(output), want) {
			t.Errorf("the newer release was not chosen; missing %q:\n%s", want, output)
		}
	}
	// AND THE OTHER RELEASE'S ASSETS ARE NOT CANDIDATES. Selecting by tag is what
	// makes that true rather than lucky.
	if strings.Contains(string(output), "v0.0.1-beta11") {
		t.Errorf("an asset from the other release was selected:\n%s", output)
	}

	// A RELEASE WITH NO PUBLICATION TIME CANNOT BE ORDERED, so the page is refused
	// rather than resolved by position — which is the assumption that failed.
	timeless := strings.Replace(newer, `"published_at": "2026-09-20T09:01:33Z",`, "", 1)
	output, err = driver(t, older+timeless, "amd64").CombinedOutput()
	if err == nil {
		t.Fatalf("a page with an unorderable release was resolved:\n%s", output)
	}
	if !strings.Contains(string(output), "publication time") {
		t.Errorf("the refusal does not say what stopped it:\n%s", output)
	}
}

// A 200 THAT IS NOT A RELEASE. `curl --fail` rejects an HTTP error before this
// runs, but a proxy or a captive portal answers with a body like this one, and
// the message has to send the operator to the channel rather than to a second
// release that does not exist. The stable channel returns exactly this today,
// because every release so far is a pre-release.
func TestResolveReleaseRefusesABodyThatNamesNoRelease(t *testing.T) {
	notFound := "{\n  \"message\": \"Not Found\",\n  \"status\": \"404\"\n}\n"
	output, err := driver(t, notFound, "amd64").CombinedOutput()
	if err == nil {
		t.Fatalf("resolution accepted a body that names no release:\n%s", output)
	}
	if !strings.Contains(string(output), "named no release") {
		t.Errorf("refusal did not distinguish an absent release from an ambiguous one:\n%s", output)
	}
}

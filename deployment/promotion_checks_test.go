package deployment

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// THE PROMOTION HAS NEVER RUN, SO ITS CHECKS ARE RUN HERE. Every release so far is
// a pre-release, and the first promotion will be the first execution of this
// workflow; a string check passes on a step that asks the right question and
// misreads the answer. Each step below is taken out of promote.yml and RUN, with
// gh, docker, curl and go replaced by stubs that answer from files and record
// what they were asked. git is real.

const promotionRepository = "KazuhaHub/Passwall-Node"

type promotionStub struct{ dir, bin string }

func newPromotionStub(t *testing.T) *promotionStub {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq stands in for gh's --jq and is what the steps read JSON with")
	}
	s := &promotionStub{dir: t.TempDir()}
	s.bin = filepath.Join(s.dir, "bin")
	if err := os.Mkdir(s.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	const prelude = "#!/usr/bin/env bash\nset -euo pipefail\nargs=(\"$@\")\nflag() { for ((i = 0; i < ${#args[@]}; i++)); do if [ \"${args[$i]}\" = \"$1\" ]; then printf '%s' \"${args[$((i + 1))]}\"; return; fi; done; }\n"
	stubs := map[string]string{
		// gh answers from files and filters through the step's own --jq, as gh
		// does; a missing file is an API error.
		"gh": `printf '%s\n' "$*" >> "$STUB/gh.args"
respond() {
  [ -f "$1" ] || { echo 'HTTP 404: Not Found' >&2; exit 1; }
  expr=$(flag --jq)
  if [ -n "$expr" ]; then jq -r "$expr" < "$1"; else cat "$1"; fi
}
case "$1 $2" in
  "release download") cp "$STUB"/release/* "$(flag --dir)"/ ;;
  "run list") respond "$STUB/runs-$(flag --workflow)" ;;
  "api -X") ;;
  api\ *)
    case "$2" in
      */releases/latest) respond "$STUB/latest" ;;
      */jobs) id=${2%/jobs}; respond "$STUB/jobs-${id##*/}" ;;
      *) echo "unexpected gh api $2" >&2; exit 97 ;;
    esac ;;
  *) echo "unexpected gh $*" >&2; exit 97 ;;
esac
`,
		"docker": `printf '%s\n' "$*" >> "$STUB/docker.args"
case "$*" in
  *'{{json .Image}}'*) cat "$STUB/image" ;;
  *'{{json .Manifest}}'*) cat "$STUB/manifest" ;;
  *) echo "unexpected docker $*" >&2; exit 97 ;;
esac
`,
		// The registry: an anonymous token, then the exact tag's headers.
		"curl": `printf '%s\n' "$*" >> "$STUB/curl.args"
case "$*" in
  *ghcr.io/token*) printf '{"token":"anonymous"}\n' ;;
  *)
    if [ -f "$STUB/digest" ]; then
      printf 'HTTP/2 200\r\ncontent-type: application/vnd.oci.image.index.v1+json\r\ndocker-content-digest: %s\r\n\r\n' "$(cat "$STUB/digest")"
    else
      printf 'HTTP/2 404\r\n\r\n'
    fi ;;
esac
`,
		// sleep returns at once, and a pause is when a cached answer turns over:
		// a queued latest.next becomes what /releases/latest serves.
		"sleep": `printf '%s\n' "$*" >> "$STUB/sleep.args"
if [ -f "$STUB/latest.next" ]; then mv "$STUB/latest.next" "$STUB/latest"; fi
`,
		// go runs only verify-release, and that is the real command, built once.
		"go": `if [ "$1 $2" = "run ./deployment/cmd/verify-release" ]; then shift 2; exec "$VERIFY_RELEASE" "$@"; fi
echo "unexpected go $*" >&2; exit 97
`,
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(s.bin, name), []byte(prelude+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func (s *promotionStub) file(t *testing.T, name, content string) {
	t.Helper()
	path := filepath.Join(s.dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (s *promotionStub) asked(t *testing.T, command string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(s.dir, command+".args"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

// run starts the step in dir with base as its environment (the test's own when
// nil), the stubs first on PATH, and extra on top.
func (s *promotionStub) run(t *testing.T, script, dir string, base []string, extra ...string) (string, error) {
	t.Helper()
	if base == nil {
		base = os.Environ()
	}
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = dir
	cmd.Env = append(append(append([]string{}, base...),
		"PATH="+s.bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"STUB="+s.dir,
		"GITHUB_REPOSITORY="+promotionRepository,
		"GITHUB_OUTPUT="+filepath.Join(s.dir, "outputs"),
	), extra...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func promotionStep(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile("../.github/workflows/promote.yml")
	if err != nil {
		t.Fatal(err)
	}
	return extractStepScript(t, workflowJob(t, string(raw), "promote"), "      - name: "+name+"\n")
}

// AN ASSET REPLACED WITH ITS MANIFEST LINE IS REFUSED, which is what re-hashing
// alone let through. No test can hold a manifest the release key signed over
// assets it also holds, so the published v4.0.1.5 manifest and signature stand in
// with no archives beside them: the signature passes and the hashes then fail,
// which shows the step reaches the second check only through the first.
func TestThePromotionTakesOnlyASignedManifestAndTheAssetsItDescribes(t *testing.T) {
	script := promotionStep(t, "Verify the published assets against the signed manifest")
	verify := filepath.Join(t.TempDir(), "verify-release")
	if out, err := exec.Command("go", "build", "-o", verify, "./cmd/verify-release").CombinedOutput(); err != nil {
		t.Fatalf("building verify-release: %v\n%s", err, out)
	}
	published := func(name string) string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join("cmd", "verify-release", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	const archive = "passwall-node_4.0.1.5_linux_amd64.tar.gz"
	replaced := "not the archive the release job built\n"
	digest := sha256.Sum256([]byte(replaced))

	for _, tc := range []struct {
		name   string
		assets map[string]string
		want   string
	}{
		{"signed, with its archives missing", map[string]string{
			"SHA256SUMS.txt":     published("SHA256SUMS.txt"),
			"SHA256SUMS.txt.sig": published("SHA256SUMS.txt.sig"),
		}, "the published assets no longer match their manifest"},
		{"an archive replaced together with its manifest line", map[string]string{
			archive:              replaced,
			"SHA256SUMS.txt":     hex.EncodeToString(digest[:]) + "  " + archive + "\n",
			"SHA256SUMS.txt.sig": published("SHA256SUMS.txt.sig"),
		}, "signature verification failed"},
		{"no signature", map[string]string{
			"SHA256SUMS.txt": published("SHA256SUMS.txt"),
		}, "read release signature"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := newPromotionStub(t)
			for name, content := range tc.assets {
				stub.file(t, filepath.Join("release", name), content)
			}
			out, err := stub.run(t, script, t.TempDir(), nil, "TAG=v4.0.1.5", "VERIFY_RELEASE="+verify)
			if err == nil || !strings.Contains(out, tc.want) {
				t.Fatalf("want a refusal naming %q, got err=%v:\n%s", tc.want, err, out)
			}
			if tc.want == "the published assets no longer match their manifest" && !strings.Contains(out, "verified") {
				t.Fatalf("the published signature was not what let the step reach the hashes:\n%s", out)
			}
			if asked := stub.asked(t, "gh"); len(asked) != 1 || !strings.HasPrefix(asked[0], "release download v4.0.1.5 --repo "+promotionRepository+" --dir ") {
				t.Fatalf("the step asked gh %q", asked)
			}
		})
	}
}

// THE DIGEST `latest` WILL NAME IS READ FROM THE EXACT TAG AND BOUND TO THE TAG'S
// COMMIT through the revision label every platform carries. The tag lives only on
// the remote here, so the step has to fetch it.
func TestThePromotedImageMustBeBuiltFromTheTagsCommit(t *testing.T) {
	script := promotionStep(t, "Read the exact image's digest and bind it to the tag's commit")
	const (
		tag     = "v4.0.99.1"
		version = "4.0.99.1"
		digest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	)
	image := func(amd64, arm64 string) string {
		label := func(revision string) string {
			if revision == "" {
				return `{"config":{"Labels":{"org.opencontainers.image.version":"` + version + `"}}}`
			}
			return `{"config":{"Labels":{"org.opencontainers.image.revision":"` + revision + `"}}}`
		}
		return `{"linux/amd64":` + label(amd64) + `,"linux/arm64":` + label(arm64) + `}`
	}
	for _, tc := range []struct {
		name           string
		digest         bool
		amd64, arm64   string // "tagged", "other" or "" for no label
		accepted       bool
		refusalMention string
	}{
		{"both platforms built from the tag", true, "tagged", "tagged", true, ""},
		{"one platform built from another commit", true, "tagged", "other", false, "was built from"},
		{"a platform with no revision label", true, "none", "tagged", false, "was built from"},
		{"no exact image tag", false, "tagged", "tagged", false, "no readable digest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newReleaseRepo(t)
			tagged := repo.commit(t, "tagged")
			repo.tagOnRemote(t, tagged, tag)
			gitIn(t, repo.work, "tag", "-d", tag)
			other := repo.commit(t, "other")
			commits := map[string]string{"tagged": tagged, "other": other, "none": ""}

			stub := newPromotionStub(t)
			if tc.digest {
				stub.file(t, "digest", digest)
			}
			stub.file(t, "image", image(commits[tc.amd64], commits[tc.arm64]))
			out, err := stub.run(t, script, repo.work, repo.env, "TAG="+tag, "VERSION="+version, "GHCR_OWNER=KazuhaHub")
			written, _ := os.ReadFile(filepath.Join(stub.dir, "outputs"))
			if tc.accepted {
				if err != nil {
					t.Fatalf("an image built from the tag was refused: %v\n%s", err, out)
				}
				if strings.TrimSpace(string(written)) != "digest="+digest {
					t.Fatalf("the step wrote %q, want the digest it read", written)
				}
			} else {
				if err == nil || !strings.Contains(out, tc.refusalMention) {
					t.Fatalf("want a refusal naming %q, got err=%v:\n%s", tc.refusalMention, err, out)
				}
				if len(written) != 0 {
					t.Fatalf("a refused image still left an output: %q", written)
				}
			}
			// The VERSION addresses the image, never the tag; and the labels read
			// are the digest's, not whatever the mutable tag names by then.
			curl := strings.Join(stub.asked(t, "curl"), "\n")
			if !strings.Contains(curl, "/manifests/"+version) {
				t.Fatalf("the digest was not read from the exact version tag:\n%s", curl)
			}
			for _, asked := range stub.asked(t, "docker") {
				if !strings.Contains(asked, "ghcr.io/kazuhahub/passwall-node@"+digest) {
					t.Fatalf("docker was asked about %q rather than the digest read", asked)
				}
			}
			if !tc.digest && len(stub.asked(t, "docker")) != 0 {
				t.Fatal("an image with no digest was inspected anyway")
			}
		})
	}
}

// A PARTIAL PROMOTION IS A STATE TO FINISH. The prerelease flag is flipped only
// while it is set, so a re-run is not a second transition; the latest mark is
// stated every time, because a release made stable by hand, or by a run that
// stopped, need not be the one /releases/latest names.
func TestTheFlipStatesStableAndLatestOnEveryRun(t *testing.T) {
	script := promotionStep(t, "Flip the release to stable")
	for _, tc := range []struct {
		already string
		want    string
	}{
		{"true", "api -X PATCH repos/" + promotionRepository + "/releases/42 -f make_latest=true -F prerelease=false"},
		{"false", "api -X PATCH repos/" + promotionRepository + "/releases/42 -f make_latest=true"},
	} {
		stub := newPromotionStub(t)
		out, err := stub.run(t, script, t.TempDir(), nil, "RELEASE_ID=42", "ALREADY="+tc.already)
		if err != nil {
			t.Fatalf("prerelease=%s: %v\n%s", tc.already, err, out)
		}
		if asked := stub.asked(t, "gh"); len(asked) != 1 || asked[0] != tc.want {
			t.Fatalf("prerelease=%s: gh was asked %q, want %q", tc.already, asked, tc.want)
		}
	}
}

// THE RESULT IS READ BACK. Both mutating steps succeed when their call is
// accepted; what users get is /releases/latest and the `latest` image. The API
// may still serve the release that was latest before the PATCH, so an old answer
// is asked again, five reads in all, before it is taken as the state; the
// registry is read once.
func TestThePromotionReadsBackWhatUsersNowGet(t *testing.T) {
	script := promotionStep(t, "Confirm what the stable pointers now name")
	const (
		tag    = "v4.0.99.1"
		digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	)
	for _, tc := range []struct {
		name, latest, later, moved, refusal string
		reads                               int
	}{
		{"both pointers name the release", tag, "", digest, "", 1},
		{"a cached answer turns over", "v4.0.1.5", tag, digest, "", 2},
		{"another release is latest", "v4.0.1.5", "", digest, "/releases/latest names v4.0.1.5, not " + tag, 5},
		{"no release is latest", "", "", digest, "HTTP 404", 5},
		{"the image pointer names other bytes", tag, "", "sha256:2222222222222222222222222222222222222222222222222222222222222222", "is sha256:2222", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := newPromotionStub(t)
			if tc.latest != "" {
				stub.file(t, "latest", `{"tag_name":"`+tc.latest+`","prerelease":false}`)
			}
			if tc.later != "" {
				stub.file(t, "latest.next", `{"tag_name":"`+tc.later+`","prerelease":false}`)
			}
			stub.file(t, "manifest", `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","digest":"`+tc.moved+`","size":855}`)
			out, err := stub.run(t, script, t.TempDir(), nil, "TAG="+tag, "DIGEST="+digest, "GHCR_OWNER=KazuhaHub")
			if reads := len(stub.asked(t, "gh")); reads != tc.reads {
				t.Fatalf("/releases/latest was read %d times, want %d:\n%s", reads, tc.reads, out)
			}
			if pauses := stub.asked(t, "sleep"); len(pauses) != tc.reads-1 {
				t.Fatalf("paused %q between %d reads", pauses, tc.reads)
			}
			if tc.refusal == "" {
				if err != nil {
					t.Fatalf("a completed promotion was refused: %v\n%s", err, out)
				}
				if asked := stub.asked(t, "docker"); len(asked) != 1 || !strings.Contains(asked[0], "ghcr.io/kazuhahub/passwall-node:latest") {
					t.Fatalf("the image pointer read back was %q", asked)
				}
				return
			}
			if err == nil || !strings.Contains(out, tc.refusal) {
				t.Fatalf("want a refusal naming %q, got err=%v:\n%s", tc.refusal, err, out)
			}
		})
	}
}

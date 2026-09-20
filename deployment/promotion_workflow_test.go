package deployment

import (
	"os"
	"strings"
	"testing"
)

// The promotion workflow's invariants, pinned because every one of them is a
// promise a YAML edit breaks silently.
func TestPromotionReusesArtefactsRatherThanBuilding(t *testing.T) {
	raw, err := os.ReadFile("../.github/workflows/promote.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)

	// IT NEVER BUILDS. The whole point of a promotion is that what users receive is
	// what was tested — same bytes, not same source — so a build step here would
	// silently publish an artefact nobody verified, under a name that says it was.
	// `docker buildx imagetools create` is a RETAG BY DIGEST and is the point of the
	// workflow, so the build patterns are narrower than the word "build": a
	// trailing space rules out buildx, and the subcommand is named for the rest.
	for _, forbidden := range []string{"go build", "docker build ", "buildx build", "build-push-action", "--no-cache"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("the promotion builds rather than reuses: %q", forbidden)
		}
	}

	// AND IT MOVES A POINTER TO A DIGEST IT READ. A digest arriving as an input
	// would let a caller point `latest` at an image no release produced.
	if !strings.Contains(text, "${repository}@${DIGEST}") {
		t.Fatal("the promotion does not retag by digest, so it is not pinned to the verified image")
	}
	if strings.Contains(text, "inputs.digest") {
		t.Fatal("the digest is a workflow input; it must be read from the registry")
	}
	if !strings.Contains(text, "docker-content-digest:") {
		t.Fatal("the promotion does not read the digest back from the registry")
	}

	// `latest` MOVES AND `beta` DOES NOT. beta tracks the newest of any kind, which
	// publication already set; a promotion that advanced it too would move a
	// testing pointer to a stable release as a side effect.
	if !strings.Contains(text, ":latest") {
		t.Fatal("the promotion does not move the latest pointer")
	}
	if strings.Contains(text, ":beta") {
		t.Fatal("the promotion touches the beta pointer, which tracks the newest of any kind")
	}
}

// ONE TRIGGER, AND IT IS A HUMAN. A `release: published` trigger would promote on
// an event a workflow produced, which is the opposite of the deliberate act V06
// describes — and it would run on every pre-release the publication path creates.
func TestPromotionIsOnlyEverDispatchedByHand(t *testing.T) {
	raw, err := os.ReadFile("../.github/workflows/promote.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, forbidden := range []string{"  push:", "  release:", "  schedule:"} {
		if strings.Contains(text, "\n"+forbidden) {
			t.Fatalf("the promotion has an automatic trigger: %q", strings.TrimSpace(forbidden))
		}
	}
	if !strings.Contains(text, "workflow_dispatch:") {
		t.Fatal("the promotion has no manual trigger")
	}
	// AND IT IS GATED LIKE PUBLICATION. Moving a pointer consumers follow is the
	// same class of decision as publishing, so it uses the same protected
	// environment rather than a second, weaker path to the same place.
	if !strings.Contains(text, "environment: release-signing") {
		t.Fatal("the promotion is not behind the same protected environment as publication")
	}
}

// A PARTIAL PROMOTION IS A STATE TO FINISH, NOT A FAILURE TO RETRY FROM SCRATCH.
// The release state, the image pointer and any policy naming this version are
// three systems; the run has to be safe to repeat, and it has to say so when it
// stopped part-way rather than report success.
func TestAPartialPromotionIsRepeatableAndSaysSo(t *testing.T) {
	raw, err := os.ReadFile("../.github/workflows/promote.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `if [ "$ALREADY" = false ]`) {
		t.Fatal("the prerelease flip is unconditional, so a re-run is not a no-op")
	}
	if !strings.Contains(text, "if: failure()") || !strings.Contains(text, "promotion_pending") {
		t.Fatal("a partial promotion is not reported as pending")
	}
}

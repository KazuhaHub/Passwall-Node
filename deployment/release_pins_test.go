package deployment

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// THE RELEASE RUNS OTHER PEOPLE'S ACTIONS ONLY BY COMMIT. The release job holds
// the signing key and the image job a token that writes packages, and a job's
// secrets can be read back out of the runner by any later step. A tag is a
// pointer its owner can move, so anything outside actions/* is pinned to a full
// commit, with the version beside it for Dependabot and for a reader.
func TestTheReleaseRunsThirdPartyActionsOnlyByCommit(t *testing.T) {
	raw, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	uses := regexp.MustCompile(`(?m)^\s+(?:- )?uses: ([^@\s]+)@(\S+)(.*)$`).FindAllStringSubmatch(string(raw), -1)
	if all := strings.Count(string(raw), "uses: "); all != len(uses) || all == 0 {
		t.Fatalf("%d uses: lines, %d in the shape this guard reads", all, len(uses))
	}
	pinned := regexp.MustCompile(`^[0-9a-f]{40}$`)
	version := regexp.MustCompile(`^ # v\d+\.\d+\.\d+$`)
	thirdParty := 0
	for _, use := range uses {
		action, ref, comment := use[1], use[2], use[3]
		if strings.HasPrefix(action, "actions/") {
			continue
		}
		thirdParty++
		if !pinned.MatchString(ref) || !version.MatchString(comment) {
			t.Errorf("%s@%s%s is not pinned to a commit with its version beside it", action, ref, comment)
		}
	}
	if thirdParty == 0 {
		t.Fatal("the release runs no third-party action; this guard reads nothing")
	}
}

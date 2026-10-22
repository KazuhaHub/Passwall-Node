// Command release-tag validates publisher input with the release identity rule.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/KazuhaHub/passwall-node/v4/releaseid"
)

// The tag, not the version. `deployment.ValidReleaseVersion` is the
// INSTALLATION rule and it validates a version — what a release is called once
// it is published. This command validates a TAG, which for the product scheme
// is `release/4.0.0` and is not a version at all. Using the installation rule
// here refused every product tag, and because this binary is the gate two
// release workflows run before they build anything, the refusal was the whole
// release rather than a wrong artifact.
//
// The two rules stay separate on purpose: they answer different questions, and
// a single rule that answered both would have to accept a version where a tag
// belongs.
//
// ON SUCCESS IT PRINTS THE VERSION AND NOTHING ELSE. The workflow needs both
// identities — the tag for the git ref and the download URL, the version for
// the build stamp, the archive name and the image tag — and the second is
// derivable from the first. Deriving it here rather than in shell keeps one
// implementation of a rule whose whole point is that there is one, and printing
// only the version means `$(...)` cannot capture a banner into a filename.
// A refusal prints nothing on stdout, so a caller that ignores the exit status
// still cannot build with an empty or invented version.
func main() {
	args := os.Args[1:]
	publish := len(args) == 2 && args[0] == "--publish"
	if publish {
		args = args[1:]
	}
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "release requires an explicit tag: release/MAJOR.MINOR.PATCH or a legacy vMAJOR.MINOR.PATCH[-prerelease]")
		os.Exit(1)
	}
	tag, err := releaseid.ParseReleaseTag(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "not a publishable release tag: %v\n", err)
		os.Exit(1)
	}
	if publish && (strings.HasPrefix(args[0], "release/") || len(strings.Split(strings.SplitN(tag.VersionString(), "-", 2)[0], ".")) != 3) {
		fmt.Fprintln(os.Stderr, "new releases require three segments, optionally followed by -beta.N or -rc.N; historical tags remain readable")
		os.Exit(1)
	}

	fmt.Println(tag.VersionString())
}

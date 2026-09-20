// Command release-tag validates publisher input with the release identity rule.
package main

import (
	"fmt"
	"os"

	"github.com/KazuhaHub/passwall-node/releaseid"
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
func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "release requires an explicit tag: release/MAJOR.MINOR.PATCH or a legacy vMAJOR.MINOR.PATCH[-prerelease]")
		os.Exit(1)
	}
	if _, err := releaseid.ParseReleaseTag(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "not a publishable release tag: %v\n", err)
		os.Exit(1)
	}
}

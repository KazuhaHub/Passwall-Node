// Command release-tag validates publisher input with the installation rule.
package main

import (
	"fmt"
	"os"

	"github.com/KazuhaHub/passwall-node/deployment"
)

func main() {
	if len(os.Args) != 2 || !deployment.ValidReleaseVersion(os.Args[1]) {
		fmt.Fprintln(os.Stderr, "release requires an explicit vMAJOR.MINOR.PATCH[-prerelease] tag")
		os.Exit(1)
	}
}

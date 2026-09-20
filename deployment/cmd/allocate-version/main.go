// Command allocate-version picks the next patch version on a release line.
//
// IT READS THE NUMBERS; IT DOES NOT CREATE THE TAG. The plan's rule is that the
// release job allocates serially and then confirms with the atomic result of
// creating an immutable tag: if the tag already exists the allocation lost a race,
// and the answer is to re-read rather than to overwrite. That confirmation is the
// workflow's, because it is the only place with the repository in hand — this
// command answers the question it can answer, and prints one version.
//
// A REFUSAL PRINTS NOTHING ON STDOUT, so a caller that reads the output without
// checking the exit status cannot build with a version this refused to allocate.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/KazuhaHub/passwall-node/releaseid"
)

func main() {
	line := flag.String("line", "", "release line, MAJOR.MINOR (for example 4.0)")
	scheme := flag.String("scheme", "", "release scheme: product or legacy")
	existing := flag.String("existing", "", "existing release tags, whitespace- or comma-separated")
	flag.Parse()

	parsedLine, err := releaseid.ParseReleaseLine(*line)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	parsedScheme := releaseid.Scheme(*scheme)
	if parsedScheme != releaseid.SchemeProduct && parsedScheme != releaseid.SchemeLegacy {
		fmt.Fprintf(os.Stderr, "scheme must be %s or %s, not %q\n", releaseid.SchemeProduct, releaseid.SchemeLegacy, *scheme)
		os.Exit(1)
	}
	version, err := releaseid.AllocatePatch(parsedLine, parsedScheme, splitTags(*existing))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(version.String())
}

// splitTags accepts what a shell hands over: newlines from a tag listing, commas
// from a hand-written list, and both at once.
func splitTags(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == ',' || r == ' ' || r == '\t' || r == '\r'
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		if trimmed := strings.TrimSpace(field); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// Package auditlog filters Xray access lines before ordinary stdout forwarding.
package auditlog

import (
	"regexp"
	"strings"
)

const maxLineBytes = 8 << 10

type lineKind uint8

const (
	lineOrdinary lineKind = iota
	lineUsage
	lineIgnored
	lineUnmatched
)

type parsedLine struct {
	kind               lineKind
	email, destination string
}

var accessPrefix = regexp.MustCompile(`^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d\.\d{6} from \S+ (?:accepted|rejected) `)

// Email is mandatory for usage parsing so the optional diagnostic cannot
// consume it. Lines without email are still private and become unmatched.
var accessLine = regexp.MustCompile(`^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d\.\d{6} from (\S+) (accepted|rejected) (\S*)(?: \[(\S+) (?:->|>>|==>) (\S+)\])?(?: (.*?))? email: (\S+)$`)

// Every recognized access prefix is private, even if its remaining fields are
// malformed. Only ordinary lines can reach forwarding. The collector owns
// email-to-subject mapping, destination validation and receive-time UTC buckets.
func parseLine(line string) parsedLine {
	if !accessPrefix.MatchString(line) {
		return parsedLine{kind: lineOrdinary}
	}
	if len(line) > maxLineBytes {
		return parsedLine{kind: lineUnmatched}
	}
	m := accessLine.FindStringSubmatch(line)
	if m == nil || m[2] != "accepted" || m[3] == "" || m[7] == "" {
		return parsedLine{kind: lineUnmatched}
	}
	if m[4] == "" && strings.HasPrefix(m[6], "[") {
		return parsedLine{kind: lineUnmatched}
	}
	if strings.HasPrefix(m[5], "psp-deny-") {
		return parsedLine{kind: lineIgnored}
	}
	return parsedLine{kind: lineUsage, destination: m[3], email: m[7]}
}

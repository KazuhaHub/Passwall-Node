//go:build linux

package process

import (
	"strings"
	"testing"
)

func TestParseStartTicksCountsFieldsFromTheLastCommDelimiter(t *testing.T) {
	// A complete, well-formed stat line: 22 fields, with 987654 in the
	// starttime position.
	const stat = "1234 (xray) S 1 1234 1234 0 -1 4194560 1234 0 0 0 10 5 0 0 20 0 12 0 987654"
	startTicks, err := parseStartTicks(stat)
	if err != nil {
		t.Fatal(err)
	}
	if startTicks != 987654 {
		t.Fatalf("startTicks = %d, want 987654", startTicks)
	}
}

// THE CASE THE FIELD-COUNTING RULE EXISTS FOR. The kernel does not escape the
// executable name it puts in the parentheses, so a core whose binary has been
// replaced has a comm of "xray) (deleted" — parentheses AND a space. Splitting
// the whole line on whitespace puts the wrong token in the starttime position
// on exactly the processes an operator is most likely to be investigating.
func TestParseStartTicksHandlesACommContainingSpacesAndParentheses(t *testing.T) {
	const stat = "1234 (xray) (deleted) S 1 1234 1234 0 -1 4194560 1234 0 0 0 10 5 0 0 20 0 12 0 987654"
	startTicks, err := parseStartTicks(stat)
	if err != nil {
		t.Fatal(err)
	}
	if startTicks != 987654 {
		t.Fatalf("startTicks = %d, want 987654", startTicks)
	}
}

func TestParseStartTicksRejectsMalformedStatLines(t *testing.T) {
	valid := "1234 (xray) S 1 1234 1234 0 -1 4194560 1234 0 0 0 10 5 0 0 20 0 12 0 987654"
	cases := []struct {
		name string
		stat string
	}{
		{"no comm delimiter", "1234 xray S 1 2 3"},
		{"nothing after comm", "1234 (xray)"},
		{"truncated before starttime", "1234 (xray) S 1 1234"},
		{"starttime is not a number", strings.Replace(valid, "987654", "abc", 1)},
		{"starttime is zero", strings.Replace(valid, "987654", "0", 1)},
		{"starttime overflows", strings.Replace(valid, "987654", "99999999999999999999999", 1)},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := parseStartTicks(testCase.stat); err == nil {
				t.Fatalf("malformed stat line was accepted: %q", testCase.stat)
			}
		})
	}
}

// A start time of zero means the field was read from the wrong position, not
// that a process started at boot. Accepting it would mint a handle that compares
// equal to any later unreadable read, which is the one comparison the identity
// must never get wrong.
func TestParseStartTicksRefusesRatherThanReturningAnUnverifiableZero(t *testing.T) {
	if _, err := parseStartTicks("1234 (xray) S 1 1234 1234 0 -1 4194560 1234 0 0 0 10 5 0 0 20 0 12 0 0"); err == nil {
		t.Fatal("a zero start time was accepted as an identity")
	}
}

package host

import (
	"sort"
	"strings"

	"github.com/KazuhaHub/passwall-node/protocol"
)

// collectTuning reads the host's congestion-control and queueing state.
//
// READ-ONLY, AND THERE IS NO OTHER MODE. Every value here comes from a fixed
// proc path; nothing in this package writes a sysctl, invokes tc, or offers to
// change an algorithm. The panel derives "BBR is available" from the list below
// and stops there — neither side ever suggests enabling it, because the system
// default congestion control is what NEW sockets receive, which is not evidence
// about the connections a running core has already established.
func (c *collector) collectTuning(collected *sample) {
	var tuning protocol.TuningObservation
	if raw, err := c.readProc("sys/net/ipv4/tcp_available_congestion_control"); err == nil {
		tuning.TCPAvailableCongestionControls = parseTokenList(raw, protocol.MaxCongestionControls, protocol.MaxCongestionControlBytes)
	}
	// The available list and the current default are reported under the same
	// token because they come from one place and answer one question: what this
	// kernel can do. Either being missing makes that question unanswerable.
	if tuning.TCPAvailableCongestionControls == nil {
		collected.markUnavailable(protocol.UnavailableTuningCC)
	}
	if raw, err := c.readProc("sys/net/ipv4/tcp_congestion_control"); err == nil {
		tuning.TCPDefaultCongestionControl = parseToken(raw, protocol.MaxCongestionControlBytes)
	}
	if tuning.TCPDefaultCongestionControl == "" {
		collected.markUnavailable(protocol.UnavailableTuningCC)
	}
	if raw, err := c.readProc("sys/net/core/default_qdisc"); err == nil {
		tuning.DefaultQdisc = parseToken(raw, protocol.MaxCongestionControlBytes)
	}
	if tuning.DefaultQdisc == "" {
		collected.markUnavailable(protocol.UnavailableTuningQdisc)
	}
	// Nothing readable at all: the section is omitted rather than emitted empty,
	// since an empty tuning section would read as a kernel with no algorithms.
	if tuning.TCPAvailableCongestionControls == nil &&
		tuning.TCPDefaultCongestionControl == "" && tuning.DefaultQdisc == "" {
		return
	}
	collected.observation.Tuning = &tuning
}

// parseToken returns a value only if it is a canonical lowercase token.
//
// The value is rendered to an administrator, and the protocol refuses anything
// that is not a token — so an unexpected value is dropped here rather than
// carried to the wire, where it would cost the whole sample.
func parseToken(raw []byte, maxBytes int) string {
	value := strings.TrimSpace(string(raw))
	if value == "" || len(value) > maxBytes || !validLowercaseToken(value) {
		return ""
	}
	return value
}

// parseTokenList reads a whitespace-separated list of algorithm names.
//
// The result is sorted and deduplicated so that an unchanged host encodes to the
// same bytes every round — the panel digests the canonical JSON, and the kernel
// does not promise a stable order. Entries that are not tokens are dropped
// rather than failing the section: this is informational, and losing the list
// entirely would cost the operator more than losing one unparseable name.
func parseTokenList(raw []byte, maxEntries, maxBytes int) []string {
	seen := map[string]struct{}{}
	tokens := make([]string, 0, maxEntries)
	for _, field := range strings.Fields(string(raw)) {
		if len(tokens) >= maxEntries {
			break
		}
		if len(field) > maxBytes || !validLowercaseToken(field) {
			continue
		}
		if _, exists := seen[field]; exists {
			continue
		}
		seen[field] = struct{}{}
		tokens = append(tokens, field)
	}
	if len(tokens) == 0 {
		return nil
	}
	sort.Strings(tokens)
	return tokens
}

// validLowercaseToken mirrors the protocol's own token rule.
func validLowercaseToken(value string) bool {
	if value == "" || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

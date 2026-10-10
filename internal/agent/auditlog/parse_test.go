package auditlog

import (
	"strings"
	"testing"
)

func TestAccessLineClassificationNeverForwardsConnectionDetails(t *testing.T) {
	const prefix = "2026/10/10 11:00:01.123456 from 192.0.2.44:1234 "
	for _, tc := range []struct {
		name, line, destination, email string
		kind                           lineKind
	}{
		{"direct", prefix + "accepted tcp:www.example.com:443 [vless >> direct] email: psp-u61-row2@example.invalid", "tcp:www.example.com:443", "psp-u61-row2@example.invalid", lineUsage},
		{"observe", prefix + "accepted tcp:www.example.com:443 [vless -> psp-watch-p9] email: user@example.invalid", "tcp:www.example.com:443", "user@example.invalid", lineUsage},
		{"trial", prefix + "accepted udp:video.example.com:443 [vless -> psp-watch-g9] email: user@example.invalid", "udp:video.example.com:443", "user@example.invalid", lineUsage},
		{"forced", prefix + "accepted tcp:www.example.com:443 [vless ==> direct] email: user@example.invalid", "tcp:www.example.com:443", "user@example.invalid", lineUsage},
		{"IPv6", prefix + "accepted tcp:[2001:db8::1]:443 [vless >> direct] email: user@example.invalid", "tcp:[2001:db8::1]:443", "user@example.invalid", lineUsage},
		{"without tags", prefix + "accepted tcp:example.com:443 email: user@example.invalid", "tcp:example.com:443", "user@example.invalid", lineUsage},
		{"with diagnostic", prefix + "accepted tcp:example.com:443 [vless -> direct] diagnostic detail email: user@example.invalid", "tcp:example.com:443", "user@example.invalid", lineUsage},
		{"deny accepted", prefix + "accepted tcp:example.com:443 [vless -> psp-deny-p9] email: user@example.invalid", "", "", lineIgnored},
		{"deny whitelist", prefix + "accepted tcp:example.com:443 [vless -> psp-deny-g9] email: user@example.invalid", "", "", lineIgnored},
		{"rejected", prefix + "rejected tcp:example.com:443 [vless -> direct] email: user@example.invalid", "", "", lineUnmatched},
		{"no email", prefix + "accepted tcp:example.com:443 [vless -> direct]", "", "", lineUnmatched},
		{"malformed private line", prefix + "accepted private-client-credential", "", "", lineUnmatched},
		{"malformed deny tag", prefix + "accepted tcp:example.com:443 [vless -> psp-deny-p9 broken] email: user@example.invalid", "", "", lineUnmatched},
		{"truncated private line", prefix + "accepted " + strings.Repeat("x", 8192), "", "", lineUnmatched},
		{"ordinary warning", "2026/10/10 11:00:01.123456 [Warning] core: ordinary failure", "", "", lineOrdinary},
		{"embedded private example", "warning: " + prefix + "accepted tcp:example.com:443", "", "", lineOrdinary},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseLine(tc.line)
			if got.kind != tc.kind || got.destination != tc.destination || got.email != tc.email {
				t.Fatalf("classification=%+v want kind=%v destination=%q email=%q", got, tc.kind, tc.destination, tc.email)
			}
		})
	}
}

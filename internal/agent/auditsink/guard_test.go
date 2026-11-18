package auditsink

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func guardPlan() GuardPlan {
	allow := GuardRule{Allow: true, Sets: []GuardSet{{Key: "src_a", Prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}}}
	deny := GuardRule{Sets: []GuardSet{
		{Key: "src_b", Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}},
		{Key: "src_c", Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/25"), netip.MustParsePrefix("2001:db8::/32")}},
	}}
	return GuardPlan{
		"guard-allow-a": allow, "psp-guard-allow-a": allow,
		"guard-deny-41c10ef944c3": deny, "psp-guard-deny-41c10ef944c3": deny,
	}
}

func postGuard(sink *Sink, token, body string) int {
	request := httptest.NewRequest(http.MethodPost, GuardPath, strings.NewReader(body))
	request.Header.Set(HeaderName, token)
	recorder := httptest.NewRecorder()
	sink.serveHTTP(recorder, request)
	return recorder.Code
}

func guardEventJSON(source, inbound, outbound, rule string) string {
	body := `{"email":"u5@x","source":"` + source + `","destination":"tcp:x:1","inboundTag":"` + inbound + `","outboundTag":"` + outbound + `"`
	if rule != "" {
		body += `,"ruleTag":"` + rule + `"`
	}
	return body + `}`
}

func TestGuardRefusalsAreAggregatedPerSetListenerAndSource(t *testing.T) {
	sink := newTestSink(t, nil)
	sink.SetGuard(guardPlan())
	for i := 0; i < 3; i++ {
		if code := postGuard(sink, testToken, guardEventJSON("192.0.2.9:5555", "psp-lst_1", "psp-guard-allow-a", "")); code != http.StatusNoContent {
			t.Fatalf("status %d", code)
		}
	}
	// The same source on another listener, and via the rule tag alone, are separate.
	postGuard(sink, testToken, guardEventJSON("192.0.2.9:6000", "psp-lst_2", "other", "guard-allow-a"))
	// IPv6 and a mapped address are canonical.
	postGuard(sink, testToken, guardEventJSON("[2001:db8::7]:1", "psp-lst_1", "psp-guard-allow-a", ""))
	postGuard(sink, testToken, guardEventJSON("[::ffff:192.0.2.9]:1", "psp-lst_1", "psp-guard-allow-a", ""))

	hits := sink.GuardHits()
	if len(hits) != 3 {
		t.Fatalf("hits = %+v", hits)
	}
	counts := map[string]int64{}
	for _, hit := range hits {
		counts[string(hit.Listener)+"/"+hit.SourceIP] = hit.Count
		if hit.Set != "src_a" || hit.LastSeenMS != fixedNow.UnixMilli() {
			t.Fatalf("hit = %+v", hit)
		}
	}
	if counts["lst_1/192.0.2.9"] != 4 || counts["lst_2/192.0.2.9"] != 1 || counts["lst_1/2001:db8::7"] != 1 {
		t.Fatalf("counts = %v", counts)
	}
	if err := protocol.ValidateSourceGuardHits(hits); err != nil {
		t.Fatalf("hits are not a valid report field: %v", err)
	}
	// Reading does not clear: the aggregate is reported with every full report.
	if again := sink.GuardHits(); len(again) != 3 {
		t.Fatalf("second read = %+v", again)
	}
}

func TestDenyRefusalNamesEverySetThatContainsTheSource(t *testing.T) {
	sink := newTestSink(t, nil)
	sink.SetGuard(guardPlan())
	postGuard(sink, testToken, guardEventJSON("198.51.100.5:1", "psp-lst_1", "psp-guard-deny-41c10ef944c3", ""))
	postGuard(sink, testToken, guardEventJSON("198.51.100.200:1", "psp-lst_1", "psp-guard-deny-41c10ef944c3", ""))
	sets := map[protocol.SourceSetKey]int64{}
	for _, hit := range sink.GuardHits() {
		sets[hit.Set] += hit.Count
	}
	// .5 is in b and c; .200 is in b only.
	if len(sets) != 2 || sets["src_b"] != 2 || sets["src_c"] != 1 {
		t.Fatalf("sets = %v", sets)
	}
	// A source no set contains matches nothing, and is counted unmatched.
	postGuard(sink, testToken, guardEventJSON("192.0.2.1:1", "psp-lst_1", "psp-guard-deny-41c10ef944c3", ""))
	if len(sink.GuardHits()) != 3 {
		t.Fatalf("hits = %+v", sink.GuardHits())
	}
}

func TestGuardEventsThatDoNotResolveAreUnmatched(t *testing.T) {
	sink := newTestSink(t, nil)
	sink.SetGuard(guardPlan())
	for _, body := range []string{
		guardEventJSON("192.0.2.9:1", "psp-lst_1", "psp-guard-unknown", ""),
		guardEventJSON("not-an-address", "psp-lst_1", "psp-guard-allow-a", ""),
		guardEventJSON("192.0.2.9:1", "transit-fwd_1", "psp-guard-allow-a", ""),
		guardEventJSON("192.0.2.9:1", "", "psp-guard-allow-a", ""),
	} {
		if code := postGuard(sink, testToken, body); code != http.StatusNoContent {
			t.Fatalf("status %d for %s", code, body)
		}
	}
	if code := postGuard(sink, testToken, "{"); code != http.StatusBadRequest {
		t.Fatalf("malformed body: status %d", code)
	}
	if hits := sink.GuardHits(); len(hits) != 0 {
		t.Fatalf("hits = %+v", hits)
	}
	if taken := sink.Take(); taken.Unmatched != 5 {
		t.Fatalf("unmatched = %d", taken.Unmatched)
	}
}

func TestGuardPathNeedsTheToken(t *testing.T) {
	sink := newTestSink(t, nil)
	sink.SetGuard(guardPlan())
	if code := postGuard(sink, "wrong", guardEventJSON("192.0.2.9:1", "psp-lst_1", "psp-guard-allow-a", "")); code != http.StatusUnauthorized {
		t.Fatalf("status %d", code)
	}
	if len(sink.GuardHits()) != 0 {
		t.Fatal("an unauthorized event was recorded")
	}
}

func TestStagedGuardPlanIsConsultedUntilConfirmedOrDiscarded(t *testing.T) {
	sink := newTestSink(t, nil)
	sink.StageGuard(guardPlan())
	postGuard(sink, testToken, guardEventJSON("192.0.2.9:1", "psp-lst_1", "psp-guard-allow-a", ""))
	if len(sink.GuardHits()) != 1 {
		t.Fatal("a staged plan was not used")
	}
	sink.DiscardStaged()
	postGuard(sink, testToken, guardEventJSON("192.0.2.10:1", "psp-lst_1", "psp-guard-allow-a", ""))
	if len(sink.GuardHits()) != 1 {
		t.Fatal("a discarded plan was still used")
	}
}

func TestGuardTableIsBoundedAndEvictsTheOldest(t *testing.T) {
	now := fixedNow
	sink := newTestSink(t, func(o *Options) { o.Now = func() time.Time { return now } })
	sink.SetGuard(guardPlan())
	// The first address is the oldest; one more than the bound pushes it out.
	for i := 0; i <= MaxGuardHits; i++ {
		now = fixedNow.Add(time.Duration(i) * time.Second)
		source := netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)}).String()
		postGuard(sink, testToken, guardEventJSON(source+":1", "psp-lst_1", "psp-guard-allow-a", ""))
	}
	hits := sink.GuardHits()
	if len(hits) != MaxGuardHits {
		t.Fatalf("%d entries, want %d", len(hits), MaxGuardHits)
	}
	for _, hit := range hits {
		if hit.SourceIP == "192.0.0.0" {
			t.Fatal("the oldest entry survived")
		}
	}
	if hits[0].SourceIP != "192.0.1.0" { // i = 256, the newest, first
		t.Fatalf("newest first expected, got %s", hits[0].SourceIP)
	}
	// An existing key counts without evicting anything.
	now = now.Add(time.Second)
	postGuard(sink, testToken, guardEventJSON("192.0.1.0:1", "psp-lst_1", "psp-guard-allow-a", ""))
	if got := sink.GuardHits(); len(got) != MaxGuardHits || got[0].Count != 2 {
		t.Fatalf("entries = %d, first = %+v", len(got), got[0])
	}
}

func TestGuardEntriesAgeOut(t *testing.T) {
	now := fixedNow
	sink := newTestSink(t, func(o *Options) { o.Now = func() time.Time { return now } })
	sink.SetGuard(guardPlan())
	postGuard(sink, testToken, guardEventJSON("192.0.2.9:1", "psp-lst_1", "psp-guard-allow-a", ""))
	now = now.Add(GuardHitMaxAge - time.Minute)
	if len(sink.GuardHits()) != 1 {
		t.Fatal("entry expired early")
	}
	now = now.Add(2 * time.Minute)
	if hits := sink.GuardHits(); len(hits) != 0 {
		t.Fatalf("entry survived its age: %+v", hits)
	}
}

// While a deployment is rolling out the old core is still running: its events
// are read in the deployed plan first, and only a tag the deployed plan does not
// know falls back to the staged one. The tags are content, so a tag found in
// either plan names the same combination.
func TestDeployedGuardPlanIsConsultedBeforeTheStagedOne(t *testing.T) {
	sink := newTestSink(t, nil)
	prefixes := func(cidr string) []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix(cidr)} }
	oldRule := GuardRule{Sets: []GuardSet{{Key: "src_b", Prefixes: prefixes("198.51.100.0/24")}}}
	newRule := GuardRule{Sets: []GuardSet{{Key: "src_b", Prefixes: prefixes("192.0.2.0/24")}}}
	onlyNew := GuardRule{Allow: true, Sets: []GuardSet{{Key: "src_n", Prefixes: prefixes("203.0.113.0/24")}}}
	sink.SetGuard(GuardPlan{"guard-deny-788671d7f16c": oldRule, "psp-guard-deny-788671d7f16c": oldRule})
	sink.StageGuard(GuardPlan{
		"guard-deny-788671d7f16c": newRule, "psp-guard-deny-788671d7f16c": newRule,
		"psp-guard-allow-n": onlyNew,
	})
	// The old core refused 198.51.100.7 by the old set's range.
	postGuard(sink, testToken, guardEventJSON("198.51.100.7:1", "psp-lst_1", "psp-guard-deny-788671d7f16c", ""))
	// A rule only the new plan has is still attributed.
	postGuard(sink, testToken, guardEventJSON("192.0.2.77:1", "psp-lst_1", "psp-guard-allow-n", ""))
	hits := sink.GuardHits()
	got := map[protocol.SourceSetKey]string{}
	for _, hit := range hits {
		got[hit.Set] = hit.SourceIP
	}
	if len(hits) != 2 || got["src_b"] != "198.51.100.7" || got["src_n"] != "192.0.2.77" {
		t.Fatalf("hits = %+v", hits)
	}
}

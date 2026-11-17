package auditsink

import (
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// usageEvent is what Xray posts for a connection the catch-all rule took. Its
// source is deliberately a value that is not an address, and of a type a string
// field could not hold: the receiver must never have read it.
func usageBody(email, destination string) string {
	return `{"email":` + quote(email) + `,"source":{"not":"an address"},"destination":` + quote(destination) +
		`,"originalTarget":"tcp:x:1","routeTarget":"tcp:x:1","outboundTag":"direct","ts":1763029230}`
}

func quote(value string) string { return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"` }

func (s *Sink) postTo(t *testing.T, path, token, body string) int {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "http://audit"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("X-PSP-Audit", token)
	}
	response, err := s.client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	return response.StatusCode
}

func (s *Sink) use(t *testing.T, body string) {
	t.Helper()
	if status := s.postTo(t, UsagePath, testToken, body); status != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", status)
	}
}

func TestUsageConstantsAreThePlansNumbers(t *testing.T) {
	if UsagePath != "/usage" || DefaultMaxUsageKeys != 50000 {
		t.Fatalf("UsagePath = %q, DefaultMaxUsageKeys = %d", UsagePath, DefaultMaxUsageKeys)
	}
}

func TestUsageIsCountedPerHourSubjectAndSite(t *testing.T) {
	sink := startTestSink(t, nil)
	sink.use(t, usageBody("u5@x", "www.example.com:443"))
	sink.use(t, usageBody("u5@x", "cdn.example.com:80"))
	sink.use(t, usageBody("u5@x", "example.com:443"))
	sink.use(t, usageBody("u5@x", "other.example:443"))
	sink.use(t, usageBody("u6@x", "www.example.com:443"))
	taken := sink.Take()
	want := []protocol.AuditUsage{
		{Hour: fixedHour, Subject: "usr_5", Site: "example.com", Count: 3},
		{Hour: fixedHour, Subject: "usr_5", Site: "other.example", Count: 1},
		{Hour: fixedHour, Subject: "usr_6", Site: "example.com", Count: 1},
	}
	if !reflect.DeepEqual(taken.Usage, want) {
		t.Fatalf("usage = %+v, want %+v", taken.Usage, want)
	}
	if len(taken.Hits) != 0 || taken.Unmatched != 0 || taken.DroppedUsage != 0 {
		t.Fatalf("taken = %+v, want only usage rows", taken)
	}
	for _, row := range taken.Usage {
		if err := protocol.ValidateAuditUsage(row); err != nil {
			t.Fatalf("row %+v does not validate: %v", row, err)
		}
	}
}

func TestUsageSiteIsTheRegistrableDomainInTheSpellingOfTheTrialRows(t *testing.T) {
	tests := []struct{ destination, site string }{
		{"www.shop.example.co.uk:443", "example.co.uk"},
		{"EXAMPLE.COM:443", "example.com"},
		{"WWW.Example.COM.:443", "example.com"},
		{"www.bücher.example:443", "xn--bcher-kva.example"},
		{"BÜCHER.example.:80", "xn--bcher-kva.example"},
		{"203.0.113.5:80", protocol.AuditSiteIP},
		{"[2001:DB8::1]:443", protocol.AuditSiteIP},
		{"[::ffff:203.0.113.5]:80", protocol.AuditSiteIP},
		{"github.io:443", "github.io"},
		{"localhost:25", "localhost"},
		{"a.b.c.d.example.org:8443", "example.org"},
	}
	for _, test := range tests {
		t.Run(test.destination, func(t *testing.T) {
			sink := startTestSink(t, nil)
			sink.use(t, usageBody("u5@x", test.destination))
			taken := sink.Take()
			if len(taken.Usage) != 1 || taken.Usage[0].Site != test.site || taken.Unmatched != 0 {
				t.Fatalf("taken = %+v, want site %q", taken, test.site)
			}
			// The same fold the trial rows use, so a site means one thing.
			host, _, _ := splitDestination(test.destination)
			if registrable(host) != test.site {
				t.Fatalf("registrable(%q) = %q", host, registrable(host))
			}
			if err := protocol.ValidateAuditUsage(taken.Usage[0]); err != nil {
				t.Fatalf("row does not validate: %v", err)
			}
		})
	}
}

// An address is never kept, in any form, and neither is the port.
func TestUsageNeverKeepsAnAddressOrAPort(t *testing.T) {
	sink := startTestSink(t, nil)
	sink.use(t, usageBody("u5@x", "198.51.100.77:4433"))
	sink.use(t, usageBody("u5@x", "[2001:db8::77]:4433"))
	taken := sink.Take()
	if len(taken.Usage) != 1 || taken.Usage[0].Site != "(ip)" || taken.Usage[0].Count != 2 {
		t.Fatalf("usage = %+v", taken.Usage)
	}
	if strings.Contains(strings.ToLower(strings.Join([]string{string(taken.Usage[0].Subject), taken.Usage[0].Site}, " ")), "198.51") {
		t.Fatal("an address was kept")
	}
}

func TestUsageEventsThatCannotBeAttributedAreUnmatched(t *testing.T) {
	sink := startTestSink(t, nil)
	bodies := map[string]string{
		"unknown email": usageBody("nobody@x", "a.example:443"),
		"empty email":   usageBody("", "a.example:443"),
		"no port":       usageBody("u5@x", "a.example"),
		"port zero":     usageBody("u5@x", "a.example:0"),
		"empty host":    usageBody("u5@x", ":443"),
		"zone":          usageBody("u5@x", "[fe80::1%eth0]:80"),
		"not json":      `{"email":`,
		"empty object":  `{}`,
		"numeric host":  usageBody("u5@x", "1.2.3:80"),
	}
	for name, body := range bodies {
		if status := sink.postTo(t, UsagePath, testToken, body); status != http.StatusNoContent && status != http.StatusBadRequest {
			t.Errorf("%s: status = %d", name, status)
		}
	}
	taken := sink.Take()
	if len(taken.Usage) != 0 || taken.Unmatched != uint64(len(bodies)) {
		t.Fatalf("taken = %+v, want %d unmatched and no rows", taken, len(bodies))
	}
}

func TestUsageNeedsTheHeaderAndOnlyPOST(t *testing.T) {
	sink := startTestSink(t, nil)
	if status := sink.postTo(t, UsagePath, "", usageBody("u5@x", "a.example:443")); status != http.StatusUnauthorized {
		t.Fatalf("no header: %d", status)
	}
	if status := sink.postTo(t, UsagePath, "wrong", usageBody("u5@x", "a.example:443")); status != http.StatusUnauthorized {
		t.Fatalf("wrong header: %d", status)
	}
	request, _ := http.NewRequest(http.MethodGet, "http://audit"+UsagePath, nil)
	request.Header.Set("X-PSP-Audit", testToken)
	response, err := sink.client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", response.StatusCode)
	}
	big := `{"email":"u5@x","destination":"a.example:443","pad":"` + strings.Repeat("x", 8<<10) + `"}`
	if status := sink.postTo(t, UsagePath, testToken, big); status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized: %d", status)
	}
	taken := sink.Take()
	// Two refused, one body too large.
	if len(taken.Usage) != 0 || taken.Unmatched != 3 || sink.Stats().Unauthorized != 2 {
		t.Fatalf("taken = %+v, unauthorized = %d", taken, sink.Stats().Unauthorized)
	}
}

// The two paths do not feed each other: a hit event is not usage, and a usage
// event is not a hit, whatever outbound it names.
func TestHitAndUsagePathsAreSeparate(t *testing.T) {
	sink := startTestSink(t, nil)
	sink.hit(t, event("u5@x", "a.example:443", "psp-deny-p1"))
	sink.use(t, usageBody("u5@x", "a.example:443"))
	// A usage event that names a deny outbound is still only usage.
	sink.use(t, event("u5@x", "b.example:443", "psp-deny-p1"))
	// A hit event naming direct is not a hit.
	sink.hit(t, event("u5@x", "c.example:443", "direct"))
	taken := sink.Take()
	if len(taken.Hits) != 1 || taken.Hits[0].Dest != "a.example" {
		t.Fatalf("hits = %+v", taken.Hits)
	}
	if len(taken.Usage) != 2 || taken.Unmatched != 1 {
		t.Fatalf("usage = %+v, unmatched = %d", taken.Usage, taken.Unmatched)
	}
}

// Usage is attributed against the roster alone: it names no rule, so a rule that
// is not deployed has no bearing, and a staged roster counts like a deployed one.
func TestUsageIsAttributedAgainstTheStagedAndDeployedRosters(t *testing.T) {
	sink := startTestSink(t, nil)
	sink.SetRoster(map[string]protocol.SubjectKey{"u5@x": "usr_5"}, nil, Egress{})
	sink.use(t, usageBody("u5@x", "a.example:443"))
	sink.use(t, usageBody("u9@x", "a.example:443"))
	sink.StageRoster(map[string]protocol.SubjectKey{"u9@x": "usr_9"}, nil, Egress{})
	sink.use(t, usageBody("u9@x", "a.example:443"))
	sink.DiscardStaged()
	sink.use(t, usageBody("u9@x", "a.example:443"))
	taken := sink.Take()
	if len(taken.Usage) != 2 || taken.Unmatched != 2 {
		t.Fatalf("taken = %+v, want usr_5 and usr_9 rows and two unmatched", taken)
	}
}

func TestUsageIsBucketedByTheNodesReceiveHour(t *testing.T) {
	now := fixedNow
	sink := startTestSink(t, func(o *Options) { o.Now = func() time.Time { return now } })
	sink.use(t, usageBody("u5@x", "a.example:443"))
	now = now.Add(time.Hour)
	sink.use(t, usageBody("u5@x", "a.example:443"))
	taken := sink.Take()
	if len(taken.Usage) != 2 || taken.Usage[0].Hour != fixedHour || taken.Usage[1].Hour != fixedHour+protocol.AuditHourMS {
		t.Fatalf("usage = %+v, want two hours, oldest first", taken.Usage)
	}
}

func TestAFullUsageTableDropsNewKeysAndCountsThemButKeepsCounting(t *testing.T) {
	sink := startTestSink(t, func(o *Options) { o.MaxUsageKeys = 2 })
	sink.use(t, usageBody("u5@x", "a.example:443"))
	sink.use(t, usageBody("u5@x", "b.example:443"))
	sink.use(t, usageBody("u5@x", "c.example:443")) // a new key: dropped
	sink.use(t, usageBody("u5@x", "c.example:443")) // dropped again
	sink.use(t, usageBody("u5@x", "a.example:443")) // an existing key still counts
	taken := sink.Take()
	if len(taken.Usage) != 2 || taken.DroppedUsage != 2 || taken.Unmatched != 0 {
		t.Fatalf("taken = %+v", taken)
	}
	if taken.Usage[0].Site != "a.example" || taken.Usage[0].Count != 2 {
		t.Fatalf("usage = %+v", taken.Usage)
	}
	// The counter restarts with the take.
	if again := sink.Take(); again.DroppedUsage != 0 {
		t.Fatalf("DroppedUsage did not restart: %+v", again)
	}
}

// Usage has a table of its own: it must not take the room a real block needs,
// nor the other way round.
func TestUsageAndHitTablesDoNotCrowdEachOtherOut(t *testing.T) {
	sink := startTestSink(t, func(o *Options) { o.MaxUsageKeys = 1; o.MaxHitKeys = 1 })
	sink.use(t, usageBody("u5@x", "a.example:443"))
	sink.hit(t, event("u5@x", "a.example:443", "psp-deny-p1"))
	taken := sink.Take()
	if len(taken.Usage) != 1 || len(taken.Hits) != 1 || taken.DroppedUsage != 0 || taken.DroppedHits != 0 {
		t.Fatalf("taken = %+v", taken)
	}
}

func TestTakeAndReturnCarryUsage(t *testing.T) {
	sink := startTestSink(t, nil)
	sink.use(t, usageBody("u5@x", "a.example:443"))
	sink.use(t, usageBody("u5@x", "b.example:443"))
	first := sink.Take()
	if len(first.Usage) != 2 {
		t.Fatalf("first = %+v", first)
	}
	if empty := sink.Take(); len(empty.Usage) != 0 {
		t.Fatalf("Take did not empty the table: %+v", empty)
	}
	// A new event for the same key arrives while the rows are out, then they go back.
	sink.use(t, usageBody("u5@x", "a.example:443"))
	sink.Return(Taken{Usage: first.Usage, DroppedUsage: 4, Unmatched: 1})
	second := sink.Take()
	if len(second.Usage) != 2 || second.DroppedUsage != 4 || second.Unmatched != 1 {
		t.Fatalf("second = %+v", second)
	}
	if second.Usage[0].Site != "a.example" || second.Usage[0].Count != 2 {
		t.Fatalf("restored count = %+v, want 2", second.Usage[0])
	}
}

func TestReturnIntoAFullUsageTableCountsTheLostEvents(t *testing.T) {
	sink := startTestSink(t, func(o *Options) { o.MaxUsageKeys = 1 })
	sink.use(t, usageBody("u5@x", "a.example:443"))
	sink.use(t, usageBody("u5@x", "a.example:443"))
	taken := sink.Take()
	sink.use(t, usageBody("u5@x", "b.example:443")) // fills the table
	sink.Return(Taken{Usage: taken.Usage})
	again := sink.Take()
	if len(again.Usage) != 1 || again.DroppedUsage != 2 {
		t.Fatalf("again = %+v, want the restored row's two events counted as dropped", again)
	}
}

func TestUsageCountSaturatesInsteadOfWrapping(t *testing.T) {
	sink := startTestSink(t, nil)
	row := protocol.AuditUsage{Hour: fixedHour, Subject: "usr_5", Site: "a.example", Count: ^uint32(0)}
	sink.Return(Taken{Usage: []protocol.AuditUsage{row}})
	sink.use(t, usageBody("u5@x", "a.example:443"))
	if taken := sink.Take(); len(taken.Usage) != 1 || taken.Usage[0].Count != ^uint32(0) {
		t.Fatalf("usage = %+v", taken.Usage)
	}
}

func TestConcurrentUsageIsAllCounted(t *testing.T) {
	sink := startTestSink(t, nil)
	const workers, each = 8, 50
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				sink.use(t, usageBody("u5@x", "www.example.com:443"))
			}
		}()
	}
	wg.Wait()
	taken := sink.Take()
	if len(taken.Usage) != 1 || taken.Usage[0].Count != workers*each || taken.Unmatched != 0 {
		t.Fatalf("taken = %+v", taken)
	}
}

// The usage event type reads exactly the email and the destination: nothing
// else of the event, the source address least of all, is a field.
func TestUsageEventDecodesOnlyEmailAndDestination(t *testing.T) {
	typ := reflect.TypeOf(usageEvent{})
	var fields []string
	for i := 0; i < typ.NumField(); i++ {
		fields = append(fields, typ.Field(i).Tag.Get("json"))
	}
	if !reflect.DeepEqual(fields, []string{"email", "destination"}) {
		t.Fatalf("the usage event decodes %v", fields)
	}
}

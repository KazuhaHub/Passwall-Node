package auditsink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/lifecycle"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

const testToken = "test-audit-token"

// fixedNow is 2026-11-13 10:20:30.5 UTC.
var fixedNow = time.Date(2026, 11, 13, 10, 20, 30, 500_000_000, time.UTC)

var fixedHour = time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC).UnixMilli()

// shortDir is a temporary directory with a short name: a unix socket path is
// limited to about 100 bytes, which a test's own directory name can exhaust.
func shortDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "as")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

func newTestSink(t *testing.T, mutate func(*Options)) *Sink {
	t.Helper()
	options := Options{
		Path:  filepath.Join(shortDir(t), "runtime", "audit.sock"),
		Token: testToken,
		Now:   func() time.Time { return fixedNow },
	}
	if mutate != nil {
		mutate(&options)
	}
	sink, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	sink.SetRoster(map[string]protocol.SubjectKey{
		"u5@x": "usr_5", "u6@x": "usr_6",
	}, []string{"p1", "p2", "s1", "g9"})
	return sink
}

func startTestSink(t *testing.T, mutate func(*Options)) *Sink {
	t.Helper()
	sink := newTestSink(t, mutate)
	if err := sink.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sink.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after cancellation")
		}
	})
	return sink
}

func (s *Sink) client() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", s.path)
		}},
	}
}

// event is what Xray posts for one hit.
func event(email, destination, outbound string) string {
	return fmt.Sprintf(`{"email":%q,"source":"203.0.113.77:51234","destination":%q,"originalTarget":"tcp:x:1","routeTarget":"tcp:x:1","outboundTag":%q,"ts":1763029230}`,
		email, destination, outbound)
}

func (s *Sink) post(t *testing.T, token, body string) int {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "http://audit/hit", strings.NewReader(body))
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

func (s *Sink) hit(t *testing.T, body string) {
	t.Helper()
	if status := s.post(t, testToken, body); status != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", status)
	}
}

func TestListenCreatesTheRuntimeDirectoryOnAFreshDataDir(t *testing.T) {
	t.Parallel()
	sink := newTestSink(t, func(o *Options) {
		// Neither the data directory's child nor the runtime directory exists.
		o.Path = filepath.Join(shortDir(t), "data", "runtime", "audit.sock")
	})
	if err := sink.Listen(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	directory, err := os.Stat(filepath.Dir(sink.path))
	if err != nil {
		t.Fatal(err)
	}
	if directory.Mode().Perm() != 0o700 {
		t.Fatalf("runtime directory mode = %v, want 0700", directory.Mode().Perm())
	}
	socket, err := os.Stat(sink.path)
	if err != nil {
		t.Fatal(err)
	}
	if socket.Mode()&os.ModeSocket == 0 || socket.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v, want a socket with 0600", socket.Mode())
	}
}

func TestListenReplacesAStaleSocketFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(shortDir(t), "runtime", "audit.sock")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	// What a crashed agent leaves behind: a socket file nobody listens on.
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = stale.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("setup: the stale socket is gone: %v", err)
	}
	sink := newTestSink(t, func(o *Options) { o.Path = path })
	if err := sink.Listen(); err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
}

func TestListenRefusesToDeleteAFileThatIsNotASocket(t *testing.T) {
	t.Parallel()
	path := filepath.Join(shortDir(t), "runtime", "audit.sock")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	sink := newTestSink(t, func(o *Options) { o.Path = path })
	if err := sink.Listen(); err == nil {
		t.Fatal("Listen replaced a regular file")
	}
	if content, _ := os.ReadFile(path); string(content) != "precious" {
		t.Fatal("the regular file was modified")
	}
}

// A unix socket path is limited by sun_path (104 bytes on macOS, 108 on Linux).
// Past 100 bytes there is no listening, and so no capability.
func TestListenRefusesAPathThatIsTooLongForASocket(t *testing.T) {
	t.Parallel()
	long := filepath.Join(shortDir(t), strings.Repeat("d", 90), "audit.sock")
	if len(long) <= MaxSocketPathBytes {
		t.Fatalf("setup: path is only %d bytes", len(long))
	}
	sink := newTestSink(t, func(o *Options) { o.Path = long })
	if err := sink.Listen(); !errors.Is(err, ErrPathTooLong) {
		t.Fatalf("Listen = %v, want ErrPathTooLong", err)
	}
	if _, err := os.Stat(filepath.Dir(long)); err == nil {
		t.Fatal("a directory was created for a path that cannot be listened on")
	}
}

func TestNewRequiresAPathAndAToken(t *testing.T) {
	t.Parallel()
	if _, err := New(Options{Token: "x"}); err == nil {
		t.Fatal("New accepted an empty path")
	}
	if _, err := New(Options{Path: "/tmp/x.sock"}); err == nil {
		t.Fatal("New accepted an empty token")
	}
}

func TestTheHeaderIsRequiredAndAWrongOneIsCounted(t *testing.T) {
	sink := startTestSink(t, nil)
	body := event("u5@x", "blocked.example:443", "psp-deny-p1")
	for name, token := range map[string]string{"missing": "", "wrong": "nope", "prefix": testToken[:5], "longer": testToken + "x"} {
		if status := sink.post(t, token, body); status != http.StatusUnauthorized {
			t.Errorf("%s token: status = %d, want 401", name, status)
		}
	}
	if got := sink.Stats().Unauthorized; got != 4 {
		t.Fatalf("Unauthorized = %d, want 4", got)
	}
	// Refused requests are counted as Unmatched as well, so that the batch
	// carries them to the panel and a node that is losing hits shows it.
	taken := sink.Take()
	if len(taken.Hits) != 0 || taken.Unmatched != 4 {
		t.Fatalf("taken = %+v, want no rows and the 4 refused requests counted as unmatched", taken)
	}
}

func TestOnlyPOSTHitIsServedAndTheBodyIsBounded(t *testing.T) {
	sink := startTestSink(t, nil)
	get, err := http.NewRequest(http.MethodGet, "http://audit/hit", nil)
	if err != nil {
		t.Fatal(err)
	}
	get.Header.Set("X-PSP-Audit", testToken)
	response, err := sink.client().Do(get)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want 405", response.StatusCode)
	}
	other, _ := http.NewRequest(http.MethodPost, "http://audit/other", strings.NewReader("{}"))
	other.Header.Set("X-PSP-Audit", testToken)
	response, err = sink.client().Do(other)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("POST /other status = %d, want 404", response.StatusCode)
	}
	huge := event("u5@x", "blocked.example:443", "psp-deny-p1")
	huge = huge[:len(huge)-1] + `,"pad":"` + strings.Repeat("a", 5000) + `"}`
	if status := sink.post(t, testToken, huge); status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d, want 413", status)
	}
	taken := sink.Take()
	if len(taken.Hits) != 0 || taken.Unmatched != 1 {
		t.Fatalf("taken = %+v, want no rows and the oversized event counted as unmatched", taken)
	}
}

func TestABlockedConnectionBecomesOneHitAndTheSourceIsDropped(t *testing.T) {
	sink := startTestSink(t, nil)
	sink.hit(t, event("u5@x", "Blocked.Example.:443", "psp-deny-p1"))
	sink.hit(t, event("u5@x", "blocked.example:443", "psp-deny-p1"))
	taken := sink.Take()
	want := protocol.AuditHit{
		Hour: fixedHour, RuleID: "p1", Action: protocol.AuditActionBlock, Subject: "usr_5",
		Dest: "blocked.example", Port: 443, Count: 2, FirstMS: fixedNow.UnixMilli(), LastMS: fixedNow.UnixMilli(),
	}
	if len(taken.Hits) != 1 || taken.Hits[0] != want {
		t.Fatalf("hits = %+v, want [%+v]", taken.Hits, want)
	}
	// The source address must not be anywhere a row, a count or an error could
	// carry it.
	encoded, err := json.Marshal(taken)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"203.0.113.77", "51234", "source"} {
		if bytes.Contains(encoded, []byte(leaked)) {
			t.Fatalf("%q appears in the taken batch: %s", leaked, encoded)
		}
	}
	if again := sink.Take(); len(again.Hits) != 0 {
		t.Fatalf("Take did not empty the aggregator: %+v", again)
	}
}

func TestAnObserveHitCarriesTheObserveAction(t *testing.T) {
	sink := startTestSink(t, nil)
	sink.hit(t, event("u6@x", "[2001:db8::1]:8443", "psp-watch-p2"))
	taken := sink.Take()
	if len(taken.Hits) != 1 {
		t.Fatalf("hits = %+v", taken.Hits)
	}
	hit := taken.Hits[0]
	if hit.Action != protocol.AuditActionObserve || hit.RuleID != "p2" || hit.Subject != "usr_6" ||
		hit.Dest != "2001:db8::1" || hit.Port != 8443 {
		t.Fatalf("hit = %+v", hit)
	}
}

func TestSourceRulesAreRecordedLikeAnyOtherRule(t *testing.T) {
	sink := startTestSink(t, nil)
	sink.hit(t, event("u5@x", "198.51.100.9:25", "psp-deny-s1"))
	taken := sink.Take()
	if len(taken.Hits) != 1 || taken.Hits[0].RuleID != "s1" || taken.Hits[0].Dest != "198.51.100.9" {
		t.Fatalf("hits = %+v", taken.Hits)
	}
}

func TestDestinationsAreNormalisedBeforeAggregation(t *testing.T) {
	tests := []struct {
		destination string
		wantDest    string
		wantPort    uint16
		ok          bool
	}{
		{"EXAMPLE.COM:443", "example.com", 443, true},
		{"example.com.:443", "example.com", 443, true},
		{"bücher.example:443", "xn--bcher-kva.example", 443, true},
		{"BÜCHER.example.:80", "xn--bcher-kva.example", 80, true},
		{"[2001:DB8::1]:443", "2001:db8::1", 443, true},
		{"203.0.113.5:80", "203.0.113.5", 80, true},
		{"[::ffff:203.0.113.5]:80", "203.0.113.5", 80, true},
		{"[fe80::1%eth0]:80", "", 0, false},
		{"localhost:25", "localhost", 25, true},
		{"example.com:0", "", 0, false},
		{"example.com:65536", "", 0, false},
		{"example.com:http", "", 0, false},
		{"example.com", "", 0, false},
		{":443", "", 0, false},
		{"exa mple.com:443", "", 0, false},
		{"example..com:443", "", 0, false},
		{"..:443", "", 0, false},
		{"", "", 0, false},
	}
	for _, test := range tests {
		t.Run(test.destination, func(t *testing.T) {
			sink := startTestSink(t, nil)
			sink.hit(t, event("u5@x", test.destination, "psp-deny-p1"))
			taken := sink.Take()
			if !test.ok {
				if len(taken.Hits) != 0 || taken.Unmatched != 1 {
					t.Fatalf("taken = %+v, want one unmatched event and no row", taken)
				}
				return
			}
			if len(taken.Hits) != 1 || taken.Hits[0].Dest != test.wantDest || taken.Hits[0].Port != test.wantPort {
				t.Fatalf("hits = %+v, want %s:%d", taken.Hits, test.wantDest, test.wantPort)
			}
			if err := protocol.ValidateAuditHit(taken.Hits[0]); err != nil {
				t.Fatalf("the aggregated row does not validate: %v", err)
			}
		})
	}
}

func TestEventsThatCannotBeAttributedAreUnmatched(t *testing.T) {
	sink := startTestSink(t, nil)
	for name, body := range map[string]string{
		"unknown email":      event("nobody@x", "a.example:443", "psp-deny-p1"),
		"empty email":        event("", "a.example:443", "psp-deny-p1"),
		"rule not deployed":  event("u5@x", "a.example:443", "psp-deny-p77"),
		"not a hit outbound": event("u5@x", "a.example:443", "direct"),
		"blackhole":          event("u5@x", "a.example:443", "blocked"),
		"empty rule":         event("u5@x", "a.example:443", "psp-deny-"),
		"not json":           `{"email":`,
		"empty object":       `{}`,
	} {
		if status := sink.post(t, testToken, body); status != http.StatusNoContent && status != http.StatusBadRequest {
			t.Errorf("%s: status = %d", name, status)
		}
	}
	taken := sink.Take()
	if len(taken.Hits) != 0 || taken.Unmatched != 8 {
		t.Fatalf("taken = %+v, want 8 unmatched and no rows", taken)
	}
}

func TestTheRosterSnapshotIsReplacedNotMerged(t *testing.T) {
	sink := startTestSink(t, nil)
	sink.SetRoster(map[string]protocol.SubjectKey{"u9@x": "usr_9"}, []string{"p5"})
	sink.hit(t, event("u5@x", "a.example:443", "psp-deny-p1")) // old user, old rule
	sink.hit(t, event("u9@x", "a.example:443", "psp-deny-p5"))
	taken := sink.Take()
	if len(taken.Hits) != 1 || taken.Hits[0].Subject != "usr_9" || taken.Hits[0].RuleID != "p5" || taken.Unmatched != 1 {
		t.Fatalf("taken = %+v", taken)
	}
}

func TestHitsAreBucketedByTheNodesReceiveHourAndKeepFirstAndLast(t *testing.T) {
	var mu sync.Mutex
	current := fixedNow
	sink := startTestSink(t, func(o *Options) {
		o.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return current }
	})
	at := func(value time.Time) { mu.Lock(); current = value; mu.Unlock() }
	body := event("u5@x", "a.example:443", "psp-deny-p1")
	at(fixedNow.Add(-5 * time.Minute)) // 10:15:30.5
	sink.hit(t, body)
	at(fixedNow.Add(20 * time.Minute)) // 10:40:30.5, same hour
	sink.hit(t, body)
	at(fixedNow.Add(40 * time.Minute)) // 11:00:30.5, next hour
	sink.hit(t, body)
	taken := sink.Take()
	if len(taken.Hits) != 2 {
		t.Fatalf("hits = %+v, want two hour buckets", taken.Hits)
	}
	first, second := taken.Hits[0], taken.Hits[1]
	if first.Hour != fixedHour || first.Count != 2 ||
		first.FirstMS != fixedNow.Add(-5*time.Minute).UnixMilli() || first.LastMS != fixedNow.Add(20*time.Minute).UnixMilli() {
		t.Fatalf("first bucket = %+v", first)
	}
	if second.Hour != fixedHour+protocol.AuditHourMS || second.Count != 1 {
		t.Fatalf("second bucket = %+v", second)
	}
}

func TestAFullHitTableDropsNewKeysAndCountsThemButKeepsCounting(t *testing.T) {
	sink := startTestSink(t, func(o *Options) { o.MaxHitKeys = 2 })
	sink.hit(t, event("u5@x", "a.example:443", "psp-deny-p1"))
	sink.hit(t, event("u5@x", "b.example:443", "psp-deny-p1"))
	sink.hit(t, event("u5@x", "c.example:443", "psp-deny-p1")) // third key: dropped
	sink.hit(t, event("u5@x", "c.example:443", "psp-deny-p1")) // dropped again
	sink.hit(t, event("u5@x", "a.example:443", "psp-deny-p1")) // existing key: counted
	taken := sink.Take()
	if len(taken.Hits) != 2 || taken.DroppedHits != 2 || taken.DroppedTrial != 0 || taken.Unmatched != 0 {
		t.Fatalf("taken = %+v, want 2 rows and DroppedHits 2", taken)
	}
	for _, hit := range taken.Hits {
		if hit.Dest == "a.example" && hit.Count != 2 {
			t.Fatalf("the existing key was not incremented: %+v", hit)
		}
	}
}

// A group on trial hits its fallback rule on nearly every connection that is
// outside the list. Those rows are folded and kept apart so that they cannot
// crowd out a real block.
func TestTrialHitsFoldToTheRegistrableDomainWithoutSubjectOrPort(t *testing.T) {
	sink := startTestSink(t, nil)
	sink.hit(t, event("u5@x", "WWW.Shop.Example.co.uk.:443", "psp-watch-g9"))
	sink.hit(t, event("u6@x", "cdn.shop.example.co.uk:8443", "psp-watch-g9"))
	sink.hit(t, event("u6@x", "203.0.113.9:443", "psp-watch-g9"))
	sink.hit(t, event("u6@x", "[2001:db8::2]:443", "psp-watch-g9"))
	sink.hit(t, event("u5@x", "localhost:80", "psp-watch-g9"))
	sink.hit(t, event("u5@x", "foo.github.io:443", "psp-watch-g9"))
	sink.hit(t, event("u5@x", "github.io:443", "psp-watch-g9"))
	taken := sink.Take()
	got := map[string]uint32{}
	for _, hit := range taken.Hits {
		if hit.Subject != "" || hit.Port != 0 || hit.RuleID != "g9" || hit.Action != protocol.AuditActionObserve || hit.Hour != fixedHour {
			t.Fatalf("a trial row keeps per-person data: %+v", hit)
		}
		if err := protocol.ValidateAuditHit(hit); err != nil {
			t.Fatalf("trial row %+v does not validate: %v", hit, err)
		}
		got[hit.Dest] = hit.Count
	}
	want := map[string]uint32{
		"example.co.uk": 2, "(ip)": 2, "localhost": 1, "foo.github.io": 1, "github.io": 1,
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("trial rows = %v, want %v", got, want)
	}
	// Neither the full host nor an address survives anywhere.
	encoded, _ := json.Marshal(taken)
	for _, leaked := range []string{"www.shop", "cdn.shop", "203.0.113.9", "2001:db8", "usr_"} {
		if bytes.Contains(encoded, []byte(leaked)) {
			t.Fatalf("%q survived the fold: %s", leaked, encoded)
		}
	}
}

func TestAnEnforcedGroupBlockIsARealHitAndNotFolded(t *testing.T) {
	sink := startTestSink(t, nil)
	sink.hit(t, event("u5@x", "www.shop.example.com:443", "psp-deny-g9"))
	taken := sink.Take()
	if len(taken.Hits) != 1 {
		t.Fatalf("hits = %+v", taken.Hits)
	}
	hit := taken.Hits[0]
	if hit.Subject != "usr_5" || hit.Port != 443 || hit.Dest != "www.shop.example.com" || hit.Action != protocol.AuditActionBlock {
		t.Fatalf("hit = %+v", hit)
	}
}

func TestTrialAndHitTablesDoNotCrowdEachOtherOut(t *testing.T) {
	sink := startTestSink(t, func(o *Options) { o.MaxHitKeys = 1; o.MaxTrialKeys = 1 })
	sink.hit(t, event("u5@x", "a.trial-one.example:443", "psp-watch-g9"))
	sink.hit(t, event("u5@x", "a.trial-two.example:443", "psp-watch-g9")) // trial table full
	sink.hit(t, event("u5@x", "a.example:443", "psp-deny-p1"))            // still room in the hit table
	sink.hit(t, event("u5@x", "b.example:443", "psp-deny-p1"))            // hit table full
	taken := sink.Take()
	if len(taken.Hits) != 2 || taken.DroppedTrial != 1 || taken.DroppedHits != 1 {
		t.Fatalf("taken = %+v, want 2 rows, DroppedTrial 1 and DroppedHits 1", taken)
	}
}

func TestTakeEmptiesEverythingAndRestoreMergesRowsBack(t *testing.T) {
	sink := startTestSink(t, nil)
	sink.hit(t, event("u5@x", "a.example:443", "psp-deny-p1"))
	sink.hit(t, event("u5@x", "www.t.example:443", "psp-watch-g9"))
	first := sink.Take()
	if len(first.Hits) != 2 {
		t.Fatalf("first take = %+v", first)
	}
	// A new event for the same key arrives while the rows are out, then they go back.
	sink.hit(t, event("u5@x", "a.example:443", "psp-deny-p1"))
	sink.Return(Taken{Hits: first.Hits})
	second := sink.Take()
	if len(second.Hits) != 2 {
		t.Fatalf("second take = %+v", second)
	}
	for _, hit := range second.Hits {
		if hit.Dest == "a.example" && hit.Count != 2 {
			t.Fatalf("restored count = %d, want 2", hit.Count)
		}
		if hit.RuleID == "g9" && (hit.Subject != "" || hit.Dest != "t.example") {
			t.Fatalf("a restored trial row went into the wrong table: %+v", hit)
		}
	}
}

func TestRestoreIntoAFullTableCountsTheLostEvents(t *testing.T) {
	sink := startTestSink(t, func(o *Options) { o.MaxHitKeys = 1 })
	sink.hit(t, event("u5@x", "a.example:443", "psp-deny-p1"))
	taken := sink.Take()
	sink.hit(t, event("u5@x", "b.example:443", "psp-deny-p1")) // fills the table
	sink.Return(Taken{Hits: taken.Hits})
	again := sink.Take()
	if len(again.Hits) != 1 || again.DroppedHits != 1 {
		t.Fatalf("again = %+v, want the restored row's single event counted as dropped", again)
	}
}

func TestConcurrentHitsAreAllCounted(t *testing.T) {
	sink := startTestSink(t, nil)
	const workers, each = 8, 50
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				sink.hit(t, event("u5@x", "a.example:443", "psp-deny-p1"))
			}
		}()
	}
	wg.Wait()
	taken := sink.Take()
	if len(taken.Hits) != 1 || taken.Hits[0].Count != workers*each {
		t.Fatalf("taken = %+v, want one row counting %d", taken, workers*each)
	}
}

// The sink is a lifecycle service: when it can no longer do its job the agent
// has to exit, so that the capability it declared is never silently untrue.
func TestAServeFailureMakesTheLifecycleReturnAnError(t *testing.T) {
	t.Parallel()
	sink := newTestSink(t, nil)
	if err := sink.Listen(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- lifecycle.Run(context.Background(),
			lifecycle.Service{Name: "audit receiver", Run: sink.Serve},
			lifecycle.Service{Name: "idle", Run: func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }},
		)
	}()
	time.Sleep(100 * time.Millisecond)
	// The listener dies underneath the server.
	sink.listener.Close()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "audit receiver") {
			t.Fatalf("lifecycle.Run = %v, want an error naming the audit receiver", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the agent kept running after the receiver failed")
	}
}

func TestServeReturnsCleanlyOnCancellationAndRemovesTheSocket(t *testing.T) {
	t.Parallel()
	sink := newTestSink(t, nil)
	if err := sink.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sink.Serve(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve = %v, want nil or context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
	if _, err := os.Stat(sink.path); !os.IsNotExist(err) {
		t.Fatalf("the socket file is still there: %v", err)
	}
}

func TestServeWithoutListenIsAnError(t *testing.T) {
	t.Parallel()
	sink := newTestSink(t, nil)
	if err := sink.Serve(context.Background()); err == nil {
		t.Fatal("Serve without Listen returned nil")
	}
}

// A candidate roster is staged BEFORE the core that uses it starts, so a hit
// the new core sends at once is attributed; until the deployment is confirmed
// both the old and the new roster are accepted.
func TestAStagedRosterIsAcceptedBesideTheDeployedOneUntilCommittedOrDiscarded(t *testing.T) {
	sink := startTestSink(t, nil)
	newUser := event("u9@x", "a.example:443", "psp-deny-p9")
	oldUser := event("u5@x", "a.example:443", "psp-deny-p1")

	sink.hit(t, newUser) // not staged yet
	if taken := sink.Take(); len(taken.Hits) != 0 || taken.Unmatched != 1 {
		t.Fatalf("before staging: %+v", taken)
	}

	sink.StageRoster(map[string]protocol.SubjectKey{"u9@x": "usr_9"}, []string{"p9"})
	sink.hit(t, newUser)
	sink.hit(t, oldUser) // the union: the deployed roster still counts
	taken := sink.Take()
	if len(taken.Hits) != 2 || taken.Unmatched != 0 {
		t.Fatalf("staged: %+v", taken)
	}

	// A failed deployment goes back to the deployed roster alone.
	sink.DiscardStaged()
	sink.hit(t, newUser)
	sink.hit(t, oldUser)
	if taken := sink.Take(); len(taken.Hits) != 1 || taken.Hits[0].RuleID != "p1" || taken.Unmatched != 1 {
		t.Fatalf("after discard: %+v", taken)
	}

	// A confirmed one replaces it, and the old one no longer counts.
	sink.StageRoster(map[string]protocol.SubjectKey{"u9@x": "usr_9"}, []string{"p9"})
	sink.SetRoster(map[string]protocol.SubjectKey{"u9@x": "usr_9"}, []string{"p9"})
	sink.hit(t, newUser)
	sink.hit(t, oldUser)
	if taken := sink.Take(); len(taken.Hits) != 1 || taken.Hits[0].RuleID != "p9" || taken.Unmatched != 1 {
		t.Fatalf("after commit: %+v", taken)
	}
}

// net/http would recover a handler panic and log it, and the receiver would
// keep running while recording nothing. A panic has to stop the receiver, so
// the agent exits instead of declaring a capability it no longer has.
func TestAHandlerPanicMakesServeReturnAnError(t *testing.T) {
	t.Parallel()
	sink := newTestSink(t, nil)
	sink.beforeRecord = func() { panic("boom") }
	if err := sink.Listen(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- sink.Serve(context.Background()) }()
	time.Sleep(50 * time.Millisecond)
	// The request itself fails; what matters is what Serve does.
	request, _ := http.NewRequest(http.MethodPost, "http://audit/hit", strings.NewReader(event("u5@x", "a.example:443", "psp-deny-p1")))
	request.Header.Set("X-PSP-Audit", testToken)
	if response, err := sink.client().Do(request); err == nil {
		response.Body.Close()
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "panic") {
			t.Fatalf("Serve = %v, want an error that names the panic", err)
		}
		if strings.Contains(err.Error(), "u5@x") {
			t.Fatalf("the error carries event content: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve kept running after a handler panic")
	}
}

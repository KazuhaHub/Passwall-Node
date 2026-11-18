// Package routebudget holds the regression tests of the routed-compile budget:
// the cap is enforced as destination entries are appended, so a compile that
// would pass it is refused before its memory is spent, whatever shape it has.
package routebudget

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/singbox"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/xray"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// heapLimit is what any compile, accepted or refused, may peak at.
const heapLimit = 256 << 20

func listener(id int64) protocol.Listener {
	return protocol.Listener{Key: protocol.NewListenerKey(id), Config: protocol.RawConfig(fmt.Sprintf(
		`{"enabled":true,"listen":"127.0.0.1","port":%d,"protocol":"shadowsocks","settings":"{\"method\":\"2022-blake3-aes-128-gcm\",\"password\":\"AAAAAAAAAAAAAAAAAAAAAA==\",\"network\":\"tcp,udp\"}"}`, 20000+id))}
}

func domains(n int, format string) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf(format, i))
	}
	sort.Strings(out)
	return out
}

type shape struct {
	name      string
	policy    *protocol.DestinationPolicy
	listeners int
	routes    func(listener int) []protocol.RouteRule
	// clients is how many roster clients the rules' subject has: the users of a
	// subject-scoped rule are copied into every segment.
	clients int
}

func (s shape) snapshot() agentcore.Snapshot {
	ss := &protocol.LinkSS{Method: "2022-blake3-aes-128-gcm", Password: "AAAAAAAAAAAAAAAAAAAAAA=="}
	transit := &protocol.Transit{LinksOut: []protocol.LinkOut{{Key: "lnk_8", Address: "127.0.0.1", Port: 9, Protocol: protocol.LinkProtocolSS2022, SS: ss}}}
	var listeners []protocol.Listener
	for l := 1; l <= s.listeners; l++ {
		listeners = append(listeners, listener(int64(l)))
		transit.Routes = append(transit.Routes, protocol.ListenerRoutes{Listener: protocol.NewListenerKey(int64(l)), Rules: s.routes(l)})
	}
	snapshot := agentcore.Snapshot{Now: time.Unix(1, 0), Listeners: listeners, DestinationPolicy: s.policy, Transit: transit}
	for i := 1; i <= s.clients; i++ {
		snapshot.Clients = append(snapshot.Clients, protocol.Client{
			Key: protocol.NewClientKey(int64(i)), Subject: protocol.NewSubjectKey(5), Enabled: true,
			Listeners:   []protocol.ListenerKey{protocol.NewListenerKey(1)},
			Credentials: protocol.Credential{Username: fmt.Sprintf("u%06d@x", i), Password: userKey(i)},
		})
	}
	return snapshot
}

// compileMeasured compiles with a sampler of the heap running and returns the
// peak it saw.
func compileMeasured(engine string, snapshot agentcore.Snapshot) (agentcore.Artifact, error, uint64) {
	runtime.GC()
	var peak atomic.Uint64
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		var m runtime.MemStats
		for {
			select {
			case <-done:
				return
			case <-time.After(5 * time.Millisecond):
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > peak.Load() {
					peak.Store(m.HeapAlloc)
				}
			}
		}
	}()
	var artifact agentcore.Artifact
	var err error
	if engine == "xray" {
		artifact, err = (xray.Compiler{APIListen: "127.0.0.1:1"}).Compile(context.Background(), snapshot)
	} else {
		artifact, err = (singbox.Compiler{APIListen: "127.0.0.1:1", APISecret: "abcdefghijklmnopqrstuvwxyzABCDEF0123"}).Compile(context.Background(), snapshot)
	}
	close(done)
	<-finished
	return artifact, err, peak.Load()
}

func routesOf(count int, withDomain bool) func(int) []protocol.RouteRule {
	return func(l int) []protocol.RouteRule {
		var out []protocol.RouteRule
		for k := 1; k <= count; k++ {
			rule := protocol.RouteRule{ID: fmt.Sprintf("r%d", k), CIDRs: []string{fmt.Sprintf("198.51.100.%d/32", k)}, Exit: "lnk_8"}
			if withDomain {
				rule.Domains = []string{"domain:test"}
			}
			out = append(out, rule)
		}
		return out
	}
}

// Every shape below used to slip under the up-front estimate or to blow up in
// the one engine; each is either refused as a listener (a config object error
// naming the group) or compiled, and neither takes more than heapLimit while it
// does, and an accepted compile stays within the cap.
func TestRoutedCompileMemoryIsBoundedByConstruction(t *testing.T) {
	var manyCIDRs []string
	for i := 0; i < 20000; i++ {
		manyCIDRs = append(manyCIDRs, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
	}
	sort.Strings(manyCIDRs)
	var allowRules []protocol.DestinationRule
	for i := 0; i < 256; i++ {
		allowRules = append(allowRules, protocol.DestinationRule{ID: fmt.Sprintf("p%d", i+1), Action: protocol.RuleAllow, Domains: []string{fmt.Sprintf("domain:h%03d.test", i)}})
	}
	var small []protocol.DestinationRule
	for i := 0; i < 64; i++ {
		small = append(small, protocol.DestinationRule{ID: fmt.Sprintf("p%d", i+1), Action: protocol.RuleBlock, Domains: domains(15, "domain:s"+strconv.Itoa(i)+"-%d.test")})
	}
	onDemand := protocol.ResolveOnDemand
	shapes := []shape{
		// Hostnames-through-addresses: the rule's 50,000 domains are copied, with
		// each route's CIDR, into one rule per route.
		{"hostnames through addresses x 18 routes", &protocol.DestinationPolicy{Resolve: onDemand, Rules: []protocol.DestinationRule{
			{ID: "p1", Action: protocol.RuleAllow, Domains: domains(50000, "domain:host-%05d.example-allowlist.test")}}}, 1, routesOf(18, true), 0},
		{"hostnames through addresses x 40 routes", &protocol.DestinationPolicy{Resolve: onDemand, Rules: []protocol.DestinationRule{
			{ID: "p1", Action: protocol.RuleAllow, Domains: domains(50000, "domain:host-%05d.example-allowlist.test")}}}, 1, routesOf(40, true), 0},
		// Many hostname rules against one route of 20,000 CIDRs.
		{"256 rules x one 20,000-CIDR route", &protocol.DestinationPolicy{Resolve: onDemand, Rules: allowRules}, 1,
			func(int) []protocol.RouteRule {
				return []protocol.RouteRule{{ID: "r1", CIDRs: manyCIDRs, Exit: "lnk_8"}}
			}, 0},
		// Small matchers (under the sharing minimum) copied into every segment.
		{"64 small matchers x 8 routes x 16 groups", &protocol.DestinationPolicy{Rules: small}, 16, routesOf(8, false), 0},
		{"50,000-domain block x 64 routes x 3 groups", &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
			{ID: "p1", Action: protocol.RuleBlock, Domains: domains(50000, "domain:host-%05d.example-blocklist.test")}}}, 3,
			func(l int) []protocol.RouteRule {
				var out []protocol.RouteRule
				for k := 1; k <= 64; k++ {
					out = append(out, protocol.RouteRule{ID: fmt.Sprintf("r%d", k), Ports: strconv.Itoa(1000*l + k), Exit: "lnk_8"})
				}
				return out
			}, 0},
	}
	var sources []string
	for i := 0; i < 60000; i++ {
		sources = append(sources, fmt.Sprintf("10.%d.%d.0/24", i/256%256, i%256))
	}
	sort.Strings(sources)
	domainRoutes := func(int) []protocol.RouteRule {
		var out []protocol.RouteRule
		for k := 1; k <= 64; k++ {
			out = append(out, protocol.RouteRule{ID: fmt.Sprintf("r%d", k), Domains: []string{fmt.Sprintf("domain:r%d.example", k)}, Exit: "lnk_8"})
		}
		return out
	}
	shapes = append(shapes,
		// Lists that are not destinations are copied into every segment too: the
		// source ranges of a rule, the users of a subject, the exempt users.
		shape{"60,000 source ranges x 64 routes", &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
			{ID: "s1", Action: protocol.RuleBlock, SourceCIDRs: sources}}}, 1, domainRoutes, 0},
		shape{"20,000 users of a subject x 64 routes", &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
			{ID: "p1", Action: protocol.RuleBlock, Subjects: []protocol.SubjectKey{"usr_5"}, Ports: "25"}}}, 1, domainRoutes, 20000},
		shape{"20,000 exempt users x 64 routes", &protocol.DestinationPolicy{Exempt: []protocol.SubjectKey{"usr_5"}, Rules: []protocol.DestinationRule{
			{ID: "p1", Action: protocol.RuleBlock, Ports: "25"}}}, 1, domainRoutes, 20000},
	)
	for _, s := range shapes {
		for _, engine := range []string{"sing-box", "xray"} {
			t.Run(s.name+"/"+engine, func(t *testing.T) {
				artifact, err, peak := compileMeasured(engine, s.snapshot())
				t.Logf("%d bytes, peak heap %d MiB, err %v", len(artifact.Config), peak>>20, err)
				if peak > heapLimit {
					t.Fatalf("peak heap %d MiB is over %d MiB", peak>>20, heapLimit>>20)
				}
				if err != nil {
					var objectErr *agentcore.ObjectError
					if !errors.As(err, &objectErr) || objectErr.Stream != protocol.StreamConfig || objectErr.Key == "" {
						t.Fatalf("a refusal must be a config object error naming the listener: %v", err)
					}
				}
			})
		}
	}
}

// A compile well inside the budget is not touched by it.
func TestARoutedCompileInsideTheBudgetIsAccepted(t *testing.T) {
	s := shape{"small", &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleAllow, Domains: []string{"domain:ok.test"}},
		{ID: "p2", Action: protocol.RuleBlock, Domains: domains(100, "domain:b%d.test")},
	}}, 2, routesOf(8, true), 0}
	for _, engine := range []string{"sing-box", "xray"} {
		if _, err, _ := compileMeasured(engine, s.snapshot()); err != nil {
			t.Fatalf("%s: %v", engine, err)
		}
	}
}

// With the cheap estimate switched off, the incremental guard alone refuses
// what must be refused, for every kind of list a routed rule carries (the
// policy's own limits cap how long a destination or source list can be, so those
// shapes are at the maximum, and sing-box, which writes such a list once, takes
// them; users and exempt users are copied everywhere and are refused on both) (and
// charges them all the same way: see core.CountEntries). A refusal by the guard
// says "reached" or "next step"; the estimate says "bring the compile to about".
func TestTheIncrementalGuardAloneRefusesEveryListKind(t *testing.T) {
	agentcore.SkipRoutedEstimate = true
	t.Cleanup(func() { agentcore.SkipRoutedEstimate = false })

	distinct := func(rules, each int, kind string) []protocol.DestinationRule {
		var out []protocol.DestinationRule
		for i := 0; i < rules; i++ {
			rule := protocol.DestinationRule{ID: fmt.Sprintf("p%d", i+1), Action: protocol.RuleBlock, Ports: strconv.Itoa(1000 + i)}
			switch kind {
			case "source":
				rule.ID, rule.Ports = fmt.Sprintf("s%d", i+1), ""
				rule.SourceCIDRs = ipRanges(each, "10.%d.%d.0/24", i)
			case "domain":
				rule.Ports = ""
				rule.Domains = domains(each, "domain:d"+strconv.Itoa(i)+"-%d.example")
			case "cidr":
				rule.Ports = ""
				rule.CIDRs = ipRanges(each, "11.%d.%d.0/24", i)
			}
			out = append(out, rule)
		}
		return out
	}
	var sources []string
	for i := 0; i < 60000; i++ {
		sources = append(sources, fmt.Sprintf("10.%d.%d.0/24", i/256%256, i%256))
	}
	sort.Strings(sources)
	domainRoutes := func(int) []protocol.RouteRule {
		var out []protocol.RouteRule
		for k := 1; k <= 64; k++ {
			out = append(out, protocol.RouteRule{ID: fmt.Sprintf("r%d", k), Domains: []string{fmt.Sprintf("domain:r%d.example", k)}, Exit: "lnk_8"})
		}
		return out
	}
	// Routes that name only a port, so a rule's destination list is copied whole.
	portRoutes := func(int) []protocol.RouteRule {
		var out []protocol.RouteRule
		for k := 1; k <= 64; k++ {
			out = append(out, protocol.RouteRule{ID: fmt.Sprintf("r%d", k), Ports: strconv.Itoa(2000 + k), Exit: "lnk_8"})
		}
		return out
	}
	cases := []struct {
		name  string
		shape shape
		// shared: sing-box writes this list once, as a rule set, so a single
		// copy of it is inside the budget there.
		shared bool
	}{
		{"60,000 source ranges x 64 routes", shape{"", &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
			{ID: "s1", Action: protocol.RuleBlock, SourceCIDRs: sources}}}, 1, domainRoutes, 0}, true},
		{"20,000 users of a subject x 64 routes", shape{"", &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
			{ID: "p1", Action: protocol.RuleBlock, Subjects: []protocol.SubjectKey{"usr_5"}, Ports: "25"}}}, 1, domainRoutes, 20000}, false},
		{"20,000 exempt users x 64 routes", shape{"", &protocol.DestinationPolicy{Exempt: []protocol.SubjectKey{"usr_5"}, Rules: []protocol.DestinationRule{
			{ID: "p1", Action: protocol.RuleBlock, Ports: "25"}}}, 1, domainRoutes, 20000}, false},
		{"15 rules x 4,000 distinct source ranges (the policy maximum)", shape{"", &protocol.DestinationPolicy{Rules: distinct(15, 4000, "source")}, 1, domainRoutes, 0}, true},
		{"12 rules x 4,000 distinct domains", shape{"", &protocol.DestinationPolicy{Rules: distinct(12, 4000, "domain")}, 1, portRoutes, 0}, true},
		{"5 rules x 4,000 distinct CIDRs (the policy maximum)", shape{"", &protocol.DestinationPolicy{Rules: distinct(5, 4000, "cidr")}, 1, portRoutes, 0}, true},
	}
	for _, c := range cases {
		for _, engine := range []string{"sing-box", "xray"} {
			t.Run(c.name+"/"+engine, func(t *testing.T) {
				artifact, err, peak := compileMeasured(engine, c.shape.snapshot())
				t.Logf("%d bytes, peak heap %d MiB, err %v", len(artifact.Config), peak>>20, err)
				if peak > heapLimit {
					t.Fatalf("peak heap %d MiB is over %d MiB", peak>>20, heapLimit>>20)
				}
				if engine == "sing-box" && c.shared {
					if err != nil {
						t.Fatalf("a shared list is inside the budget once: %v", err)
					}
					return
				}
				var objectErr *agentcore.ObjectError
				if !errors.As(err, &objectErr) || objectErr.Stream != protocol.StreamConfig {
					t.Fatalf("want a config object error from the guard, got %v", err)
				}
				if strings.Contains(err.Error(), "bring the compile to about") || !(strings.Contains(err.Error(), "reached") || strings.Contains(err.Error(), "next step")) {
					t.Fatalf("not refused by the incremental guard: %v", err)
				}
			})
		}
	}
}

func ipRanges(count int, format string, salt int) []string {
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, fmt.Sprintf(format, (salt*16+i/256)%256, i%256))
	}
	sort.Strings(out)
	return out
}

// userKey is a 2022 user key of its own for each user: two rows with one
// credential on a listener are refused as the one user they would be.
func userKey(i int) string {
	raw := make([]byte, 16)
	binary.BigEndian.PutUint64(raw[8:], uint64(i))
	return base64.StdEncoding.EncodeToString(raw)
}

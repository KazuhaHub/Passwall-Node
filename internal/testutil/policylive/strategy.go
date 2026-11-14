package policylive

import (
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// RebindHost is a fake name every server in the harness resolves to 127.0.0.1.
// It stands for a hostname an operator or a client controls that points into an
// address range the policy blocks.
const RebindHost = "rebind.example"

// NXHost is a fake name no server in the harness can resolve.
const NXHost = "nxdomain.example"

// StrategyKind names one configuration of the routing domain strategy. The
// first four are hand-set in the compiled configuration of a real Xray, to pin
// down what the core itself does with them; they are not product behaviour. The
// last two are what the compiler emits for a policy whose Resolve is on_demand.
type StrategyKind string

const (
	// StrategyAsIs is routing.domainStrategy "AsIs", which is what the compiler
	// has always written: no DNS at routing time.
	StrategyAsIs StrategyKind = "as_is"
	// StrategyAsIsRouteOnly is AsIs on an inbound whose own sniffing is
	// routeOnly:true, the control of StrategyOnDemandRouteOnly.
	StrategyAsIsRouteOnly StrategyKind = "as_is_route_only"
	// StrategyIfNonMatch is a hand-set "IPIfNonMatch", the strategy the product
	// rejects, kept as a live test of the core.
	StrategyIfNonMatch StrategyKind = "if_non_match"
	// StrategyOnDemandRouteOnly is a hand-set "IPOnDemand" on an inbound whose
	// sniffing is routeOnly:true, the combination the sniffing check refuses.
	StrategyOnDemandRouteOnly StrategyKind = "on_demand_route_only"
)

// blockLoopback is the policy every strategy case starts from: block the
// address the fake names resolve to.
func blockLoopback(extra ...protocol.DestinationRule) *protocol.DestinationPolicy {
	rules := []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"127.0.0.1/32"}}}
	return &protocol.DestinationPolicy{Rules: append(rules, extra...)}
}

func observeRebind() protocol.DestinationRule {
	return protocol.DestinationRule{ID: "p2", Action: protocol.RuleObserve, Domains: []string{"full:" + RebindHost}}
}

func strategyCases(kind StrategyKind, engine string) []liveCase {
	switch kind {
	case StrategyAsIs:
		return []liveCase{
			{name: "AsIs: a name that resolves into a blocked CIDR is not blocked", policy: fixed(blockLoopback()), outcomes: []outcome{
				viaDomain(reaches("name resolving to the blocked address", socksDomain(RebindHost))),
				isBlocked("the blocked address itself", plainBytes),
			}},
			{name: "AsIs: a report-only rule for the name changes nothing", policy: fixed(blockLoopback(observeRebind())), outcomes: []outcome{
				viaDomain(reaches("name resolving to the blocked address", socksDomain(RebindHost))),
				isBlocked("the blocked address itself", plainBytes),
			}},
		}
	case StrategyAsIsRouteOnly:
		return []liveCase{
			{name: "AsIs with routeOnly sniffing: the real address is what an address rule sees", policy: fixed(blockLoopback()), outcomes: []outcome{
				isBlocked("the blocked address, claiming a name that resolves elsewhere", httpHost(ClaimedHost)),
			}},
		}
	case StrategyIfNonMatch:
		return []liveCase{
			{name: "IPIfNonMatch: a CIDR block alone resolves the name and blocks it", policy: fixed(blockLoopback()), outcomes: []outcome{
				viaDomain(isBlocked("name resolving to the blocked address", socksDomain(RebindHost))),
				isBlocked("the blocked address itself", plainBytes),
			}},
			// The reason the product does not offer IPIfNonMatch: the observe rule
			// matches the NAME in the first pass, so the second pass, which is the
			// only one that sees addresses, never runs. A report-only rule has
			// changed a block into an allow.
			{name: "IPIfNonMatch: a report-only rule for the name skips the CIDR block", policy: fixed(blockLoopback(observeRebind())), outcomes: []outcome{
				viaDomain(reaches("name resolving to the blocked address", socksDomain(RebindHost))),
				isBlocked("the blocked address itself", plainBytes),
			}},
		}
	case StrategyOnDemandRouteOnly:
		return []liveCase{
			// Under routeOnly the connection still goes to the address the client
			// asked for, but routing judges the claimed name's addresses instead of
			// it, so the block never sees 127.0.0.1.
			{name: "IPOnDemand with routeOnly sniffing: a claimed name replaces the real address", policy: fixed(blockLoopback()), outcomes: []outcome{
				reaches("the blocked address, claiming a name that resolves elsewhere", httpHost(ClaimedHost)),
				isBlocked("the blocked address, claiming nothing", plainBytes),
				viaDomain(isBlocked("name resolving to the blocked address", socksDomain(RebindHost))),
			}},
		}
	}
	return nil
}

// RunStrategy runs the strategy cases of kind against the core start launches.
func RunStrategy(t *testing.T, clientBinary string, options Options, kind StrategyKind, start StartFunc) {
	t.Helper()
	for _, test := range strategyCases(kind, options.Engine) {
		t.Run(test.name, func(t *testing.T) {
			s := newSink(t)
			serverPort := FreePort(t)
			server := start(t, test.policy(s.port()), serverPort)
			socksPort := StartSOCKSClient(t, clientBinary, serverPort)
			for _, expected := range test.outcomes {
				if (expected.domain && !options.SOCKSDomainTargets) || (expected.engine != "" && expected.engine != options.Engine) {
					continue
				}
				if got := expected.attempt.run(t, socksPort, s, server); got != expected.delivered {
					t.Errorf("%s: delivered = %v, want %v", expected.name, got, expected.delivered)
				}
			}
		})
	}
}

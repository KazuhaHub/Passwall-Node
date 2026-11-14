package policylive

import (
	"fmt"
	"net"
	"testing"
	"time"

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
	// StrategyOnDemand is a policy whose Resolve is on_demand, compiled as it
	// ships: nothing is hand-set.
	StrategyOnDemand StrategyKind = "on_demand"
	// StrategyOnDemandUnresolvable is the same, for a name that does not
	// resolve.
	StrategyOnDemandUnresolvable StrategyKind = "on_demand_unresolvable"
)

// blockLoopback is the policy every strategy case starts from: block the
// address the fake names resolve to.
func blockLoopback(extra ...protocol.DestinationRule) *protocol.DestinationPolicy {
	rules := []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"127.0.0.1/32"}}}
	return &protocol.DestinationPolicy{Rules: append(rules, extra...)}
}

// onDemand is blockLoopback with the resolve option on.
func onDemand(policy *protocol.DestinationPolicy) *protocol.DestinationPolicy {
	policy.Resolve = protocol.ResolveOnDemand
	return policy
}

// routedTo is an attempt for a name no sink can be placed at, judged by the
// core's log: it "succeeds" when the log holds text.
func routedTo(host string, text string) attempt {
	a := socksDomain(host)
	a.logHas, a.timeout = text, 2500*time.Millisecond
	return a
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
	case StrategyOnDemand:
		cases := []liveCase{
			{name: "on_demand: a name that resolves into a private range is blocked", policy: fixed(onDemand(&protocol.DestinationPolicy{
				Rules: []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, Private: true}},
			})), outcomes: []outcome{
				viaDomain(isBlocked("name resolving to loopback", socksDomain(RebindHost))),
				isBlocked("loopback by address", plainBytes),
			}},
			{name: "on_demand: a name that resolves into a blocked CIDR is blocked", policy: fixed(onDemand(blockLoopback())), outcomes: []outcome{
				viaDomain(isBlocked("name resolving to the blocked address", socksDomain(RebindHost))),
				isBlocked("the blocked address itself", plainBytes),
			}},
			{name: "on_demand: a name that resolves outside the blocked CIDR is let through", policy: fixed(onDemand(&protocol.DestinationPolicy{
				Rules: []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"198.51.100.0/24"}}},
			})), outcomes: []outcome{
				viaDomain(reaches("name resolving to loopback", socksDomain(RebindHost))),
			}},
			// The case IPIfNonMatch gets wrong: here a report-only rule changes
			// nothing about the verdict.
			{name: "on_demand: a report-only rule for the name does not skip the CIDR block", policy: fixed(onDemand(blockLoopback(observeRebind()))), outcomes: []outcome{
				viaDomain(isBlocked("name resolving to the blocked address", socksDomain(RebindHost))),
				isBlocked("the blocked address itself", plainBytes),
			}},
		}
		if engine == "xray" {
			cases = append(cases,
				// Xray's injected sniffing rewrites the destination to the claimed
				// name, so the claimed name is where the connection goes, and its
				// addresses are what an IP rule has to judge. A domain rule in the
				// policy is what makes the node inject the sniffing.
				liveCase{name: "on_demand: a claimed name that resolves into a blocked range is blocked", claimed: true,
					policy: fixed(onDemand(&protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
						{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"::1/128"}},
						{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"domain:blocked.example"}},
					}})), outcomes: []outcome{
						isBlocked("by address, claiming a name that resolves into the blocked range", claimingByAddress(ClaimedHost)),
					}},
				liveCase{name: "AsIs: a claimed name that resolves into a blocked range is reached", claimed: true,
					policy: policyOf(
						protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"::1/128"}},
						protocol.DestinationRule{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"domain:blocked.example"}},
					), outcomes: []outcome{
						reaches("by address, claiming a name that resolves into the blocked range", claimingByAddress(ClaimedHost)),
					}},
			)
		}
		return cases
	case StrategyOnDemandUnresolvable:
		return []liveCase{{name: "on_demand: a name that does not resolve", policy: fixed(onDemand(blockLoopback())), outcomes: []outcome{
			// The log lines are the cores' own and are what tells the verdicts
			// apart: nothing reaches a sink either way.
			forEngine("xray", viaDomain(reaches("Xray fails open: no IP rule matched, so the default route is taken", routedTo(NXHost, "default route for tcp:"+NXHost)))),
			forEngine("sing-box", viaDomain(reaches("sing-box fails closed: the resolve action fails the connection", routedTo(NXHost, "dns: lookup failed for "+NXHost)))),
		}}}
	}
	return nil
}

// claimingByAddress asks for the sink's address and claims host in the HTTP
// request, and is satisfied only by reaching the sink where host resolves.
func claimingByAddress(host string) attempt {
	a := httpHost(host)
	a.claimedHost = true
	return a
}

// RunStrategy runs the strategy cases of kind against the core start launches.
func RunStrategy(t *testing.T, clientBinary string, options Options, kind StrategyKind, start StartFunc) {
	t.Helper()
	for _, test := range strategyCases(kind, options.Engine) {
		t.Run(test.name, func(t *testing.T) {
			s := newSink(t)
			if test.claimed {
				probe, err := net.Listen("tcp", fmt.Sprintf("[::1]:%d", s.port()))
				if err != nil {
					t.Skipf("no IPv6 loopback listener at the sink's port: %v", err)
				}
				_ = probe.Close()
				s.claimed = newSinkAt(t, fmt.Sprintf("[::1]:%d", s.port()))
			}
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
			if t.Failed() {
				t.Logf("core output:\n%s", server.Output())
			}
		})
	}
}

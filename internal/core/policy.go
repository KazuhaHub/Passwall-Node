package core

import (
	"fmt"
	"sort"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// PolicyError means the destination policy, and not any one listener or
// client, is what a compiler could not express. It is deliberately NOT an
// ObjectError: an object error is attributed to one object and marks that
// object rejected, and a policy belongs to none of them. Wrapping it as the
// first listener's error would mark an unrelated listener rejected whenever it
// happened to change in the same round. A policy failure is reported only
// through PolicyStatus.
//
// THE POLICY IS NEVER DROPPED TO MAKE A DEPLOYMENT SUCCEED. A node that
// silently deployed without the policy would turn every block and allowlist
// into an allow while reporting itself healthy.
type PolicyError struct {
	// Code is protocol.IssueDestinationPolicyRejected or
	// protocol.IssueDestinationPolicySniffingInsufficient.
	Code string
	// Listeners names the inbounds whose sniffing cannot support the policy.
	// Set only with IssueDestinationPolicySniffingInsufficient.
	Listeners []protocol.ListenerKey
	Err       error
}

func (e *PolicyError) Error() string {
	if e == nil {
		return "destination policy error"
	}
	if e.Err == nil {
		return fmt.Sprintf("destination policy: %s", e.Code)
	}
	return fmt.Sprintf("destination policy: %s: %v", e.Code, e.Err)
}

func (e *PolicyError) Unwrap() error { return e.Err }

// PlannedRule is one policy rule reduced to what a single compile can say.
type PlannedRule struct {
	Rule  protocol.DestinationRule
	Phase int
	// Users are the usernames (Xray email, sing-box user name) of every client
	// of every subject the rule names. Nil means the rule names no subject and
	// applies to everyone.
	Users []string
	// Inbounds are the listeners of this compile the rule applies to. Nil means
	// every inbound.
	Inbounds []protocol.ListenerKey
}

// PolicyPlan is a validated policy resolved against one roster and the set of
// listeners one compile actually emits. Both compilers build their rules from
// it, so the decisions that are about safety rather than syntax are made once:
//
//   - A rule whose subjects expand to no client is DROPPED. Left in, it would
//     compile to an empty user list, which Xray reads as "everyone".
//   - A rule that named inbounds and kept none is DROPPED. Left in, it would
//     apply to every inbound.
type PolicyPlan struct {
	Rules []PlannedRule
	// ExemptUsers are the usernames of every exempt subject. Empty means there
	// is no exempt step.
	ExemptUsers []string
	// ExemptAt is the index in Rules before which the exempt step is
	// evaluated: the first rule whose phase is 3 or later, else len(Rules).
	ExemptAt int
	// SkippedUsers counts the roster clients whose name the compiler's
	// normaliser refused, so none of their names reached a rule.
	SkippedUsers int
	// Resolve is the policy's resolve mode: whether the core resolves a
	// hostname before it tries the IP rules on it.
	Resolve     protocol.ResolveMode
	trailingDot bool
}

// The evaluation phases of a rule, from the wire spec. The exempt step sits
// between phaseAllow and phaseBlock.
const (
	phaseSourceDeny = 0
	phaseAllow      = 1
	phaseBlock      = 3
	phaseGroup      = 4
	phaseObserve    = 5

	// PhaseObserve is exported for a compiler that has to treat report-only
	// rules differently.
	PhaseObserve = phaseObserve
)

// PlanPolicy validates policy and resolves it. A policy that does not validate
// is a *PolicyError with IssueDestinationPolicyRejected: the panel validates
// before it ships one, so reaching here means it did not, and the node's answer
// is to refuse the whole policy.
//
// clients is the deployed roster, regardless of which clients are enabled.
// inbounds are the listeners this compile emits.
// UsernameFunc turns a client's credential username into the name a compiler
// writes into the core for it, and says whether that name may be written into a
// rule at all. The rules must name each client exactly as its inbound does, or a
// rule and the exempt list would match different spellings of one user.
type UsernameFunc func(username string) (name string, usable bool)

// PlanPolicy takes the compiler's UsernameFunc; nil uses the username as it is.
func PlanPolicy(policy *protocol.DestinationPolicy, clients []protocol.Client, inbounds []protocol.ListenerKey, username UsernameFunc) (PolicyPlan, error) {
	if policy == nil {
		return PolicyPlan{}, nil
	}
	if err := protocol.ValidateDestinationPolicy(policy); err != nil {
		return PolicyPlan{}, &PolicyError{Code: protocol.IssueDestinationPolicyRejected, Err: err}
	}
	if username == nil {
		username = func(name string) (string, bool) { return name, true }
	}
	plan := PolicyPlan{Resolve: policy.Resolve}
	usersBySubject := make(map[protocol.SubjectKey][]string, len(clients))
	for _, client := range clients {
		name, usable := username(client.Credentials.Username)
		if !usable {
			plan.SkippedUsers++
			continue
		}
		usersBySubject[client.Subject] = append(usersBySubject[client.Subject], name)
	}
	present := make(map[protocol.ListenerKey]struct{}, len(inbounds))
	for _, key := range inbounds {
		present[key] = struct{}{}
	}
	expand := func(subjects []protocol.SubjectKey) []string {
		var users []string
		for _, subject := range subjects {
			users = append(users, usersBySubject[subject]...)
		}
		sort.Strings(users)
		return users
	}

	for _, rule := range policy.Rules {
		planned := PlannedRule{Rule: rule, Phase: rulePhase(rule)}
		if len(rule.Subjects) > 0 {
			planned.Users = expand(rule.Subjects)
			if len(planned.Users) == 0 {
				continue
			}
		}
		if len(rule.Inbounds) > 0 {
			for _, key := range rule.Inbounds {
				if _, exists := present[key]; exists {
					planned.Inbounds = append(planned.Inbounds, key)
				}
			}
			if len(planned.Inbounds) == 0 {
				continue
			}
		}
		plan.Rules = append(plan.Rules, planned)
	}
	for _, rule := range policy.Rules {
		if rule.Action == protocol.RuleBlock && len(rule.Domains) > 0 {
			plan.trailingDot = true
		}
	}
	plan.ExemptUsers = expand(policy.Exempt)
	plan.ExemptAt = len(plan.Rules)
	for index, rule := range plan.Rules {
		if rule.Phase >= phaseBlock {
			plan.ExemptAt = index
			break
		}
	}
	return plan, nil
}

// rulePhase mirrors the protocol's phase table. ValidateDestinationPolicy has
// already accepted the rule, so every combination reaching here has a phase.
func rulePhase(rule protocol.DestinationRule) int {
	switch {
	case rule.ID[0] == 'g':
		return phaseGroup
	case rule.Action == protocol.RuleObserve:
		return phaseObserve
	case rule.ID[0] == 's':
		return phaseSourceDeny
	case rule.Action == protocol.RuleAllow:
		return phaseAllow
	default:
		return phaseBlock
	}
}

// ruleNeed is what one rule needs from sniffing. An IP rule (CIDRs, Private)
// needs the resolved-address guard only when the policy resolves hostnames:
// under AsIs it is tried on an address target and nothing is looked up.
func ruleNeed(rule protocol.DestinationRule, resolve protocol.ResolveMode) protocol.SniffNeed {
	var need protocol.SniffNeed
	if resolve == protocol.ResolveOnDemand && (len(rule.CIDRs) > 0 || rule.Private) {
		need |= protocol.SniffForResolvedIPs
	}
	if len(rule.Domains) > 0 {
		need |= protocol.SniffForDomains
	}
	if len(rule.Protocols) > 0 {
		need |= protocol.SniffForProtocols
	}
	return need
}

// SniffNeed is what the planned rules need from sniffing, over every listener.
func (p PolicyPlan) SniffNeed() protocol.SniffNeed {
	var need protocol.SniffNeed
	for _, rule := range p.Rules {
		need |= ruleNeed(rule.Rule, p.Resolve)
	}
	return need
}

// SniffNeedFor is what the planned rules that apply to one listener need from
// its sniffing. A rule scoped to other inbounds asks nothing of this one.
func (p PolicyPlan) SniffNeedFor(listener protocol.ListenerKey) protocol.SniffNeed {
	var need protocol.SniffNeed
	for _, rule := range p.Rules {
		if rule.Inbounds != nil && !containsListener(rule.Inbounds, listener) {
			continue
		}
		need |= ruleNeed(rule.Rule, p.Resolve)
	}
	return need
}

func containsListener(keys []protocol.ListenerKey, key protocol.ListenerKey) bool {
	for _, candidate := range keys {
		if candidate == key {
			return true
		}
	}
	return false
}

// TrailingDotGuard reports whether the compilers must add the builtin rule that
// blocks a host written with a trailing dot (protocol.BuiltinTrailingDot).
// Neither core normalises "blocked.example." to "blocked.example" before
// matching, so a domain block would let the dotted spelling through. The guard
// blocks the spelling instead of matching it, sits after the exempt step and
// before the blocks, and exists only when a BLOCK rule has domains: an allow or
// observe rule that misses a dotted host fails safe, and report-only must never
// gain a blocking rule. It is decided on the policy, as MatchDestination does,
// not on which rules survive this compile.
func (p PolicyPlan) TrailingDotGuard() bool { return p.trailingDot }

// ExitsAllow reports whether a rule scoped to exits applies to traffic leaving
// through exit: an empty scope applies to every exit.
func ExitsAllow(exits []protocol.LinkKey, exit protocol.LinkKey) bool {
	if len(exits) == 0 {
		return true
	}
	for _, candidate := range exits {
		if candidate == exit {
			return true
		}
	}
	return false
}

// scoped is the plan restricted to listeners. keep decides, per rule and
// listener, whether the rule applies there. A rule keeps no listener is dropped,
// and every kept rule names its listeners explicitly (Inbounds non-nil), in the
// order of its own Inbounds when it had them.
func (p PolicyPlan) scoped(listeners []protocol.ListenerKey, keep func(PlannedRule, protocol.ListenerKey) bool) PolicyPlan {
	member := make(map[protocol.ListenerKey]bool, len(listeners))
	for _, key := range listeners {
		member[key] = true
	}
	out := p
	out.Rules = nil
	for _, rule := range p.Rules {
		candidates := rule.Inbounds
		if candidates == nil {
			candidates = listeners
		}
		var kept []protocol.ListenerKey
		for _, key := range candidates {
			if member[key] && keep(rule, key) {
				kept = append(kept, key)
			}
		}
		if len(kept) == 0 {
			continue
		}
		rule.Inbounds = kept
		out.Rules = append(out.Rules, rule)
	}
	out.ExemptAt = len(out.Rules)
	for index, rule := range out.Rules {
		if rule.Phase >= phaseBlock {
			out.ExemptAt = index
			break
		}
	}
	return out
}

// ForBase is the plan for the listeners that have no route rules, which leave
// through their default exit only: a rule scoped to exits (DestinationRule.Exits)
// applies to a listener only when its default exit is one of them. restrict
// additionally names the listeners of every rule, which a compile with routed
// listeners needs so that no rule of the base list can also judge a routed
// listener's traffic ahead of its segments. Without restrict and without a rule
// that has Exits the plan is returned as it is, byte for byte.
func (p PolicyPlan) ForBase(unrouted []protocol.ListenerKey, defaultExit func(protocol.ListenerKey) protocol.LinkKey, restrict bool) PolicyPlan {
	if !restrict {
		scoped := false
		for _, rule := range p.Rules {
			if len(rule.Rule.Exits) > 0 {
				scoped = true
				break
			}
		}
		if !scoped {
			return p
		}
	}
	scopedPlan := p.scoped(unrouted, func(rule PlannedRule, key protocol.ListenerKey) bool {
		return ExitsAllow(rule.Rule.Exits, defaultExit(key))
	})
	if restrict {
		return scopedPlan
	}
	// Only the rules with Exits are named explicitly; the rest keep meaning
	// "every inbound", as they always did.
	out := p
	out.Rules = nil
	index := 0
	for _, rule := range p.Rules {
		if len(rule.Rule.Exits) == 0 {
			out.Rules = append(out.Rules, rule)
			continue
		}
		for index < len(scopedPlan.Rules) && scopedPlan.Rules[index].Rule.ID != rule.Rule.ID {
			index++
		}
		if index < len(scopedPlan.Rules) {
			out.Rules = append(out.Rules, scopedPlan.Rules[index])
			index++
		}
	}
	out.ExemptAt = len(out.Rules)
	for i, rule := range out.Rules {
		if rule.Phase >= phaseBlock {
			out.ExemptAt = i
			break
		}
	}
	return out
}

// ForSegment is the plan for one segment of a routed group: the rules that
// apply to traffic leaving through exit, confined to the group's listeners.
func (p PolicyPlan) ForSegment(group []protocol.ListenerKey, exit protocol.LinkKey) PolicyPlan {
	return p.scoped(group, func(rule PlannedRule, _ protocol.ListenerKey) bool {
		return ExitsAllow(rule.Rule.Exits, exit)
	})
}

// MaxRoutedEntries bounds what a compile with routed listeners may write: the
// destination entries (domains, CIDRs) of its rules, counted before anything is
// built. A policy rule's matcher can have tens of thousands of entries and is
// copied into every segment of every group, so the product, not the rule count,
// is what costs memory; at roughly 60 bytes an entry, a million is tens of MiB
// of configuration and well under 512 MiB of heap while it is encoded.
const MaxRoutedEntries = 1_000_000

// SkipRoutedEstimate is a test hook: with it set the compilers skip the cheap
// up-front estimate, so a test can show that the incremental RouteBudget alone
// refuses what it must. Nothing outside tests sets it.
var SkipRoutedEstimate bool

func ruleEntries(rule protocol.DestinationRule) int {
	n := len(rule.Domains) + len(rule.CIDRs)
	if rule.Private {
		n += len(protocol.PrivateDestinationCIDRs())
	}
	return n
}

func routeEntries(route protocol.RouteRule) int { return len(route.Domains) + len(route.CIDRs) }

// CountEntries is the number of elements in every list a rule holds, nested
// rules and objects included: destination entries, users, source ranges,
// inbound tags, whatever the field. The budget charges a rule with this and with
// no list of field names, so a field added later cannot be forgotten.
func CountEntries(value any) int {
	switch v := value.(type) {
	case map[string]any:
		n := 0
		for _, inner := range v {
			n += CountEntries(inner)
		}
		return n
	case []map[string]any:
		n := 0
		for _, inner := range v {
			n += CountEntries(inner)
		}
		return n
	case []any:
		n := 0
		for _, inner := range v {
			n += 1 + CountEntries(inner)
		}
		return n
	case []string:
		return len(v)
	case []int:
		return len(v)
	}
	return 0
}

// RouteBudget is the authoritative guard of a routed compile: the compilers
// count every destination entry and rule AS THEY APPEND it while generating
// segments, and stop at the first one past MaxRoutedEntries or MaxRoutedRules,
// so memory is bounded by construction, whatever shape the policy and routes
// have. Check is for a step about to allocate a known amount (an intersection
// of two lists, say) so it is refused before it does.
type RouteBudget struct {
	entries, rules int
}

func (b *RouteBudget) over() error {
	switch {
	case b.entries > MaxRoutedEntries:
		return fmt.Errorf("more than %d destination entries (the compile has reached %d)", MaxRoutedEntries, b.entries)
	case b.rules > MaxRoutedRules:
		return fmt.Errorf("more than %d core rules (the compile has reached %d)", MaxRoutedRules, b.rules)
	}
	return nil
}

// Add counts one appended rule with entries destination entries.
func (b *RouteBudget) Add(entries int) error {
	b.rules++
	b.entries += entries
	return b.over()
}

// AddEntries counts destination entries that are not a rule of their own (a
// rule set's).
func (b *RouteBudget) AddEntries(entries int) error {
	b.entries += entries
	return b.over()
}

// Check refuses a step that would allocate about pending entries when that
// would pass the budget.
func (b *RouteBudget) Check(pending int) error {
	if b.entries+pending > MaxRoutedEntries {
		return fmt.Errorf("more than %d destination entries (%d so far, and the next step needs about %d)", MaxRoutedEntries, b.entries, pending)
	}
	return nil
}

// EstimateRoutedEntries is a cheap estimate of the destination
// entries one group adds, from the plan and the group alone. It may
// UNDERCOUNT (it does not see the exempt step, the usage and trailing-dot rules,
// the copies of a route's matcher, or the hostname-through-address rules), so it
// is only a fast path that refuses the obvious before anything is built; the
// RouteBudget the builders count into is what bounds the compile. With shared, a compiler writes each
// policy rule's matcher once (an inline rule set) and each segment refers to
// it, so the matchers count once, in seen (carried across groups), and a
// segment costs a reference per rule. Without it every segment carries its own
// copy, intersected with the route rule: at most the product of the two lists.
func EstimateRoutedEntries(plan PolicyPlan, group RouteGroup, shared bool, seen map[string]bool) int {
	total := 0
	segment := func(exit protocol.LinkKey, route *protocol.RouteRule) {
		if route != nil {
			total += routeEntries(*route) + 1
		}
		segmentPlan := plan.ForSegment(group.Listeners, exit)
		total += len(segmentPlan.ExemptUsers)
		for _, planned := range segmentPlan.Rules {
			rule := planned.Rule
			if shared {
				total += 1 + len(planned.Users)
				if !seen[rule.ID] {
					seen[rule.ID] = true
					total += ruleEntries(rule) + len(rule.SourceCIDRs)
				}
				continue
			}
			extra := len(rule.SourceCIDRs) + len(planned.Users) + len(planned.Inbounds)
			cost := ruleEntries(rule) + 1 + extra
			if route != nil {
				domains, addresses := len(rule.Domains), len(rule.CIDRs)
				if rule.Private {
					addresses += len(protocol.PrivateDestinationCIDRs())
				}
				cost = max(domains*max(len(route.Domains), 1), domains) + max(addresses*max(len(route.CIDRs), 1), addresses) + 1 + extra
			}
			total += cost
		}
	}
	for position := range group.Rules {
		segment(group.Rules[position].Exit, &group.Rules[position])
	}
	segment(group.Default, nil)
	return total
}

// HasProtocolRules reports whether any planned rule names a protocol.
func (p PolicyPlan) HasProtocolRules() bool {
	for _, rule := range p.Rules {
		if len(rule.Rule.Protocols) > 0 {
			return true
		}
	}
	return false
}

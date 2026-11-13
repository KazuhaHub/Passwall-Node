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
	trailingDot  bool
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
	var plan PolicyPlan
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

func ruleNeed(rule protocol.DestinationRule) protocol.SniffNeed {
	var need protocol.SniffNeed
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
		need |= ruleNeed(rule.Rule)
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
		need |= ruleNeed(rule.Rule)
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

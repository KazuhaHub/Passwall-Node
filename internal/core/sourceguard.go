package core

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// The rule tags of the source guard rules. The audit receiver reads the set (allow) or the combination (deny) off the tag, so the
// two sides share this one spelling.
const (
	GuardAllowTagPrefix = "guard-allow-"
	GuardDenyTagPrefix  = "guard-deny-"
	// GuardOutboundPrefix names the blackhole outbound a guard rule sends its
	// match to. It is one outbound per rule and not the shared "blocked" one,
	// because the webhook event names the outbound it was routed to: the tag
	// is what lets the receiver tell which rule refused the connection without
	// depending on the core reporting the rule tag as well.
	GuardOutboundPrefix = "psp-guard-"
)

// GuardRule is one routing rule of the source guard, engine independent.
type GuardRule struct {
	// Tag is the rule tag: guard-allow-<suffix> or guard-deny-<n>.
	Tag string
	// Allow is true for an allow rule: the match is the users on Listeners whose
	// source is OUTSIDE CIDRs. A deny rule matches a source INSIDE CIDRs.
	Allow bool
	// Sets are the sets the rule is about: the one allow set, or the existing
	// sets of the deny combination, ascending.
	Sets []protocol.SourceSetKey
	// Missing is true for an allow rule whose set is not in the config. It has
	// no CIDRs and matches every source: the client is refused entirely.
	Missing bool
	// CIDRs is the allow set's networks, or the union of a deny combination's.
	// Sorted as text, unique.
	CIDRs []string
	// Listeners are the served listeners of the rule's clients, ascending.
	Listeners []protocol.ListenerKey
	// Users are the raw credential usernames of the rule's clients, ascending;
	// each engine maps them to the name its core matches.
	Users []string
}

// OutboundTag is the blackhole outbound of the rule.
func (r GuardRule) OutboundTag() string {
	return GuardOutboundPrefix + strings.TrimPrefix(r.Tag, "guard-")
}

// GuardPlan is the compile's source guard, shared by the engines and the audit
// receiver so that the rules and the attribution of their hits cannot differ.
type GuardPlan struct {
	Rules []GuardRule
	// Sets holds the parsed networks of every set a rule is about, for the
	// receiver's "which of the combination's sets contains the source".
	Sets map[protocol.SourceSetKey][]netip.Prefix
}

// PlanSourceGuard turns the config's source sets and the roster's guards into
// rules. Only enabled, unexpired clients on a served listener are covered: the
// others are not in the core's user list, so a rule naming them would match
// nothing and only grow the config. A snapshot with no guarded client yields an
// empty plan, and the compilers then emit exactly what they emitted before the
// guard existed.
//
// A deny rule is skipped when none of its sets exists (nothing to refuse), and
// the compilers skip an allow rule whose set covers every address, because an
// empty source list would read as "any source" in Xray.
func PlanSourceGuard(snapshot Snapshot, served []protocol.ListenerKey) (GuardPlan, error) {
	var plan GuardPlan
	sets := map[protocol.SourceSetKey][]string{}
	if snapshot.Transit != nil {
		for _, set := range snapshot.Transit.SourceSets {
			sets[set.Key] = set.CIDRs
		}
	}
	servedSet := make(map[protocol.ListenerKey]struct{}, len(served))
	for _, key := range served {
		servedSet[key] = struct{}{}
	}

	type group struct {
		listeners map[protocol.ListenerKey]struct{}
		users     map[string]struct{}
	}
	add := func(groups map[string]*group, name string, client protocol.Client, listeners []protocol.ListenerKey) {
		entry := groups[name]
		if entry == nil {
			entry = &group{listeners: map[protocol.ListenerKey]struct{}{}, users: map[string]struct{}{}}
			groups[name] = entry
		}
		entry.users[client.Credentials.Username] = struct{}{}
		for _, key := range listeners {
			entry.listeners[key] = struct{}{}
		}
	}
	allow := map[string]*group{}
	deny := map[string]*group{}
	for _, client := range snapshot.Clients {
		guard := client.SourceGuard
		if guard == nil || !client.Enabled ||
			(client.ExpiresAtMS > 0 && !snapshot.Now.IsZero() && snapshot.Now.UnixMilli() >= client.ExpiresAtMS) {
			continue
		}
		if err := protocol.ValidateClientSourceGuard(guard); err != nil {
			return GuardPlan{}, &GuardError{Client: client.Key, Err: err}
		}
		var listeners []protocol.ListenerKey
		for _, key := range client.Listeners {
			if _, ok := servedSet[key]; ok {
				listeners = append(listeners, key)
			}
		}
		if len(listeners) == 0 || client.Credentials.Username == "" {
			continue
		}
		if guard.AllowFrom != "" {
			add(allow, string(guard.AllowFrom), client, listeners)
			continue
		}
		// Only the sets that exist count: two clients whose lists differ only in
		// a missing set are denied the same sources, so they share a rule.
		var existing []string
		for _, key := range guard.DenyFrom {
			if _, ok := sets[key]; ok {
				existing = append(existing, string(key))
			}
		}
		if len(existing) == 0 {
			continue
		}
		sort.Strings(existing)
		add(deny, strings.Join(existing, "\x00"), client, listeners)
	}

	plan.Sets = map[protocol.SourceSetKey][]netip.Prefix{}
	parse := func(key protocol.SourceSetKey) error {
		if _, done := plan.Sets[key]; done {
			return nil
		}
		prefixes := make([]netip.Prefix, 0, len(sets[key]))
		for _, raw := range sets[key] {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return fmt.Errorf("source set %s: %w", key, err)
			}
			prefixes = append(prefixes, prefix)
		}
		plan.Sets[key] = prefixes
		return nil
	}
	finish := func(entry *group) ([]protocol.ListenerKey, []string) {
		listeners := make([]protocol.ListenerKey, 0, len(entry.listeners))
		for key := range entry.listeners {
			listeners = append(listeners, key)
		}
		sort.Slice(listeners, func(i, j int) bool { return listeners[i] < listeners[j] })
		users := make([]string, 0, len(entry.users))
		for user := range entry.users {
			users = append(users, user)
		}
		sort.Strings(users)
		return listeners, users
	}

	names := make([]string, 0, len(allow))
	for name := range allow {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		key := protocol.SourceSetKey(name)
		rule := GuardRule{Tag: GuardAllowTagPrefix + key.Suffix(), Allow: true, Sets: []protocol.SourceSetKey{key}}
		rule.Listeners, rule.Users = finish(allow[name])
		if cidrs, ok := sets[key]; ok {
			if err := parse(key); err != nil {
				return GuardPlan{}, err
			}
			rule.CIDRs = append([]string(nil), cidrs...)
			sort.Strings(rule.CIDRs)
		} else {
			rule.Missing = true
		}
		plan.Rules = append(plan.Rules, rule)
	}

	names = names[:0]
	for name := range deny {
		names = append(names, name)
	}
	sort.Strings(names)
	for index, name := range names {
		rule := GuardRule{Tag: GuardDenyTagPrefix + strconv.Itoa(index+1)}
		union := map[string]struct{}{}
		for _, raw := range strings.Split(name, "\x00") {
			key := protocol.SourceSetKey(raw)
			if err := parse(key); err != nil {
				return GuardPlan{}, err
			}
			rule.Sets = append(rule.Sets, key)
			for _, cidr := range sets[key] {
				union[cidr] = struct{}{}
			}
		}
		for cidr := range union {
			rule.CIDRs = append(rule.CIDRs, cidr)
		}
		sort.Strings(rule.CIDRs)
		rule.Listeners, rule.Users = finish(deny[name])
		plan.Rules = append(plan.Rules, rule)
	}
	return plan, nil
}

// GuardError is a guard that could not be planned, attributed to a client when
// one is at fault.
type GuardError struct {
	Client protocol.ClientKey
	Err    error
}

func (e *GuardError) Error() string {
	if e.Client != "" {
		return fmt.Sprintf("client %s source guard: %v", e.Client, e.Err)
	}
	return "source guard: " + e.Err.Error()
}

func (e *GuardError) Unwrap() error { return e.Err }

// ServedListenerKeys are the listeners of a config that a compile serves: the
// enabled ones, in key order. It exists for the audit receiver, which plans the
// guard from the stored config and roster and must number the deny rules exactly
// as the compile did. A listener whose config cannot be read is left out: the
// compile refuses it, so no deployment holds it.
func ServedListenerKeys(listeners []protocol.Listener) []protocol.ListenerKey {
	var served []protocol.ListenerKey
	for _, listener := range listeners {
		var spec struct {
			Enabled bool `json:"enabled"`
		}
		if json.Unmarshal(listener.Config, &spec) == nil && spec.Enabled {
			served = append(served, listener.Key)
		}
	}
	sort.Slice(served, func(i, j int) bool { return served[i] < served[j] })
	return served
}

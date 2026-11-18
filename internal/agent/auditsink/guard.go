package auditsink

import (
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

const (
	// GuardPath is the path the source guard rules' webhooks post to: one event
	// per refused connection.
	GuardPath = "/guard"

	// MaxGuardHits bounds the distinct (set, listener, source) entries kept; it
	// is the most a report carries. A scan from many addresses must not grow
	// the table, so a new entry in a full table evicts the one seen longest ago.
	MaxGuardHits = protocol.MaxSourceGuardHits
	// GuardHitMaxAge is how long an entry is kept after it was last seen. The
	// aggregate is reported with every full report and is not cleared when sent,
	// so this is what retires an address that stopped knocking.
	GuardHitMaxAge = 24 * time.Hour

	guardListenerTagPrefix = "psp-"
)

// GuardSet is one source set a guard rule is about: its key and its networks,
// which the receiver needs to find which set of a deny combination contains a
// refused source.
type GuardSet struct {
	Key      protocol.SourceSetKey
	Prefixes []netip.Prefix
}

// GuardRule is what the receiver knows of one guard rule. Allow rules name
// their one set whatever the source (it was outside the set by definition); a
// deny rule names the sets of its combination that contain the source.
type GuardRule struct {
	Allow bool
	Sets  []GuardSet
}

// GuardPlan maps the tags a webhook event can carry, the rule tag and the
// rule's own outbound tag, to the rule. It is a snapshot like the roster.
type GuardPlan map[string]GuardRule

type guardKey struct {
	set      protocol.SourceSetKey
	listener protocol.ListenerKey
	ip       netip.Addr
}

type guardEntry struct {
	count      int64
	lastSeenMS int64
}

// SetGuard replaces the deployed guard plan and drops a staged one.
func (s *Sink) SetGuard(plan GuardPlan) {
	s.mu.Lock()
	s.guard, s.stagedGuard = plan, nil
	s.mu.Unlock()
}

// StageGuard is the plan of a deployment about to start, consulted after the
// deployed one until the deployment is confirmed (SetGuard) or abandoned
// (DiscardStaged), for the same reason the roster is staged.
func (s *Sink) StageGuard(plan GuardPlan) {
	s.mu.Lock()
	s.stagedGuard = plan
	s.mu.Unlock()
}

// guardEvent is the part of Xray's event the guard path reads. Unlike the other
// paths it needs the source address, because that is what is reported; it is
// kept only as the key of a bounded table, and never logged.
type guardEvent struct {
	Source      string `json:"source"`
	InboundTag  string `json:"inboundTag"`
	OutboundTag string `json:"outboundTag"`
	RuleTag     string `json:"ruleTag"`
}

func (s *Sink) handleGuard(w http.ResponseWriter, body []byte) {
	var event guardEvent
	if err := json.Unmarshal(body, &event); err != nil {
		s.countUnmatched()
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.recordGuard(event)
	w.WriteHeader(http.StatusNoContent)
}

// recordGuard turns one refusal into at most one counted entry. It is a few map
// operations and no I/O.
func (s *Sink) recordGuard(event guardEvent) {
	source, ok := parseSource(event.Source)
	listener := protocol.ListenerKey(strings.TrimPrefix(event.InboundTag, guardListenerTagPrefix))
	if _, err := listener.RowID(); err != nil || !ok {
		s.countUnmatched()
		return
	}
	nowMS := s.now().UnixMilli()
	s.mu.Lock()
	defer s.mu.Unlock()
	rules := s.guardRulesLocked(event)
	if len(rules) == 0 {
		s.unmatched++
		return
	}
	// The deployed rule is tried first and the staged one after it: while a
	// deployment rolls out, a tag both plans know can hold different networks, and
	// the event is from whichever core refused it, so a source that only the
	// staged rule's networks contain still belongs to the new core.
	for _, rule := range rules {
		matched := false
		for _, set := range rule.Sets {
			if !rule.Allow && !containsAddr(set.Prefixes, source) {
				continue
			}
			s.addGuardLocked(guardKey{set.Key, listener, source}, nowMS)
			matched = true
			if rule.Allow {
				break
			}
		}
		if matched {
			return
		}
	}
	s.unmatched++
}

// guardRulesLocked resolves the tag of an event to the rules it can mean: the
// deployed plan's first (while a deployment is staged the core still running is
// the old one, and a tag both plans know is the same set combination, tags being
// content), then the staged plan's, which belongs to the new core.
func (s *Sink) guardRulesLocked(event guardEvent) []GuardRule {
	var rules []GuardRule
	for _, plan := range []GuardPlan{s.guard, s.stagedGuard} {
		for _, tag := range []string{event.RuleTag, event.OutboundTag} {
			if tag == "" {
				continue
			}
			if rule, ok := plan[tag]; ok {
				rules = append(rules, rule)
				break
			}
		}
	}
	return rules
}

func (s *Sink) addGuardLocked(key guardKey, nowMS int64) {
	s.expireGuardLocked(nowMS)
	entry, exists := s.guardHits[key]
	if !exists && len(s.guardHits) >= MaxGuardHits {
		var oldest guardKey
		oldestSeen := int64(1<<63 - 1)
		for candidate, value := range s.guardHits {
			if value.lastSeenMS < oldestSeen {
				oldest, oldestSeen = candidate, value.lastSeenMS
			}
		}
		delete(s.guardHits, oldest)
	}
	if entry.count < 1<<62 {
		entry.count++
	}
	entry.lastSeenMS = nowMS
	s.guardHits[key] = entry
}

func (s *Sink) expireGuardLocked(nowMS int64) {
	cutoff := nowMS - GuardHitMaxAge.Milliseconds()
	for key, entry := range s.guardHits {
		if entry.lastSeenMS < cutoff {
			delete(s.guardHits, key)
		}
	}
}

// GuardHits returns the current aggregate, newest first, without clearing it:
// it is reported with every full report and entries age out (GuardHitMaxAge)
// instead of being settled, so a report the panel never accepted loses nothing.
// The count of an entry is cumulative from its first sighting while it lives.
func (s *Sink) GuardHits() []protocol.SourceGuardHit {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireGuardLocked(s.now().UnixMilli())
	out := make([]protocol.SourceGuardHit, 0, len(s.guardHits))
	for key, entry := range s.guardHits {
		out = append(out, protocol.SourceGuardHit{
			Set: key.set, Listener: key.listener, SourceIP: key.ip.String(),
			Count: entry.count, LastSeenMS: entry.lastSeenMS,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case a.LastSeenMS != b.LastSeenMS:
			return a.LastSeenMS > b.LastSeenMS
		case a.Set != b.Set:
			return a.Set < b.Set
		case a.Listener != b.Listener:
			return a.Listener < b.Listener
		}
		return a.SourceIP < b.SourceIP
	})
	return out
}

// parseSource reads Xray's "ip:port" (IPv6 in brackets) into the unmapped
// address, so one client is one entry whichever way the core spelled it.
func parseSource(source string) (netip.Addr, bool) {
	host := source
	if h, _, err := net.SplitHostPort(source); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func containsAddr(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

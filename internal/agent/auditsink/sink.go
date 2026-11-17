// Package auditsink receives the hits Xray reports for the rules that carry a
// webhook, and the per-site usage it reports for the connections that are let
// through, and aggregates both for the next report.
//
// WHAT IT KEEPS IS DELIBERATELY SMALL. Xray's event names the client's source
// address; the receiver decodes only the fields it uses, so the address is never
// held, and neither is anything else it was not asked for. Events are counted per
// (hour, rule, action, subject, destination, port, egress); a group on trial is
// folded further, to (hour, rule, site, egress), so that who went where never
// leaves this package for those rows. The egress is empty unless the deployment
// asks for it.
//
// Usage is counted per (hour, subject, site): the same registrable domain a trial
// row is folded to, or "(ip)" where the destination was an address, so neither
// an address nor a port nor a full host name is kept for it.
//
// NOTHING IS WRITTEN TO DISK AND NOTHING IS LOGGED. A hit names an account and a
// destination. The receiver exposes counts only.
package auditsink

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KazuhaHub/passwall-protocol/protocol"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

const (
	// HeaderName carries the shared secret Xray is configured to send.
	HeaderName = "X-PSP-Audit"
	// HitPath is the path a webhook posts to.
	HitPath = "/hit"
	// UsagePath is the path the usage webhook posts to: every connection that
	// was let through, one event each, with no rule behind it.
	UsagePath = "/usage"

	// MaxSocketPathBytes is the longest socket path the receiver listens on.
	// sun_path is 104 bytes on macOS and 108 on Linux, and Xray's own use of the
	// path adds nothing, so 100 leaves a margin on both.
	MaxSocketPathBytes = 100

	// DefaultMaxHitKeys and DefaultMaxTrialKeys bound the two aggregators. They
	// are separate on purpose: the fallback rule of a group on trial matches
	// most of the connections its members make outside the list, and must not
	// be able to take the room a real block needs.
	// The usage table is its own as well: a site visited by many people would
	// otherwise take room from the hits.
	DefaultMaxHitKeys   = 20000
	DefaultMaxTrialKeys = 10000
	// DefaultMaxUsageKeys bounds (hour, subject, site) rows between two takes.
	DefaultMaxUsageKeys = 50000

	maxBodyBytes        = 4 << 10
	maxHeaderBytes      = 8 << 10
	readHeaderTimeout   = 2 * time.Second
	readBodyTimeout     = 5 * time.Second
	outboundDenyPrefix  = "psp-deny-"
	outboundWatchPrefix = "psp-watch-"
)

// ErrPathTooLong means the socket path cannot be listened on. A node in that
// state records no hits and must not say it does.
var ErrPathTooLong = errors.New("audit socket path is too long for a unix socket")

// Options configures a Sink.
type Options struct {
	// Path is the absolute socket path, <DataDir>/runtime/audit.sock.
	Path string
	// Token is what the X-PSP-Audit header must equal.
	Token string
	// Now is the clock the hour bucket and the first/last times come from: the
	// node's receive time, not the time in the event.
	Now func() time.Time
	// MaxHitKeys and MaxTrialKeys are the aggregator limits; zero uses the
	// defaults.
	MaxHitKeys   int
	MaxTrialKeys int
	MaxUsageKeys int
}

// Stats are the receiver's own counters, for tests and diagnostics. None of
// them carries content.
type Stats struct {
	// Unauthorized counts requests refused for a missing or wrong header.
	Unauthorized uint64
}

// Egress is the part of a deployment the receiver needs to read the egress off
// an outbound tag: whether the policy asks for it (audit_egress), and the links
// this entry has, which are the only suffixes a split rule can honestly carry.
// It is a snapshot taken with the roster, because the core that sends the event
// is the one that deployment compiled.
type Egress struct {
	Enabled bool
	Links   []protocol.LinkKey
}

// egressSet is Egress prepared for lookups. It is never mutated after it is
// built, so a copy of the struct can be used outside the lock.
type egressSet struct {
	enabled bool
	links   map[protocol.LinkKey]struct{}
}

// accepts reports whether a hit's link suffix belongs to this snapshot: always
// when egress is not reported (the suffix is then only stripped), otherwise
// only for one of its links.
func (e egressSet) accepts(suffix string) bool {
	if !e.enabled {
		return true
	}
	_, ok := e.links[protocol.LinkKey(suffix)]
	return ok
}

func newEgressSet(egress Egress) egressSet {
	set := egressSet{enabled: egress.Enabled, links: make(map[protocol.LinkKey]struct{}, len(egress.Links))}
	for _, link := range egress.Links {
		set.links[link] = struct{}{}
	}
	return set
}

// Taken is what one Take removed from the aggregators.
type Taken struct {
	// Hits holds every aggregated row, trial rows included, oldest hour first.
	Hits []protocol.AuditHit
	// Usage holds every per-site row, oldest hour first.
	Usage []protocol.AuditUsage
	// The counters are events that never became a row.
	DroppedHits  uint64
	DroppedTrial uint64
	DroppedUsage uint64
	Unmatched    uint64
}

type hitKey struct {
	hour    int64
	rule    string
	action  string
	subject protocol.SubjectKey
	dest    string
	port    uint16
	egress  protocol.LinkKey
}

type trialKey struct {
	hour   int64
	rule   string
	dest   string
	egress protocol.LinkKey
}

type usageKey struct {
	hour    int64
	subject protocol.SubjectKey
	site    string
}

type counted struct {
	count   uint32
	firstMS int64
	lastMS  int64
	set     bool
}

// Sink is the receiver and its aggregators.
type Sink struct {
	path  string
	token []byte
	now   func() time.Time

	listener net.Listener
	server   *http.Server
	// broken carries the first failure that must stop the receiver, a handler
	// panic. Serve returns it.
	broken chan error
	// beforeRecord is a test hook that runs before an event is recorded.
	beforeRecord func()

	unauthorized atomic.Uint64

	mu           sync.Mutex
	subjects     map[string]protocol.SubjectKey
	rules        map[string]struct{}
	stagedUsers  map[string]protocol.SubjectKey
	stagedRules  map[string]struct{}
	egress       egressSet
	stagedEgress egressSet
	hits         map[hitKey]counted
	trial        map[trialKey]counted
	usage        map[usageKey]uint32
	maxHitKeys   int
	maxTrialKeys int
	maxUsageKeys int
	droppedHits  uint64
	droppedTrial uint64
	droppedUsage uint64
	unmatched    uint64
}

// New builds a Sink. It does not listen: Listen does, so the caller can decline
// to declare the capability when it fails.
func New(options Options) (*Sink, error) {
	if options.Path == "" {
		return nil, errors.New("audit socket path is required")
	}
	if options.Token == "" {
		return nil, errors.New("audit token is required")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.MaxHitKeys <= 0 {
		options.MaxHitKeys = DefaultMaxHitKeys
	}
	if options.MaxTrialKeys <= 0 {
		options.MaxTrialKeys = DefaultMaxTrialKeys
	}
	if options.MaxUsageKeys <= 0 {
		options.MaxUsageKeys = DefaultMaxUsageKeys
	}
	sink := &Sink{
		path: options.Path, token: []byte(options.Token), now: options.Now,
		subjects: map[string]protocol.SubjectKey{}, rules: map[string]struct{}{},
		hits: map[hitKey]counted{}, trial: map[trialKey]counted{}, broken: make(chan error, 1),
		usage:      map[usageKey]uint32{},
		maxHitKeys: options.MaxHitKeys, maxTrialKeys: options.MaxTrialKeys, maxUsageKeys: options.MaxUsageKeys,
	}
	sink.server = &http.Server{
		Handler:           http.HandlerFunc(sink.serveHTTP),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readBodyTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	return sink, nil
}

// Path is the socket path.
func (s *Sink) Path() string { return s.path }

// Stats returns the receiver's counters.
func (s *Sink) Stats() Stats { return Stats{Unauthorized: s.unauthorized.Load()} }

// Listen creates the socket. The directory is created with mode 0700, because
// a fresh installation has no runtime directory yet; a socket left by an earlier
// run is removed, but nothing that is not a socket is; and the socket is 0600.
// It is a filesystem socket and never an abstract one, which would bypass file
// permissions and let any local process forge hits.
func (s *Sink) Listen() error {
	if len(s.path) > MaxSocketPathBytes {
		return fmt.Errorf("%w (%d bytes, limit %d)", ErrPathTooLong, len(s.path), MaxSocketPathBytes)
	}
	if !filepath.IsAbs(s.path) {
		return errors.New("audit socket path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create audit socket directory: %w", err)
	}
	if info, err := os.Lstat(s.path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("audit socket path exists and is not a socket")
		}
		if err := os.Remove(s.path); err != nil {
			return fmt.Errorf("remove stale audit socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect audit socket path: %w", err)
	}
	listener, err := net.Listen("unix", s.path)
	if err != nil {
		return fmt.Errorf("listen on audit socket: %w", err)
	}
	if err := os.Chmod(s.path, 0o600); err != nil {
		_ = listener.Close()
		return fmt.Errorf("restrict audit socket: %w", err)
	}
	s.listener = listener
	return nil
}

// Serve accepts events until ctx is cancelled. It is a lifecycle service: any
// other way of stopping is an error, so the agent exits rather than keep
// declaring a capability it no longer has.
func (s *Sink) Serve(ctx context.Context) error {
	if s.listener == nil {
		return errors.New("audit receiver is not listening")
	}
	failed := make(chan error, 1)
	go func() { failed <- s.server.Serve(s.listener) }()
	select {
	case <-ctx.Done():
		_ = s.Close()
		<-failed
		return nil
	case err := <-s.broken:
		_ = s.Close()
		<-failed
		return err
	case err := <-failed:
		_ = s.Close()
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			err = errors.New("server stopped")
		}
		return fmt.Errorf("audit receiver stopped: %w", err)
	}
}

// Close stops the receiver and removes the socket file.
func (s *Sink) Close() error {
	err := s.server.Close()
	if s.listener != nil {
		_ = s.listener.Close()
		_ = os.Remove(s.path)
	}
	return err
}

// SetRoster replaces the snapshot events are attributed against: the email of
// every client of the DEPLOYED roster, and the ID of every rule of the deployed
// policy, and the egress snapshot of that deployment. It is a snapshot and not a
// delta, and the latest deployment replaces the one before it.
func (s *Sink) SetRoster(subjects map[string]protocol.SubjectKey, ruleIDs []string, egress Egress) {
	copied := make(map[string]protocol.SubjectKey, len(subjects))
	for email, subject := range subjects {
		copied[email] = subject
	}
	rules := make(map[string]struct{}, len(ruleIDs))
	for _, id := range ruleIDs {
		rules[id] = struct{}{}
	}
	s.mu.Lock()
	s.subjects, s.rules, s.egress = copied, rules, newEgressSet(egress)
	s.stagedUsers, s.stagedRules, s.stagedEgress = nil, nil, egressSet{}
	s.mu.Unlock()
}

// StageRoster is given the roster and rules of a deployment that is about to
// start, BEFORE the core it configures does. Until the deployment is confirmed
// (SetRoster) or abandoned (DiscardStaged) an event is attributed against the
// deployed snapshot and this one together, the staged one first: a core sends
// hits the moment it is up, and attributing them to the roster it replaced would
// record them as unmatched.
func (s *Sink) StageRoster(subjects map[string]protocol.SubjectKey, ruleIDs []string, egress Egress) {
	copied := make(map[string]protocol.SubjectKey, len(subjects))
	for email, subject := range subjects {
		copied[email] = subject
	}
	rules := make(map[string]struct{}, len(ruleIDs))
	for _, id := range ruleIDs {
		rules[id] = struct{}{}
	}
	s.mu.Lock()
	s.stagedUsers, s.stagedRules, s.stagedEgress = copied, rules, newEgressSet(egress)
	s.mu.Unlock()
}

// DiscardStaged drops a staged snapshot whose deployment failed, leaving the
// deployed one.
func (s *Sink) DiscardStaged() {
	s.mu.Lock()
	s.stagedUsers, s.stagedRules, s.stagedEgress = nil, nil, egressSet{}
	s.mu.Unlock()
}

// webhookEvent is the part of Xray's event the receiver reads. The source
// address is in the event and is deliberately not a field here.
type webhookEvent struct {
	Email       string `json:"email"`
	Destination string `json:"destination"`
	OutboundTag string `json:"outboundTag"`
}

// usageEvent is the part of Xray's event the usage path reads: the account and
// the destination, and nothing else. The source address is in the event and is
// deliberately not a field here, and neither is the outbound: a usage event
// names no rule.
type usageEvent struct {
	Email       string `json:"email"`
	Destination string `json:"destination"`
}

// serveHTTP wraps the handler so that a panic is not swallowed. net/http would
// recover it, log it and carry on, and a receiver whose handler panics on every
// event would keep declaring a capability while recording nothing. The failure
// is handed to Serve, which returns it so that the agent exits. Only the type of
// the panic value is kept: it may be built from the event.
func (s *Sink) serveHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if recovered := recover(); recovered != nil {
			select {
			case s.broken <- fmt.Errorf("audit receiver stopped: handler panic (%T)", recovered):
			default:
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}()
	s.handle(w, r)
}

func (s *Sink) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != HitPath && r.URL.Path != UsagePath {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get(HeaderName)), s.token) != 1 {
		// A refused request is counted as Unmatched too, and not only in Stats:
		// Unmatched is what the next batch carries to the panel, and a node
		// whose webhook token no longer matches (a core still running an old
		// configuration, say) is losing hits, which the panel should be able to
		// see rather than read as a quiet node.
		s.unauthorized.Add(1)
		s.countUnmatched()
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		s.countUnmatched()
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "bad request", http.StatusBadRequest)
		}
		return
	}
	if r.URL.Path == UsagePath {
		var event usageEvent
		if err := json.Unmarshal(body, &event); err != nil {
			s.countUnmatched()
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		s.recordUsage(event)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var event webhookEvent
	if err := json.Unmarshal(body, &event); err != nil {
		s.countUnmatched()
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.record(event)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Sink) countUnmatched() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unmatched++
}

// lookup resolves a rule and an email against the deployed and staged
// snapshots, and returns the egress snapshot of the one the rule is in: the
// staged one first, because it is the core that was just started that sends the
// event. While a deployment is being validated or rolled back the previous core
// still runs, so a link suffix the staged snapshot does not know but the
// deployed one does is read with the deployed snapshot rather than dropped.
// Every locked section uses defer, so a panic recovered by the handler wrapper
// can never leave the mutex held and hang Take.
func (s *Sink) lookup(rule, email, suffix string, split bool) (subject protocol.SubjectKey, deployed, known bool, egress egressSet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, inStaged := s.stagedRules[rule]
	_, inCurrent := s.rules[rule]
	switch {
	case inStaged && inCurrent && split && !s.stagedEgress.accepts(suffix) && s.egress.accepts(suffix):
		deployed, egress = true, s.egress
	case inStaged:
		deployed, egress = true, s.stagedEgress
	case inCurrent:
		deployed, egress = true, s.egress
	}
	subject, known = s.stagedUsers[email]
	if !known {
		subject, known = s.subjects[email]
	}
	return subject, deployed, known, egress
}

func (s *Sink) add(hit protocol.AuditHit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addLocked(hit)
}

// record turns one event into at most one counted key. It is a few map
// operations and does no I/O: Xray holds a goroutine per event until this
// returns.
func (s *Sink) record(event webhookEvent) {
	now := s.now().UTC()
	var action, rule string
	switch {
	case strings.HasPrefix(event.OutboundTag, outboundDenyPrefix):
		action, rule = protocol.AuditActionBlock, strings.TrimPrefix(event.OutboundTag, outboundDenyPrefix)
	case strings.HasPrefix(event.OutboundTag, outboundWatchPrefix):
		action, rule = protocol.AuditActionObserve, strings.TrimPrefix(event.OutboundTag, outboundWatchPrefix)
	default:
		s.countUnmatched()
		return
	}
	// A rule split for a link's listeners routes to "<outbound>~lnk_<id>": the
	// rule is what precedes the suffix, and the suffix names the link the
	// connection left through (or, for a block, would have). It is reported
	// only when the deployment asks for it.
	suffix, split := "", false
	if before, after, found := strings.Cut(rule, "~"); found {
		rule, suffix, split = before, after, true
	}
	dest, port, ok := splitDestination(event.Destination)
	if !ok {
		s.countUnmatched()
		return
	}
	trial := action == protocol.AuditActionObserve && strings.HasPrefix(rule, "g")
	hit := protocol.AuditHit{
		Hour:   now.Truncate(time.Hour).UnixMilli(),
		RuleID: rule, Action: action, Dest: dest, Port: port,
		Count: 1, FirstMS: now.UnixMilli(), LastMS: now.UnixMilli(),
	}
	if trial {
		hit.Dest, hit.Port = registrable(dest), 0
	}

	if s.beforeRecord != nil {
		s.beforeRecord()
	}
	// The lookups are the only thing done under the lock: validation is
	// computed outside it, because Xray holds a goroutine per event until this
	// returns and every event contends for the same mutex.
	subject, deployed, known, egress := s.lookup(rule, event.Email, suffix, split)
	if !deployed || !known {
		// A trial row names no one, but an event from an account this node does
		// not hold is not one of the group's either.
		s.countUnmatched()
		return
	}
	if egress.enabled && split {
		// A suffix this entry has no link for is not one this deployment
		// compiled: it is not trusted into a row.
		link := protocol.LinkKey(suffix)
		if _, ok := egress.links[link]; !ok {
			s.countUnmatched()
			return
		}
		hit.Egress = link
	}
	if !trial {
		hit.Subject = subject
	}
	if err := protocol.ValidateAuditHit(hit); err != nil {
		s.countUnmatched()
		return
	}
	s.add(hit)
}

// recordUsage turns one let-through connection into at most one counted key. Like
// record it is a few map operations and no I/O. The site is the registrable
// domain of the destination, the same fold the trial rows use, so the port is
// not kept and an address becomes "(ip)".
func (s *Sink) recordUsage(event usageEvent) {
	now := s.now().UTC()
	dest, _, ok := splitDestination(event.Destination)
	if !ok {
		s.countUnmatched()
		return
	}
	row := protocol.AuditUsage{Hour: now.Truncate(time.Hour).UnixMilli(), Site: registrable(dest), Count: 1}
	subject, _, known, _ := s.lookup("", event.Email, "", false)
	if !known {
		s.countUnmatched()
		return
	}
	row.Subject = subject
	if err := protocol.ValidateAuditUsage(row); err != nil {
		s.countUnmatched()
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addUsageLocked(row)
}

// addUsageLocked adds one row. A new key in a full table is dropped and its
// events counted; an existing key always counts, and saturates.
func (s *Sink) addUsageLocked(row protocol.AuditUsage) {
	key := usageKey{row.Hour, row.Subject, row.Site}
	count, exists := s.usage[key]
	if !exists && len(s.usage) >= s.maxUsageKeys {
		s.droppedUsage += uint64(row.Count)
		return
	}
	if sum := uint64(count) + uint64(row.Count); sum > uint64(^uint32(0)) {
		count = ^uint32(0)
	} else {
		count = uint32(sum)
	}
	s.usage[key] = count
}

// addLocked folds one row into the table it belongs to. A new key in a full
// table is dropped and its events counted; an existing key always counts.
func (s *Sink) addLocked(hit protocol.AuditHit) {
	if isTrial(hit) {
		key := trialKey{hit.Hour, hit.RuleID, hit.Dest, hit.Egress}
		entry, exists := s.trial[key]
		if !exists && len(s.trial) >= s.maxTrialKeys {
			s.droppedTrial += uint64(hit.Count)
			return
		}
		s.trial[key] = merge(entry, hit)
		return
	}
	key := hitKey{hit.Hour, hit.RuleID, hit.Action, hit.Subject, hit.Dest, hit.Port, hit.Egress}
	entry, exists := s.hits[key]
	if !exists && len(s.hits) >= s.maxHitKeys {
		s.droppedHits += uint64(hit.Count)
		return
	}
	s.hits[key] = merge(entry, hit)
}

func isTrial(hit protocol.AuditHit) bool {
	return hit.Action == protocol.AuditActionObserve && strings.HasPrefix(hit.RuleID, "g")
}

func merge(entry counted, hit protocol.AuditHit) counted {
	if !entry.set {
		return counted{count: hit.Count, firstMS: hit.FirstMS, lastMS: hit.LastMS, set: true}
	}
	if sum := uint64(entry.count) + uint64(hit.Count); sum > uint64(^uint32(0)) {
		entry.count = ^uint32(0)
	} else {
		entry.count = uint32(sum)
	}
	if hit.FirstMS < entry.firstMS {
		entry.firstMS = hit.FirstMS
	}
	if hit.LastMS > entry.lastMS {
		entry.lastMS = hit.LastMS
	}
	return entry
}

// Take removes and returns everything aggregated so far, with the counters,
// which restart from zero. Rows are ordered oldest hour first.
func (s *Sink) Take() Taken {
	s.mu.Lock()
	hits, trial, usage := s.hits, s.trial, s.usage
	taken := Taken{DroppedHits: s.droppedHits, DroppedTrial: s.droppedTrial, DroppedUsage: s.droppedUsage, Unmatched: s.unmatched}
	s.hits, s.trial, s.usage = map[hitKey]counted{}, map[trialKey]counted{}, map[usageKey]uint32{}
	s.droppedHits, s.droppedTrial, s.droppedUsage, s.unmatched = 0, 0, 0, 0
	s.mu.Unlock()

	taken.Hits = make([]protocol.AuditHit, 0, len(hits)+len(trial))
	for key, entry := range hits {
		taken.Hits = append(taken.Hits, protocol.AuditHit{
			Hour: key.hour, RuleID: key.rule, Action: key.action, Subject: key.subject, Dest: key.dest, Port: key.port, Egress: key.egress,
			Count: entry.count, FirstMS: entry.firstMS, LastMS: entry.lastMS,
		})
	}
	for key, entry := range trial {
		taken.Hits = append(taken.Hits, protocol.AuditHit{
			Hour: key.hour, RuleID: key.rule, Action: protocol.AuditActionObserve, Dest: key.dest, Egress: key.egress,
			Count: entry.count, FirstMS: entry.firstMS, LastMS: entry.lastMS,
		})
	}
	SortHits(taken.Hits)
	taken.Usage = make([]protocol.AuditUsage, 0, len(usage))
	for key, count := range usage {
		taken.Usage = append(taken.Usage, protocol.AuditUsage{Hour: key.hour, Subject: key.subject, Site: key.site, Count: count})
	}
	SortUsage(taken.Usage)
	return taken
}

// SortUsage orders rows oldest hour first, then by subject and site, so a batch
// is deterministic.
func SortUsage(usage []protocol.AuditUsage) {
	sort.Slice(usage, func(i, j int) bool {
		a, b := usage[i], usage[j]
		switch {
		case a.Hour != b.Hour:
			return a.Hour < b.Hour
		case a.Subject != b.Subject:
			return a.Subject < b.Subject
		}
		return a.Site < b.Site
	})
}

// SortHits orders rows oldest hour first, then by the rest of the key, so a
// batch is deterministic.
func SortHits(hits []protocol.AuditHit) {
	sort.Slice(hits, func(i, j int) bool {
		a, b := hits[i], hits[j]
		switch {
		case a.Hour != b.Hour:
			return a.Hour < b.Hour
		case a.RuleID != b.RuleID:
			return a.RuleID < b.RuleID
		case a.Action != b.Action:
			return a.Action < b.Action
		case a.Subject != b.Subject:
			return a.Subject < b.Subject
		case a.Dest != b.Dest:
			return a.Dest < b.Dest
		case a.Port != b.Port:
			return a.Port < b.Port
		}
		return a.Egress < b.Egress
	})
}

// Return gives back what a Take removed and was not sent: rows and counters.
func (s *Sink) Return(taken Taken) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, hit := range taken.Hits {
		s.addLocked(hit)
	}
	for _, row := range taken.Usage {
		s.addUsageLocked(row)
	}
	s.droppedHits += taken.DroppedHits
	s.droppedTrial += taken.DroppedTrial
	s.droppedUsage += taken.DroppedUsage
	s.unmatched += taken.Unmatched
}

// splitDestination reads Xray's "host:port" (IPv6 in brackets) and normalises
// the host. It reports false for anything that is not a usable destination.
func splitDestination(destination string) (string, uint16, bool) {
	host, portText, err := net.SplitHostPort(destination)
	if err != nil || host == "" {
		return "", 0, false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", 0, false
	}
	normalised, ok := normaliseHost(host)
	if !ok {
		return "", 0, false
	}
	return normalised, uint16(port), true
}

// normaliseHost is the spelling the protocol accepts: lower case, punycode, no
// trailing dot, and an address in its canonical form, unmapped.
func normaliseHost(host string) (string, bool) {
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Zone() != "" {
			return "", false
		}
		return address.Unmap().String(), true
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", false
	}
	if isASCII(host) {
		return strings.ToLower(host), true
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil || ascii == "" {
		return "", false
	}
	return strings.ToLower(ascii), true
}

func isASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			return false
		}
	}
	return true
}

// registrable folds a normalised destination to its registrable domain: an
// address becomes "(ip)", and a host with none (a single label, or a public
// suffix itself) stays as it is. It is computed here and nowhere else, because
// two public suffix lists of different ages would disagree.
func registrable(dest string) string {
	if _, err := netip.ParseAddr(dest); err == nil {
		return protocol.AuditSiteIP
	}
	site, err := publicsuffix.EffectiveTLDPlusOne(dest)
	if err != nil {
		return dest
	}
	return site
}

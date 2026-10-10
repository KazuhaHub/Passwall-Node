// Package audit owns transient, separately bounded audit aggregation.
package audit

import (
	"cmp"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/KazuhaHub/passwall-protocol/protocol"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
	"math"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Snapshot struct {
	Collect  string
	Revision uint64
	Subjects map[string]protocol.SubjectKey
	Rules    map[string]protocol.RuleAction
}
type Stats struct {
	StaleRevision, Unclassified                    uint64
	ExpiredRows, ExpiredEvents, OffRows, OffEvents uint64
	InvalidRows, InvalidEvents                     uint64
}
type Batch struct {
	Observation               *protocol.AuditObservation
	Frozen                    bool
	HitsTrimmed, UsageTrimmed int
}
type hitKey struct {
	rule    string
	subject protocol.SubjectKey
	dest    string
	port    uint16
}
type usageKey struct {
	subject protocol.SubjectKey
	site    string
}
type bucket struct {
	hits               map[hitKey]protocol.AuditHit
	usage              map[usageKey]protocol.AuditUsage
	dropped, unmatched uint64
}
type lane struct {
	buckets     map[int64]*bucket
	pending     *protocol.AuditObservation
	keys, limit int
}

// The key limit covers all retained hours in a class. Pending is separately
// bounded to one immutable subtree per class; no low-priority state uses the
// block lane's capacity. All state, including counters, is lost on restart.
type Collector struct {
	mu       sync.Mutex
	now      func() time.Time
	newID    func() (string, error)
	snapshot Snapshot
	lanes    map[string]*lane
	slot     int
	stats    Stats
}

var slots = [...]string{"block", "block", "block", "block", "observe", "trial", "usage"}

func New(now func() time.Time) *Collector {
	if now == nil {
		now = time.Now
	}
	c := &Collector{now: now, newID: func() (string, error) {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return "", err
		}
		return hex.EncodeToString(id[:]), nil
	}}
	c.reset()
	return c
}

func (c *Collector) reset() {
	c.lanes = map[string]*lane{}
	for kind, limit := range map[string]int{"block": 20_000, "observe": 10_000, "trial": 10_000, "usage": 50_000} {
		c.lanes[kind] = &lane{buckets: map[int64]*bucket{}, limit: limit}
	}
	c.slot = 0
}

// SetSnapshot is called only after deployment persistence succeeds, or when
// restoring that confirmed deployment. Received candidates are not evidence.
// A revision transition clears every old lane, even if the mode is unchanged.
func (c *Collector) SetSnapshot(s Snapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s.Revision != c.snapshot.Revision || s.Collect != c.snapshot.Collect {
		for _, l := range c.lanes {
			for _, b := range l.buckets {
				c.addOff(b)
			}
			if l.pending != nil {
				rows, events := observationCounts(l.pending)
				c.stats.OffRows = add(c.stats.OffRows, rows)
				c.stats.OffEvents = add(c.stats.OffEvents, events)
			}
		}
		c.reset()
	}
	copy := Snapshot{Collect: s.Collect, Revision: s.Revision, Subjects: map[string]protocol.SubjectKey{}, Rules: map[string]protocol.RuleAction{}}
	for email, subject := range s.Subjects {
		copy.Subjects[email] = subject
	}
	for rule, action := range s.Rules {
		copy.Rules[rule] = action
	}
	c.snapshot = copy
}

// AddHit never retains email, source IP or the original webhook. Trial is
// collapsed to group/site before its key or row enters any retained structure.
func (c *Collector) AddHit(revision uint64, email, destination, tag string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.acceptRevision(revision) {
		return
	}
	kind, rule, action := classify(tag)
	if kind == "" {
		c.stats.Unclassified = add(c.stats.Unclassified, 1)
		return
	}
	now := c.now().UnixMilli()
	b := c.currentBucket(kind, now)
	if b == nil {
		return
	}
	expected, exists := c.snapshot.Rules[rule]
	subject, known := c.snapshot.Subjects[email]
	if !exists || expected != action || !known {
		b.unmatched = add(b.unmatched, 1)
		return
	}
	if _, err := subject.RowID(); err != nil {
		b.unmatched = add(b.unmatched, 1)
		return
	}
	host, port, ok := normalizedDestination(destination)
	if !ok {
		b.unmatched = add(b.unmatched, 1)
		return
	}
	if kind == "trial" {
		host, ok = site(host)
		if !ok {
			b.unmatched = add(b.unmatched, 1)
			return
		}
		subject, port = "", 0
	}
	hour := now / protocol.AuditHourMS * protocol.AuditHourMS
	hit := protocol.AuditHit{Hour: hour, RuleID: rule, Action: string(action), Subject: subject, Dest: host, Port: port, Count: 1, FirstMS: now, LastMS: now}
	if err := protocol.ValidateAuditObservation(protocol.AuditObservation{BatchID: strings.Repeat("0", 32), Kind: kind, Hour: hour, CollectRevision: revision, Hits: []protocol.AuditHit{hit}}); err != nil {
		b.unmatched = add(b.unmatched, 1)
		return
	}
	key := hitKey{rule, subject, host, port}
	if old, found := b.hits[key]; found {
		if old.Count == math.MaxUint32 {
			b.dropped = add(b.dropped, 1)
			return
		}
		old.Count++
		old.FirstMS = min(old.FirstMS, now)
		old.LastMS = max(old.LastMS, now)
		b.hits[key] = old
		return
	}
	if c.lanes[kind].keys == c.lanes[kind].limit {
		b.dropped = add(b.dropped, 1)
		return
	}
	b.hits[key] = hit
	c.lanes[kind].keys++
}

// AddUsage is the validated ingestion entry for the later access-log filter.
// Its caller must already exclude denied/rejected connections. Keeping this
// entry does not advertise audit.usage.v1 or enable an access log.
func (c *Collector) AddUsage(revision uint64, email, destination string) {
	c.AddUsageAt(revision, email, destination, c.now())
}

// AddUsageAt retains the receive time across the bounded access-log queue;
// parsing after an hour boundary must not move a connection into another hour.
func (c *Collector) AddUsageAt(revision uint64, email, destination string, received time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.acceptRevision(revision) || c.snapshot.Collect != "hits_and_usage" {
		return
	}
	now := received.UnixMilli()
	b := c.receivedBucket("usage", now, 1, 1)
	if b == nil {
		return
	}
	subject, found := c.snapshot.Subjects[email]
	destination = strings.TrimPrefix(strings.TrimPrefix(destination, "tcp:"), "udp:")
	host, _, ok := normalizedDestination(destination)
	if !found || !ok {
		b.unmatched = add(b.unmatched, 1)
		return
	}
	host, ok = site(host)
	if !ok {
		b.unmatched = add(b.unmatched, 1)
		return
	}
	hour := now / protocol.AuditHourMS * protocol.AuditHourMS
	row := protocol.AuditUsage{Hour: hour, Subject: subject, Site: host, Count: 1}
	if err := protocol.ValidateAuditObservation(protocol.AuditObservation{BatchID: strings.Repeat("0", 32), Kind: "usage", Hour: hour, CollectRevision: revision, Usage: []protocol.AuditUsage{row}}); err != nil {
		b.unmatched = add(b.unmatched, 1)
		return
	}
	key := usageKey{subject, host}
	if old, found := b.usage[key]; found {
		if old.Count == math.MaxUint32 {
			b.dropped = add(b.dropped, 1)
			return
		}
		old.Count++
		b.usage[key] = old
		return
	}
	if c.lanes["usage"].keys == c.lanes["usage"].limit {
		b.dropped = add(b.dropped, 1)
		return
	}
	b.usage[key] = row
	c.lanes["usage"].keys++
}

func (c *Collector) AddLoss(kind string, revision, dropped, unmatched uint64) {
	c.AddLossAt(kind, revision, dropped, unmatched, c.now())
}

func (c *Collector) AddLossAt(kind string, revision, dropped, unmatched uint64, received time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if dropped == 0 && unmatched == 0 {
		return
	}
	if !c.acceptRevision(revision) || c.lanes[kind] == nil || kind == "usage" && c.snapshot.Collect != "hits_and_usage" {
		return
	}
	if b := c.receivedBucket(kind, received.UnixMilli(), 0, add(dropped, unmatched)); b != nil {
		b.dropped = add(b.dropped, dropped)
		b.unmatched = add(b.unmatched, unmatched)
	}
}

func (c *Collector) receivedBucket(kind string, received int64, rows, events uint64) *bucket {
	now := c.now().UnixMilli()
	c.expire(now)
	hour := received / protocol.AuditHourMS * protocol.AuditHourMS
	if received > 0 && now > hour && now-hour > protocol.MaxAuditReplayAgeMS {
		c.stats.ExpiredRows = add(c.stats.ExpiredRows, rows)
		c.stats.ExpiredEvents = add(c.stats.ExpiredEvents, events)
		return nil
	}
	if received > now && received-now > protocol.MaxAuditFutureSkewMS {
		c.stats.Unclassified = add(c.stats.Unclassified, events)
		return nil
	}
	return c.bucketAt(kind, received)
}

func (c *Collector) acceptRevision(revision uint64) bool {
	if revision == 0 || revision != c.snapshot.Revision {
		c.stats.StaleRevision = add(c.stats.StaleRevision, 1)
		return false
	}
	return c.snapshot.Collect == "hits" || c.snapshot.Collect == "hits_and_usage"
}

func (c *Collector) currentBucket(kind string, now int64) *bucket {
	c.expire(now)
	return c.bucketAt(kind, now)
}

func (c *Collector) bucketAt(kind string, now int64) *bucket {
	if now <= 0 {
		c.stats.Unclassified = add(c.stats.Unclassified, 1)
		return nil
	}
	hour := now / protocol.AuditHourMS * protocol.AuditHourMS
	if hour == 0 {
		c.stats.Unclassified = add(c.stats.Unclassified, 1)
		return nil
	}
	l := c.lanes[kind]
	if b := l.buckets[hour]; b != nil {
		return b
	}
	// Clock changes must not turn loss-only buckets into unbounded state.
	if len(l.buckets) >= 50 {
		oldest := int64(math.MaxInt64)
		for h := range l.buckets {
			oldest = min(oldest, h)
		}
		c.expireBucket(l, oldest)
	}
	b := &bucket{hits: map[hitKey]protocol.AuditHit{}, usage: map[usageKey]protocol.AuditUsage{}}
	l.buckets[hour] = b
	return b
}

// Next advances the seven-slot schedule even when the previous report failed.
// maxBytes is the remaining wire allowance for a NEW batch. Already frozen
// pending ignores that allowance: the report builder must defer it as a whole.
// Rows that do not fit remain in the original hour; trimming is not loss.
func (c *Collector) Next(maxBytes int) (Batch, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expire(c.now().UnixMilli())
	position := c.slot
	c.slot = (c.slot + 1) % len(slots)
	available := func(kind string) bool { l := c.lanes[kind]; return l.pending != nil || len(l.buckets) > 0 }
	kind := slots[position]
	if !available(kind) {
		kind = ""
		if available("block") {
			kind = "block"
		} else {
			for offset := 1; offset < len(slots); offset++ {
				candidate := slots[(position+offset)%len(slots)]
				if available(candidate) {
					kind = candidate
					break
				}
			}
		}
	}
	if kind == "" {
		return Batch{}, nil
	}
	l := c.lanes[kind]
	if l.pending != nil {
		return Batch{Observation: clone(l.pending), Frozen: true}, nil
	}
	if maxBytes <= 0 {
		return Batch{}, nil
	}
	maxBytes = min(maxBytes, protocol.MaxAuditObservationBytes)
	hour := int64(math.MaxInt64)
	for h := range l.buckets {
		hour = min(hour, h)
	}
	b := l.buckets[hour]
	id, err := c.newID()
	if err != nil {
		return Batch{}, err
	}
	o := &protocol.AuditObservation{BatchID: id, Kind: kind, Hour: hour, CollectRevision: c.snapshot.Revision, Dropped: b.dropped, Unmatched: b.unmatched}
	base, err := json.Marshal(o)
	if err != nil {
		return Batch{}, err
	}
	size := len(base)
	if size > maxBytes {
		return Batch{}, nil
	}
	if kind == "usage" {
		rows := make([]protocol.AuditUsage, 0, len(b.usage))
		for _, row := range b.usage {
			rows = append(rows, row)
		}
		slices.SortFunc(rows, func(a, b protocol.AuditUsage) int {
			if n := cmp.Compare(a.Subject, b.Subject); n != 0 {
				return n
			}
			return cmp.Compare(a.Site, b.Site)
		})
		for _, row := range rows {
			encoded, err := json.Marshal(row)
			if err != nil {
				return Batch{}, err
			}
			extra := len(encoded) + 1
			if len(o.Usage) == 0 {
				extra = len(encoded) + len(`,"usage":[]`)
			}
			if len(o.Usage) == protocol.MaxAuditUsage || size+extra > maxBytes {
				break
			}
			size += extra
			o.Usage = append(o.Usage, row)
		}
	} else {
		rows := make([]protocol.AuditHit, 0, len(b.hits))
		for _, row := range b.hits {
			rows = append(rows, row)
		}
		slices.SortFunc(rows, func(a, b protocol.AuditHit) int {
			if n := cmp.Compare(a.RuleID, b.RuleID); n != 0 {
				return n
			}
			if n := cmp.Compare(a.Subject, b.Subject); n != 0 {
				return n
			}
			if n := cmp.Compare(a.Dest, b.Dest); n != 0 {
				return n
			}
			return cmp.Compare(a.Port, b.Port)
		})
		for _, row := range rows {
			encoded, err := json.Marshal(row)
			if err != nil {
				return Batch{}, err
			}
			extra := len(encoded) + 1
			if len(o.Hits) == 0 {
				extra = len(encoded) + len(`,"hits":[]`)
			}
			if len(o.Hits) == protocol.MaxAuditHits || size+extra > maxBytes {
				break
			}
			size += extra
			o.Hits = append(o.Hits, row)
		}
	}
	if len(o.Hits) == 0 && len(o.Usage) == 0 && o.Dropped == 0 && o.Unmatched == 0 {
		return Batch{}, nil
	}
	if err := protocol.ValidateAuditObservation(*o); err != nil {
		return Batch{}, err
	}
	result := Batch{Observation: clone(o), HitsTrimmed: len(b.hits) - len(o.Hits), UsageTrimmed: len(b.usage) - len(o.Usage)}
	for _, row := range o.Hits {
		delete(b.hits, hitKey{row.RuleID, row.Subject, row.Dest, row.Port})
	}
	for _, row := range o.Usage {
		delete(b.usage, usageKey{row.Subject, row.Site})
	}
	l.keys -= len(o.Hits) + len(o.Usage)
	b.dropped = 0
	b.unmatched = 0
	if len(b.hits) == 0 && len(b.usage) == 0 {
		delete(l.buckets, hour)
	}
	l.pending = o
	return result, nil
}

// Acknowledge is called only with the kind and ID actually serialized into a
// report whose control response validated. Delivery does not prove persistence.
func (c *Collector) Acknowledge(kind, id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	l := c.lanes[kind]
	if l == nil || l.pending == nil || l.pending.BatchID != id {
		return false
	}
	l.pending = nil
	return true
}

// DiscardInvalid is the last safety valve for a corrupted frozen subtree. It
// must not stall control synchronization or relabel the bad data into a retry.
func (c *Collector) DiscardInvalid(kind, id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	l := c.lanes[kind]
	if l == nil || l.pending == nil || l.pending.BatchID != id {
		return
	}
	rows, events := observationCounts(l.pending)
	c.stats.InvalidRows = add(c.stats.InvalidRows, rows)
	c.stats.InvalidEvents = add(c.stats.InvalidEvents, events)
	l.pending = nil
}

func (c *Collector) Stats() Stats { c.mu.Lock(); defer c.mu.Unlock(); return c.stats }

func (c *Collector) expire(now int64) {
	if now <= 0 {
		return
	}
	for _, l := range c.lanes {
		for hour := range l.buckets {
			if now > hour && now-hour > protocol.MaxAuditReplayAgeMS {
				c.expireBucket(l, hour)
			}
		}
		if l.pending != nil && now > l.pending.Hour && now-l.pending.Hour > protocol.MaxAuditReplayAgeMS {
			rows, events := observationCounts(l.pending)
			c.stats.ExpiredRows = add(c.stats.ExpiredRows, rows)
			c.stats.ExpiredEvents = add(c.stats.ExpiredEvents, events)
			l.pending = nil
		}
	}
}

func (c *Collector) expireBucket(l *lane, hour int64) {
	b := l.buckets[hour]
	rows, events := bucketCounts(b)
	c.stats.ExpiredRows = add(c.stats.ExpiredRows, rows)
	c.stats.ExpiredEvents = add(c.stats.ExpiredEvents, events)
	l.keys -= len(b.hits) + len(b.usage)
	delete(l.buckets, hour)
}
func (c *Collector) addOff(b *bucket) {
	rows, events := bucketCounts(b)
	c.stats.OffRows = add(c.stats.OffRows, rows)
	c.stats.OffEvents = add(c.stats.OffEvents, events)
}
func bucketCounts(b *bucket) (uint64, uint64) {
	events := add(b.dropped, b.unmatched)
	for _, row := range b.hits {
		events = add(events, uint64(row.Count))
	}
	for _, row := range b.usage {
		events = add(events, uint64(row.Count))
	}
	return uint64(len(b.hits) + len(b.usage)), events
}
func observationCounts(o *protocol.AuditObservation) (uint64, uint64) {
	events := add(o.Dropped, o.Unmatched)
	for _, row := range o.Hits {
		events = add(events, uint64(row.Count))
	}
	for _, row := range o.Usage {
		events = add(events, uint64(row.Count))
	}
	return uint64(len(o.Hits) + len(o.Usage)), events
}
func add(a, b uint64) uint64 {
	if b > math.MaxUint64-a {
		return math.MaxUint64
	}
	return a + b
}
func clone(o *protocol.AuditObservation) *protocol.AuditObservation {
	copy := *o
	copy.Hits = slices.Clone(o.Hits)
	copy.Usage = slices.Clone(o.Usage)
	return &copy
}

func classify(tag string) (kind, rule string, action protocol.RuleAction) {
	if strings.HasPrefix(tag, "psp-deny-") {
		return "block", strings.TrimPrefix(tag, "psp-deny-"), protocol.RuleBlock
	}
	if strings.HasPrefix(tag, "psp-watch-p") {
		return "observe", strings.TrimPrefix(tag, "psp-watch-"), protocol.RuleObserve
	}
	if strings.HasPrefix(tag, "psp-watch-g") && !strings.Contains(strings.TrimPrefix(tag, "psp-watch-g"), "x") {
		return "trial", strings.TrimPrefix(tag, "psp-watch-"), protocol.RuleObserve
	}
	return "", "", ""
}
func normalizedDestination(destination string) (string, uint16, bool) {
	if len(destination) > 4096 {
		return "", 0, false
	}
	host, port, err := net.SplitHostPort(destination)
	if err != nil {
		return "", 0, false
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return "", 0, false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return "", 0, false
		}
		return addr.String(), uint16(n), true
	}
	host = strings.TrimSuffix(host, ".")
	// The protocol permits ASCII underscores. Apply Lookup only to IDNs;
	// applying its DNS-label restrictions to ASCII would silently lose hits
	// for names the wire contract explicitly accepts.
	if strings.IndexFunc(host, func(r rune) bool { return r > 127 }) >= 0 {
		host, err = idna.Lookup.ToASCII(host)
		if err != nil {
			return "", 0, false
		}
	}
	if len(host) == 0 || len(host) > 253 {
		return "", 0, false
	}
	return strings.ToLower(host), uint16(n), true
}
func site(host string) (string, bool) {
	if _, err := netip.ParseAddr(host); err == nil {
		return "(ip)", true
	}
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	return domain, err == nil
}

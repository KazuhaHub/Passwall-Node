package core

import (
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"sort"
	"strconv"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// FrontLoopbackHost is where a fronted listener, and an incoming link a front
// routes to, is bound instead of its public address.
const FrontLoopbackHost = "127.0.0.1"

// FrontsRequireXray is why every other engine refuses a front.
const FrontsRequireXray = "SNI fronts require Xray"

// FrontTag is the core inbound tag of a front. It sits under TransitTagPrefix,
// so every parser that treats "transit-" as "not a user listener" treats a
// front as one: its connections are never a user's.
func FrontTag(key protocol.FrontKey) string { return TransitTagPrefix + string(key) }

// FrontTargetTag is the core outbound tag a front hands a target's connections
// to. A forward keeps ForwardTag, so that its counters keep their name (the
// forward has no inbound of its own behind a front); the other targets are
// named for the front.
func FrontTargetTag(front protocol.FrontKey, target protocol.FrontTarget) string {
	switch {
	case target.Forward != "":
		return ForwardTag(target.Forward)
	case target.Listener != "":
		return TransitTagPrefix + string(front) + "-" + string(target.Listener)
	case target.Link != "":
		return TransitTagPrefix + string(front) + "-" + string(target.Link)
	}
	return TransitTagPrefix + string(front) + "-external"
}

// FrontListener is what a compiler knows of one served listener when a front
// asks to move it: its public port, and why it cannot sit behind a front (empty
// when it can).
type FrontListener struct {
	Port  int
	Unfit string
}

// FrontSupport says the engine can compile fronts and describes the listeners
// it serves. A nil support (PlanTransit) refuses every front.
type FrontSupport struct {
	Listeners map[protocol.ListenerKey]FrontListener
	// Local lists this host's own addresses, for the check that an external
	// default is not the front itself. Nil reads the interfaces.
	Local func() []netip.Addr
}

// FrontObjects are the config-stream keys of a front and everything it fronts:
// the front itself first, then its listeners, forwards and links, sorted.
func FrontObjects(front protocol.Front) []string {
	set := map[string]bool{}
	for _, item := range front.Listeners {
		set[string(item.Listener)] = true
	}
	add := func(target protocol.FrontTarget) {
		switch {
		case target.Listener != "":
			set[string(target.Listener)] = true
		case target.Forward != "":
			set[string(target.Forward)] = true
		case target.Link != "":
			set[string(target.Link)] = true
		}
	}
	for _, route := range front.Routes {
		add(route.Target)
	}
	add(front.Default)
	delete(set, string(front.Key))
	out := make([]string, 0, len(set)+1)
	out = append(out, string(front.Key))
	rest := make([]string, 0, len(set))
	for key := range set {
		rest = append(rest, key)
	}
	sort.Strings(rest)
	return append(out, rest...)
}

// FrontError rejects a front and everything it fronts, as one cause.
func FrontError(front protocol.Front, err error) error {
	objects := FrontObjects(front)
	return &ObjectError{Stream: protocol.StreamConfig, Key: objects[0], Code: "core_config_rejected", Err: err, Related: objects[1:]}
}

// RejectFronts is the answer of an engine that cannot front: every front and
// everything it fronts is a config-object error. Failing the compile is the
// closed way to refuse: a fronted listener would otherwise be bound on its
// public port by itself, and the sharing the panel planned would not exist.
func RejectFronts(transit *protocol.Transit) error {
	if transit == nil || len(transit.Fronts) == 0 {
		return nil
	}
	set := map[string]bool{}
	for _, front := range transit.Fronts {
		for _, key := range FrontObjects(front) {
			set[key] = true
		}
	}
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	first := transit.Fronts[0].Key
	for _, front := range transit.Fronts {
		if front.Key < first {
			first = front.Key
		}
	}
	related := make([]string, 0, len(keys))
	for _, key := range keys {
		if key != string(first) {
			related = append(related, key)
		}
	}
	return &ObjectError{Stream: protocol.StreamConfig, Key: string(first), Code: "core_config_rejected",
		Err: errors.New(FrontsRequireXray), Related: related}
}

// frontedTargets maps every forward and link that some front routes to.
func frontedTargets(fronts []protocol.Front) (forwards map[protocol.ForwardKey]protocol.FrontKey, links map[protocol.LinkKey]protocol.FrontKey) {
	forwards = map[protocol.ForwardKey]protocol.FrontKey{}
	links = map[protocol.LinkKey]protocol.FrontKey{}
	add := func(front protocol.FrontKey, target protocol.FrontTarget) {
		if target.Forward != "" {
			forwards[target.Forward] = front
		}
		if target.Link != "" {
			links[target.Link] = front
		}
	}
	for _, front := range fronts {
		for _, route := range front.Routes {
			add(front.Key, route.Target)
		}
		add(front.Key, front.Default)
	}
	return forwards, links
}

// FrontedListenerKeys are the listeners the transit moves behind a front,
// whether or not the snapshot turns out to serve them: a compiler leaves them
// out of its public binds before it plans the transit.
func FrontedListenerKeys(transit *protocol.Transit) map[protocol.ListenerKey]bool {
	if transit == nil || len(transit.Fronts) == 0 {
		return nil
	}
	out := map[protocol.ListenerKey]bool{}
	for _, front := range transit.Fronts {
		for _, item := range front.Listeners {
			out[item.Listener] = true
		}
	}
	return out
}

// LocalAddresses lists the unicast addresses of this host's interfaces.
func LocalAddresses() []netip.Addr {
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, address := range interfaces {
		var ip net.IP
		switch value := address.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		}
		if addr, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, addr.Unmap())
		}
	}
	return out
}

// externalIsThisFront reports whether an external default points back at the
// front itself: an IP literal that is one of this host's own addresses, on the
// front's port, where the front listens on every address or on that one. The
// connection would come straight back into the front. A public address the
// host only owns through NAT is on no interface and cannot be seen from here:
// the panel, which knows the address the server is seen at, must check it.
func externalIsThisFront(front protocol.Front, local []netip.Addr) bool {
	external := front.Default.External
	if external == nil || external.Port != front.Port {
		return false
	}
	host, err := netip.ParseAddr(external.Host)
	if err != nil {
		return false
	}
	host = host.Unmap()
	// Any loopback address (127.0.0.0/8, ::1) is this host's, whether or not an
	// interface lists it.
	isLocal := host.IsLoopback()
	for _, address := range local {
		if address.Unmap() == host {
			isLocal = true
			break
		}
	}
	if !isLocal {
		return false
	}
	if front.Listen == "" {
		return true
	}
	listen, err := netip.ParseAddr(front.Listen)
	if err != nil {
		return true
	}
	listen = listen.Unmap()
	return listen.IsUnspecified() && (!listen.Is4() || host.Is4()) || listen == host
}

// planFrontBinds is the first half of planning fronts: it checks that the
// listeners can sit behind each front and claims the front's own bind and the
// loopback port of each fronted listener. claim is PlanTransit's bind check;
// reserved the binds only the core owns (its API), which a loopback port must
// not take either.
func planFrontBinds(plan *TransitPlan, transit *protocol.Transit, support FrontSupport,
	claim func(owner, listen string, port int) error, reserved []string) (map[int]bool, error) {
	fronts := append([]protocol.Front(nil), transit.Fronts...)
	sort.Slice(fronts, func(i, j int) bool { return fronts[i].Key < fronts[j].Key })
	reservedPorts := map[int]bool{}
	for _, bind := range reserved {
		if _, port, ok := splitBindPort(bind); ok {
			reservedPorts[port] = true
		}
	}
	local := support.Local
	if local == nil {
		local = LocalAddresses
	}
	var addresses []netip.Addr
	for _, front := range fronts {
		if front.Default.External != nil && addresses == nil {
			addresses = local()
		}
		for _, item := range front.Listeners {
			info, served := support.Listeners[item.Listener]
			switch {
			case !served:
				return nil, FrontError(front, fmt.Errorf("front %s fronts listener %s, which this node does not serve (it is disabled or absent)", front.Key, item.Listener))
			case info.Unfit != "":
				return nil, FrontError(front, fmt.Errorf("front %s fronts listener %s, which %s", front.Key, item.Listener, info.Unfit))
			case info.Port != front.Port:
				return nil, FrontError(front, fmt.Errorf("front %s fronts listener %s on port %d, but its own port is %d", front.Key, item.Listener, front.Port, info.Port))
			}
		}
		if externalIsThisFront(front, addresses) {
			external := front.Default.External
			return nil, FrontError(front, fmt.Errorf("front %s default %s:%d is this host's own address on the front's port; relaying there loops back into the front", front.Key, external.Host, external.Port))
		}
		if err := claim(string(front.Key), front.Listen, front.Port); err != nil {
			return nil, FrontError(front, err)
		}
		for _, item := range front.Listeners {
			if reservedPorts[item.LoopbackPort] {
				return nil, FrontError(front, fmt.Errorf("loopback port %d of %s is the core's own API port", item.LoopbackPort, item.Listener))
			}
			if err := claim("front loopback of "+string(item.Listener), FrontLoopbackHost, item.LoopbackPort); err != nil {
				return nil, FrontError(front, fmt.Errorf("loopback port of %s: %w", item.Listener, err))
			}
			if plan.ListenerLoopback == nil {
				plan.ListenerLoopback = map[protocol.ListenerKey]int{}
			}
			plan.ListenerLoopback[item.Listener] = item.LoopbackPort
		}
	}
	plan.Fronts = fronts
	return reservedPorts, nil
}

// planFrontLinks is the second half: a link a front routes to is reached on a
// loopback port the agent picks, because the protocol gives a link none. It runs
// AFTER every bind of the transit has been claimed, so the port it picks is free
// of the forwards and links that keep their own sockets.
func planFrontLinks(plan *TransitPlan, claim func(owner, listen string, port int) error, reservedPorts map[int]bool) error {
	_, links := frontedTargets(plan.Fronts)
	linkKeys := make([]protocol.LinkKey, 0, len(links))
	for key := range links {
		linkKeys = append(linkKeys, key)
	}
	sort.Slice(linkKeys, func(i, j int) bool { return linkKeys[i] < linkKeys[j] })
	for _, key := range linkKeys {
		port, ok := allocateLoopback(string(key), func(candidate int) bool {
			return !reservedPorts[candidate] && claim("front link "+string(key), FrontLoopbackHost, candidate) == nil
		})
		if !ok {
			return FrontError(frontByKey(plan.Fronts, links[key]), fmt.Errorf("no free loopback port for link %s", key))
		}
		if plan.LinkLoopback == nil {
			plan.LinkLoopback = map[protocol.LinkKey]int{}
		}
		plan.LinkLoopback[key] = port
	}
	return nil
}

func frontByKey(fronts []protocol.Front, key protocol.FrontKey) protocol.Front {
	for _, front := range fronts {
		if front.Key == key {
			return front
		}
	}
	return protocol.Front{Key: key}
}

func splitBindPort(bind string) (string, int, bool) {
	host, text, err := net.SplitHostPort(bind)
	if err != nil {
		return "", 0, false
	}
	port, err := strconv.Atoi(text)
	return host, port, err == nil
}

// allocateLoopback walks the probe range from a point derived from the seed
// and returns the first port try accepts, so a seed normally keeps its port.
func allocateLoopback(seed string, try func(port int) bool) (int, bool) {
	span := ProbePortLast - ProbePortFirst + 1
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(seed))
	start := int(hash.Sum32() % uint32(span))
	for offset := 0; offset < span; offset++ {
		candidate := ProbePortFirst + (start+offset)%span
		if try(candidate) {
			return candidate, true
		}
	}
	return 0, false
}

// WithoutFronts is the snapshot an engine that cannot front compiles: the
// fronts, the listeners they front, the forwards and links they route to, and
// the attachments of clients to those listeners are left out, and the rejection
// that says so names every one of them (RejectFronts). The rest of the
// configuration is untouched, so one front a panel should not have sent costs
// the node only what the front was to carry. The snapshot it was given is not
// modified.
func WithoutFronts(snapshot Snapshot) (Snapshot, *ObjectError) {
	rejection := RejectFronts(snapshot.Transit)
	if rejection == nil {
		return snapshot, nil
	}
	objectErr := rejection.(*ObjectError)
	return dropObjects(snapshot, objectErr), objectErr
}

// WithoutFront is WithoutFronts for ONE front an engine that can front has
// found it cannot carry (an ineligible listener, a bind that collides): that
// front and what it fronts are left out and rejected for the given cause, and
// the other fronts and the rest of the configuration are untouched. The
// rejection is false when the snapshot has no such front.
func WithoutFront(snapshot Snapshot, key protocol.FrontKey, cause error) (Snapshot, *ObjectError) {
	if snapshot.Transit == nil {
		return snapshot, nil
	}
	for _, front := range snapshot.Transit.Fronts {
		if front.Key == key {
			objects := FrontObjects(front)
			objectErr := &ObjectError{Stream: protocol.StreamConfig, Key: objects[0], Code: "core_config_rejected", Err: cause, Related: objects[1:]}
			return dropObjects(snapshot, objectErr), objectErr
		}
	}
	return snapshot, nil
}

// dropObjects is the snapshot without the objects an error names, and without
// the fronts among them.
func dropObjects(snapshot Snapshot, objectErr *ObjectError) Snapshot {
	gone := map[string]bool{objectErr.Key: true}
	for _, key := range objectErr.Related {
		gone[key] = true
	}
	out := snapshot
	out.Listeners = nil
	for _, listener := range snapshot.Listeners {
		if !gone[string(listener.Key)] {
			out.Listeners = append(out.Listeners, listener)
		}
	}
	out.Clients = make([]protocol.Client, 0, len(snapshot.Clients))
	for _, client := range snapshot.Clients {
		kept := make([]protocol.ListenerKey, 0, len(client.Listeners))
		for _, key := range client.Listeners {
			if !gone[string(key)] {
				kept = append(kept, key)
			}
		}
		client.Listeners = kept
		out.Clients = append(out.Clients, client)
	}
	transit := *snapshot.Transit
	transit.Fronts = nil
	for _, front := range snapshot.Transit.Fronts {
		if !gone[string(front.Key)] {
			transit.Fronts = append(transit.Fronts, front)
		}
	}
	transit.Forwards, transit.LinksIn = nil, nil
	for _, forward := range snapshot.Transit.Forwards {
		if !gone[string(forward.Key)] {
			transit.Forwards = append(transit.Forwards, forward)
		}
	}
	for _, link := range snapshot.Transit.LinksIn {
		if !gone[string(link.Key)] {
			transit.LinksIn = append(transit.LinksIn, link)
		}
	}
	if probe := snapshot.Transit.Probe; probe != nil {
		copied := *probe
		copied.Forwards = nil
		for _, target := range probe.Forwards {
			if !gone[string(target.Key)] {
				copied.Forwards = append(copied.Forwards, target)
			}
		}
		transit.Probe = &copied
		if copied.LinkURL == "" && len(copied.Forwards) == 0 {
			// Settings that probe nothing are not valid; nothing to probe is none.
			transit.Probe = nil
		}
	}
	out.Transit = &transit
	return out
}

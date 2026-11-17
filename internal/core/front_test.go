package core

import (
	"errors"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// frontTransitOf is a front on :443 over two listeners, a forward and a link:
// lst_1 and lst_2 are fronted (loopback 20001 and 20002), fwd_3 and lnk_4 are
// routed to.
func frontTransitOf() *protocol.Transit {
	return &protocol.Transit{
		Forwards: []protocol.Forward{{Key: "fwd_3", Port: 443, Target: "203.0.113.9", TargetPort: 443, Network: protocol.ForwardNetworkTCP}},
		LinksIn: []protocol.LinkIn{{Key: "lnk_4", Port: 443, Protocol: protocol.LinkProtocolVLESSReality, Reality: &protocol.LinkRealityServer{
			UUID: "0f62f495-b5ca-4509-b6cd-54a040deafd5", PrivateKey: "sCg4m4EzwI-ABTXkpBUlq7bXjvoGzOubGY3J8dhTL2o", Target: "www.example.com:443",
			ServerNames: []string{"link.example.com"}, ShortIDs: []string{"a1b2"}}}},
		Fronts: []protocol.Front{{
			Key: "fnt_1", Port: 443,
			Listeners: []protocol.FrontedListener{{Listener: "lst_1", LoopbackPort: 20001}, {Listener: "lst_2", LoopbackPort: 20002}},
			Routes: []protocol.FrontRoute{
				{ServerNames: []string{"a.example.com"}, Target: protocol.FrontTarget{Listener: "lst_1"}},
				{ServerNames: []string{"b.example.com"}, Target: protocol.FrontTarget{Listener: "lst_2"}},
				{ServerNames: []string{"relay.example.com"}, Target: protocol.FrontTarget{Forward: "fwd_3"}},
				{ServerNames: []string{"link.example.com"}, Target: protocol.FrontTarget{Link: "lnk_4"}},
			},
			Default: protocol.FrontTarget{External: &protocol.FrontExternal{Host: "www.example.org", Port: 443}},
		}},
	}
}

var frontServed = []protocol.ListenerKey{"lst_1", "lst_2"}

func frontSupport() FrontSupport {
	return FrontSupport{Listeners: map[protocol.ListenerKey]FrontListener{"lst_1": {Port: 443}, "lst_2": {Port: 443}}}
}

func objectError(t *testing.T, err error) *ObjectError {
	t.Helper()
	var objectErr *ObjectError
	if !errors.As(err, &objectErr) {
		t.Fatalf("err = %v, want an ObjectError", err)
	}
	return objectErr
}

func TestPlanTransitFrontedMovesWhatTheFrontOwns(t *testing.T) {
	plan, err := PlanTransitFronted(frontTransitOf(), nil, frontServed, "0.0.0.0", frontSupport())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.ListenerLoopback, map[protocol.ListenerKey]int{"lst_1": 20001, "lst_2": 20002}) {
		t.Errorf("listener loopbacks = %v", plan.ListenerLoopback)
	}
	port, ok := plan.LinkLoopback["lnk_4"]
	if !ok || port < ProbePortFirst || port > ProbePortLast {
		t.Errorf("link loopback = %v, want one in the probe range", plan.LinkLoopback)
	}
	// The forward has no socket of its own; the link stays an inbound.
	if len(plan.Forwards) != 0 || plan.FrontedForwards["fwd_3"].Target != "203.0.113.9" {
		t.Errorf("forwards %v, fronted %v", plan.Forwards, plan.FrontedForwards)
	}
	if len(plan.LinksIn) != 1 || len(plan.Fronts) != 1 || plan.Empty() {
		t.Errorf("links %v, fronts %v", plan.LinksIn, plan.Fronts)
	}
}

func TestPlanTransitFrontedAllocatesTheLinkPortDeterministically(t *testing.T) {
	first, _ := PlanTransitFronted(frontTransitOf(), nil, frontServed, "0.0.0.0", frontSupport())
	again, _ := PlanTransitFronted(frontTransitOf(), nil, frontServed, "0.0.0.0", frontSupport())
	if first.LinkLoopback["lnk_4"] == 0 || first.LinkLoopback["lnk_4"] != again.LinkLoopback["lnk_4"] {
		t.Fatalf("%v vs %v", first.LinkLoopback, again.LinkLoopback)
	}
	// It takes the next free port when its own is taken.
	occupied := map[string]string{"127.0.0.1:" + itoa(first.LinkLoopback["lnk_4"]): "lst_9"}
	moved, err := PlanTransitFronted(frontTransitOf(), occupied, frontServed, "0.0.0.0", frontSupport())
	if err != nil || moved.LinkLoopback["lnk_4"] == first.LinkLoopback["lnk_4"] {
		t.Fatalf("%v %v", moved.LinkLoopback, err)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestPlanTransitFrontedProbesAvoidTheFrontsLoopbackPorts(t *testing.T) {
	transit := frontTransitOf()
	transit.Fronts[0].Listeners[0].LoopbackPort = ProbePortFirst
	transit.Fronts[0].Listeners[1].LoopbackPort = ProbePortFirst + 1
	transit.LinksOut = []protocol.LinkOut{{Key: "lnk_9", Address: "exit.example.com", Port: 30009, Protocol: protocol.LinkProtocolSS2022,
		SS: &protocol.LinkSS{Method: "2022-blake3-aes-128-gcm", Password: "glwKkLUrNxQ4VbjbZG4svg=="}}}
	transit.Probe = &protocol.ProbeSettings{IntervalSeconds: 60, TimeoutMS: 3000, LinkURL: "https://probe.example.com/x"}
	plan, err := PlanTransitFronted(transit, nil, frontServed, "0.0.0.0", frontSupport())
	if err != nil {
		t.Fatal(err)
	}
	taken := map[int]bool{ProbePortFirst: true, ProbePortFirst + 1: true, plan.LinkLoopback["lnk_4"]: true}
	for _, probe := range plan.Probes {
		if taken[probe.Port] {
			t.Errorf("probe port %d is a front's loopback port", probe.Port)
		}
	}
	if len(plan.Probes) != 1 {
		t.Errorf("probes = %+v", plan.Probes)
	}
}

func TestPlanTransitFrontedWithoutFrontsIsPlanTransit(t *testing.T) {
	transit := probeTransit(3, 4)
	transit.Forwards = []protocol.Forward{{Key: "fwd_1", Port: 8443, Target: "203.0.113.9", TargetPort: 443, Network: protocol.ForwardNetworkTCPUDP}}
	binds := map[string]string{"0.0.0.0:443": "lst_1"}
	want, err := PlanTransit(transit, binds, frontServed, "0.0.0.0", "127.0.0.1:10085")
	if err != nil {
		t.Fatal(err)
	}
	got, err := PlanTransitFronted(transit, binds, frontServed, "0.0.0.0", frontSupport(), "127.0.0.1:10085")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v vs %+v (%v)", got, want, err)
	}
}

func TestPlanTransitRefusesFrontsWithoutSupport(t *testing.T) {
	_, err := PlanTransit(frontTransitOf(), nil, frontServed, "0.0.0.0")
	objectErr := objectError(t, err)
	if !strings.Contains(err.Error(), FrontsRequireXray) || objectErr.Key != "fnt_1" || objectErr.Code != "core_config_rejected" {
		t.Fatalf("err = %v", err)
	}
	for _, key := range []string{"fnt_1", "lst_1", "lst_2", "fwd_3", "lnk_4"} {
		if !objectErr.Names(protocol.StreamConfig, key) {
			t.Errorf("%s is not rejected", key)
		}
	}
	if objectErr.Names(protocol.StreamConfig, "lst_9") || objectErr.Names(protocol.StreamRoster, "fnt_1") {
		t.Error("an unrelated object, or the wrong stream, is named")
	}
	// PlanForwards is PlanTransit for forwards only: it refuses as well.
	if _, err := PlanForwards(frontTransitOf(), nil, "0.0.0.0"); err == nil {
		t.Error("PlanForwards planned a front")
	}
}

func TestPlanTransitFrontedRejectsAFrontAndEverythingItFronts(t *testing.T) {
	for _, test := range []struct {
		name    string
		mutate  func(*FrontSupport)
		binds   map[string]string
		reserve []string
		want    string
	}{
		{"listener not served", func(s *FrontSupport) { delete(s.Listeners, "lst_2") }, nil, nil, "does not serve"},
		{"listener unfit", func(s *FrontSupport) {
			s.Listeners["lst_1"] = FrontListener{Port: 443, Unfit: "uses the \"ws\" transport"}
		}, nil, nil, "\"ws\" transport"},
		{"public port differs", func(s *FrontSupport) { s.Listeners["lst_2"] = FrontListener{Port: 8443} }, nil, nil, "port is 8443"},
		{"front bind taken by another listener", func(*FrontSupport) {}, map[string]string{"0.0.0.0:443": "lst_9"}, nil, "conflicts with lst_9"},
		{"loopback port taken by a listener", func(*FrontSupport) {}, map[string]string{"0.0.0.0:20002": "lst_9"}, nil, "conflicts with lst_9"},
		{"loopback port is the core's API", func(*FrontSupport) {}, nil, []string{"127.0.0.1:20001"}, "API"},
	} {
		t.Run(test.name, func(t *testing.T) {
			support := frontSupport()
			test.mutate(&support)
			_, err := PlanTransitFronted(frontTransitOf(), test.binds, frontServed, "0.0.0.0", support, test.reserve...)
			objectErr := objectError(t, err)
			if !strings.Contains(err.Error(), test.want) || objectErr.Key != "fnt_1" || objectErr.Stream != protocol.StreamConfig {
				t.Fatalf("err = %v", err)
			}
			for _, key := range []string{"lst_1", "lst_2", "fwd_3", "lnk_4"} {
				if !objectErr.Names(protocol.StreamConfig, key) {
					t.Errorf("%s is not rejected with its front", key)
				}
			}
		})
	}
}

func TestFrontedListenerKeys(t *testing.T) {
	if FrontedListenerKeys(nil) != nil || FrontedListenerKeys(&protocol.Transit{}) != nil {
		t.Fatal("keys without fronts")
	}
	keys := FrontedListenerKeys(frontTransitOf())
	if len(keys) != 2 || !keys["lst_1"] || !keys["lst_2"] {
		t.Fatalf("keys = %v", keys)
	}
}

func TestFrontTargetTagKeepsAForwardsOwnName(t *testing.T) {
	for _, test := range []struct {
		target protocol.FrontTarget
		want   string
	}{
		{protocol.FrontTarget{Forward: "fwd_3"}, "transit-fwd_3"},
		{protocol.FrontTarget{Listener: "lst_1"}, "transit-fnt_1-lst_1"},
		{protocol.FrontTarget{Link: "lnk_4"}, "transit-fnt_1-lnk_4"},
		{protocol.FrontTarget{External: &protocol.FrontExternal{Host: "a.example", Port: 1}}, "transit-fnt_1-external"},
	} {
		if got := FrontTargetTag("fnt_1", test.target); got != test.want {
			t.Errorf("tag = %s, want %s", got, test.want)
		}
	}
	if FrontTag("fnt_1") != "transit-fnt_1" {
		t.Error("front tag")
	}
}

func client(key, uuid, password string) protocol.Client {
	return protocol.Client{Key: protocol.ClientKey(key), Credentials: protocol.Credential{UUID: uuid, Password: password}}
}

func TestCredentialSet(t *testing.T) {
	const base = "0f62f495-b5ca-4509-b6cd-54a040deafd5"
	for _, test := range []struct {
		name     string
		protocol string
		mask     bool
		clients  []protocol.Client
		dup, org protocol.ClientKey
	}{
		{"distinct vless", "vless", true, []protocol.Client{client("cli_1", base, ""), client("cli_2", "1f62f495-b5ca-4509-b6cd-54a040deafd5", "")}, "", ""},
		{"same vless uuid", "vless", true, []protocol.Client{client("cli_1", base, ""), client("cli_2", base, "")}, "cli_2", "cli_1"},
		{"case and dashes", "vless", true, []protocol.Client{client("cli_1", base, ""), client("cli_2", "0F62F495B5CA4509B6CD54A040DEAFD5", "")}, "cli_2", "cli_1"},
		{"xray masks bytes 6 and 7", "vless", true, []protocol.Client{client("cli_1", base, ""), client("cli_2", "0f62f495-b5ca-1234-b6cd-54a040deafd5", "")}, "cli_2", "cli_1"},
		{"sing-box keys by the whole uuid", "vless", false, []protocol.Client{client("cli_1", base, ""), client("cli_2", "0f62f495-b5ca-1234-b6cd-54a040deafd5", "")}, "", ""},
		{"byte 5 is not masked", "vless", true, []protocol.Client{client("cli_1", base, ""), client("cli_2", "0f62f495-b5cb-4509-b6cd-54a040deafd5", "")}, "", ""},
		{"byte 8 is not masked", "vless", true, []protocol.Client{client("cli_1", base, ""), client("cli_2", "0f62f495-b5ca-4509-b7cd-54a040deafd5", "")}, "", ""},
		{"vmess keys by the whole uuid", "vmess", true, []protocol.Client{client("cli_1", base, ""), client("cli_2", "0f62f495-b5ca-1234-b6cd-54a040deafd5", "")}, "", ""},
		{"same vmess uuid", "vmess", true, []protocol.Client{client("cli_1", base, ""), client("cli_2", base, "")}, "cli_2", "cli_1"},
		{"same trojan password", "trojan", true, []protocol.Client{client("cli_1", "", "pw"), client("cli_2", "", "pw")}, "cli_2", "cli_1"},
		{"distinct trojan passwords", "trojan", true, []protocol.Client{client("cli_1", "", "pw"), client("cli_2", "", "PW")}, "", ""},
		{"same shadowsocks password", "shadowsocks", true, []protocol.Client{client("cli_1", "", "k"), client("cli_2", "", "x"), client("cli_3", "", "k")}, "cli_3", "cli_1"},
		{"a vless client's password is not its credential", "vless", true, []protocol.Client{client("cli_1", base, "pw"), client("cli_2", "1f62f495-b5ca-4509-b6cd-54a040deafd5", "pw")}, "", ""},
		{"empty credentials are never duplicates of each other", "trojan", true, []protocol.Client{client("cli_1", "", ""), client("cli_2", "", "")}, "", ""},
		{"non-uuid text is compared as written", "vless", true, []protocol.Client{client("cli_1", "alice", ""), client("cli_2", "alice", ""), client("cli_3", "bob", "")}, "cli_2", "cli_1"},
		{"an unknown protocol has no credential to compare", "hysteria2", true, []protocol.Client{client("cli_1", "", "auth"), client("cli_2", "", "auth")}, "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			set := NewCredentialSet(test.protocol, test.mask)
			var dup, org protocol.ClientKey
			for _, c := range test.clients {
				if original, duplicate := set.Add(c); duplicate && dup == "" {
					dup, org = c.Key, original
				}
			}
			if dup != test.dup || org != test.org {
				t.Fatalf("got %s duplicates %s, want %s duplicates %s", dup, org, test.dup, test.org)
			}
		})
	}
}

// A link's loopback port is picked after every other bind of the transit is
// claimed: starting from where the hash of its key lands, it must not take the
// port of a forward that has its own socket there.
func TestPlanTransitFrontedLinkPortAvoidsEveryOtherBind(t *testing.T) {
	first, err := PlanTransitFronted(frontTransitOf(), nil, frontServed, "0.0.0.0", frontSupport())
	if err != nil {
		t.Fatal(err)
	}
	taken := first.LinkLoopback["lnk_4"]
	transit := frontTransitOf()
	transit.Forwards = append(transit.Forwards, protocol.Forward{Key: "fwd_9", Port: taken, Target: "203.0.113.10", TargetPort: 443, Network: protocol.ForwardNetworkTCP})
	plan, err := PlanTransitFronted(transit, nil, frontServed, "0.0.0.0", frontSupport())
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.LinkLoopback["lnk_4"]; got == taken || got == 0 {
		t.Fatalf("link loopback = %d, which is fwd_9's bind (%d)", got, taken)
	}
	var kept bool
	for _, forward := range plan.Forwards {
		kept = kept || forward.Key == "fwd_9"
	}
	if !kept {
		t.Fatal("fwd_9 was dropped")
	}
	// The same for an incoming link that is not fronted.
	transit = frontTransitOf()
	transit.LinksIn = append(transit.LinksIn, protocol.LinkIn{Key: "lnk_9", Port: taken, Protocol: protocol.LinkProtocolSS2022,
		SS: &protocol.LinkSS{Method: "2022-blake3-aes-128-gcm", Password: "glwKkLUrNxQ4VbjbZG4svg=="}})
	plan, err = PlanTransitFronted(transit, nil, frontServed, "0.0.0.0", frontSupport())
	if err != nil || plan.LinkLoopback["lnk_4"] == taken {
		t.Fatalf("link loopback = %d (%v)", plan.LinkLoopback["lnk_4"], err)
	}
}

func TestPlanTransitFrontedRefusesAnExternalDefaultThatIsThisHost(t *testing.T) {
	local := func(addresses ...string) func() []netip.Addr {
		return func() []netip.Addr {
			var out []netip.Addr
			for _, text := range addresses {
				out = append(out, netip.MustParseAddr(text))
			}
			return out
		}
	}
	for _, test := range []struct {
		name        string
		listen      string
		host        string
		port        int
		local       []string
		refused     bool
		skipForward bool
	}{
		{"own address, all addresses, front port", "", "203.0.113.5", 443, []string{"203.0.113.5"}, true, false},
		{"own address, front bound to 0.0.0.0", "0.0.0.0", "203.0.113.5", 443, []string{"203.0.113.5"}, true, false},
		{"own address, front bound to another one", "203.0.113.6", "203.0.113.5", 443, []string{"203.0.113.5", "203.0.113.6"}, false, false},
		{"own address, another port", "", "203.0.113.5", 8443, []string{"203.0.113.5"}, false, false},
		{"someone else's address", "", "203.0.113.77", 443, []string{"203.0.113.5"}, false, false},
		{"a name is not resolved here", "", "www.example.org", 443, []string{"203.0.113.5"}, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			transit := frontTransitOf()
			transit.Fronts[0].Listen = test.listen
			transit.Forwards[0].Listen = test.listen
			transit.LinksIn[0].Listen = test.listen
			transit.Fronts[0].Default = protocol.FrontTarget{External: &protocol.FrontExternal{Host: test.host, Port: test.port}}
			support := frontSupport()
			support.Local = local(test.local...)
			_, err := PlanTransitFronted(transit, nil, frontServed, "0.0.0.0", support)
			if test.refused {
				objectErr := objectError(t, err)
				if objectErr.Key != "fnt_1" || !objectErr.Names(protocol.StreamConfig, "lst_1") || !strings.Contains(err.Error(), "loops back") {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
}

// The protocol refuses an external that is the front's own bind, mapped
// spellings included; what only this host can see is an address of one of its
// interfaces under a front that listens on every address.
func TestExternalIsThisFrontNormalisesMappedAddresses(t *testing.T) {
	front := protocol.Front{Key: "fnt_1", Port: 443, Default: protocol.FrontTarget{External: &protocol.FrontExternal{Host: "203.0.113.5", Port: 443}}}
	for _, local := range []string{"203.0.113.5", "::ffff:203.0.113.5"} {
		if !externalIsThisFront(front, []netip.Addr{netip.MustParseAddr(local)}) {
			t.Errorf("local address %s is not this front's external", local)
		}
	}
	// Any loopback address is local, on no interface list at all.
	for _, loopback := range []string{"127.0.0.1", "127.8.9.10", "::1"} {
		front.Default.External.Host = loopback
		if !externalIsThisFront(front, nil) {
			t.Errorf("%s is not taken for this host", loopback)
		}
	}
	front.Default.External.Host = "203.0.113.5"
	front.Listen = "::"
	if !externalIsThisFront(front, []netip.Addr{netip.MustParseAddr("203.0.113.5")}) {
		t.Error(":: listens on every address")
	}
	front.Listen = "203.0.113.6"
	if externalIsThisFront(front, []netip.Addr{netip.MustParseAddr("203.0.113.5")}) {
		t.Error("a front on another address is not the external")
	}
	front.Listen = ""
	front.Default = protocol.FrontTarget{Listener: "lst_1"}
	if externalIsThisFront(front, []netip.Addr{netip.MustParseAddr("203.0.113.5")}) {
		t.Error("a listener default has no external")
	}
}

func TestWithoutFrontsLeavesTheRestOfTheSnapshot(t *testing.T) {
	snapshot := Snapshot{
		Listeners: []protocol.Listener{{Key: "lst_1"}, {Key: "lst_2"}, {Key: "lst_5"}},
		Clients: []protocol.Client{
			{Key: "cli_1", Listeners: []protocol.ListenerKey{"lst_1", "lst_5"}},
			{Key: "cli_2", Listeners: []protocol.ListenerKey{"lst_2"}},
		},
		Transit: frontTransitOf(),
	}
	snapshot.Transit.Forwards = append(snapshot.Transit.Forwards, protocol.Forward{Key: "fwd_8", Port: 8443, Target: "203.0.113.9", TargetPort: 443, Network: protocol.ForwardNetworkTCP})
	snapshot.Transit.Probe = &protocol.ProbeSettings{IntervalSeconds: 60, TimeoutMS: 3000,
		Forwards: []protocol.ProbeTarget{{Key: "fwd_3", Method: protocol.ProbeMethodTLS}, {Key: "fwd_8", Method: protocol.ProbeMethodTCP}}}
	out, rejection := WithoutFronts(snapshot)
	if rejection == nil || !strings.Contains(rejection.Error(), FrontsRequireXray) {
		t.Fatalf("rejection = %v", rejection)
	}
	if len(out.Listeners) != 1 || out.Listeners[0].Key != "lst_5" {
		t.Errorf("listeners = %v", out.Listeners)
	}
	if !reflect.DeepEqual(out.Clients[0].Listeners, []protocol.ListenerKey{"lst_5"}) || len(out.Clients[1].Listeners) != 0 {
		t.Errorf("attachments = %v %v", out.Clients[0].Listeners, out.Clients[1].Listeners)
	}
	if out.Transit.Fronts != nil || len(out.Transit.LinksIn) != 0 || len(out.Transit.Forwards) != 1 || out.Transit.Forwards[0].Key != "fwd_8" ||
		len(out.Transit.Probe.Forwards) != 1 || out.Transit.Probe.Forwards[0].Key != "fwd_8" {
		t.Errorf("transit = %+v", out.Transit)
	}
	// The snapshot handed in is not modified.
	if len(snapshot.Listeners) != 3 || len(snapshot.Transit.Fronts) != 1 || len(snapshot.Clients[0].Listeners) != 2 || len(snapshot.Transit.Probe.Forwards) != 2 {
		t.Error("WithoutFronts modified its input")
	}
	// Probe settings left with nothing to probe are dropped, not left invalid.
	only := snapshot
	onlyTransit := *snapshot.Transit
	onlyTransit.Probe = &protocol.ProbeSettings{IntervalSeconds: 60, TimeoutMS: 3000, Forwards: []protocol.ProbeTarget{{Key: "fwd_3", Method: protocol.ProbeMethodTLS}}}
	only.Transit = &onlyTransit
	if out, _ := WithoutFronts(only); out.Transit.Probe != nil {
		t.Errorf("probe settings = %+v", out.Transit.Probe)
	}
	if _, none := WithoutFronts(Snapshot{Listeners: []protocol.Listener{{Key: "lst_1"}}}); none != nil {
		t.Error("a snapshot without fronts was rejected")
	}
}

// One front an engine cannot carry is left out alone: the other fronts stay.
func TestWithoutFrontDropsOnlyThatFront(t *testing.T) {
	transit := frontTransitOf()
	transit.Fronts = append(transit.Fronts, protocol.Front{
		Key: "fnt_2", Port: 8443, Listeners: []protocol.FrontedListener{{Listener: "lst_5", LoopbackPort: 20005}},
		Routes:  []protocol.FrontRoute{{ServerNames: []string{"e.example.com"}, Target: protocol.FrontTarget{Listener: "lst_5"}}},
		Default: protocol.FrontTarget{Listener: "lst_5"},
	})
	snapshot := Snapshot{Listeners: []protocol.Listener{{Key: "lst_1"}, {Key: "lst_2"}, {Key: "lst_5"}}, Transit: transit}
	out, rejection := WithoutFront(snapshot, "fnt_1", errors.New("because"))
	if rejection == nil || rejection.Key != "fnt_1" || rejection.Err.Error() != "because" || rejection.Names(protocol.StreamConfig, "lst_5") || !rejection.Names(protocol.StreamConfig, "lnk_4") {
		t.Fatalf("rejection = %+v", rejection)
	}
	if len(out.Listeners) != 1 || out.Listeners[0].Key != "lst_5" || len(out.Transit.Fronts) != 1 || out.Transit.Fronts[0].Key != "fnt_2" || len(snapshot.Transit.Fronts) != 2 {
		t.Fatalf("out = %+v", out)
	}
	if _, none := WithoutFront(snapshot, "fnt_9", errors.New("x")); none != nil {
		t.Error("an unknown front was rejected")
	}
}

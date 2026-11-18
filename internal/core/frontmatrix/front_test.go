package frontmatrix

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/agent"
	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/singbox"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func fetchOK(socks int, target string) error {
	got, err := httpGetSum(viaSOCKS(socks, target), target, "/small")
	if err != nil || got != sum([]byte("ok")) {
		return fmt.Errorf("fetch: %v %s", err, got)
	}
	return nil
}

// TestFrontOwnListeners reaches two REALITY listeners that share the front's
// port, each by its own SNI, with a real Xray client (VLESS, REALITY, XTLS
// Vision): a small fetch, a 1 MiB download and a 1 MiB upload, hash-checked.
// A listener does not answer for the other's user, and nothing reaches the
// default site.
func TestFrontOwnListeners(t *testing.T) {
	r := newRig(t, rigOptions{})
	for _, c := range []struct{ name, sni, uuid string }{{"lst_1", sniOwn, uuidOne}, {"lst_2", sniOwn2, uuidTwo}} {
		t.Run(c.name, func(t *testing.T) {
			socks := r.client(clientOptions{serverPort: r.layout.frontPort, sni: c.sni, uuid: c.uuid})
			if err := transfer(socks, r.target); err != nil {
				t.Fatalf("%v\n%s", err, r.dump())
			}
		})
	}
	t.Run("a listener does not know the other's user", func(t *testing.T) {
		socks := r.client(clientOptions{serverPort: r.layout.frontPort, sni: sniOwn, uuid: uuidTwo})
		if err := fetchOK(socks, r.target); err == nil {
			t.Fatal("lst_1 accepted lst_2's user")
		}
	})
	if n := r.defaultHits(); n != 0 {
		t.Errorf("default site saw %d connections", n)
	}
}

// TestFrontRelaysRawBytes sends a REALITY client to the landing core through a
// forward behind the front, with a tee on each side of the front: every
// connection's bytes, both ways, are identical at the client and at the
// landing, so the front changed nothing in the stream.
func TestFrontRelaysRawBytes(t *testing.T) {
	r := newRig(t, rigOptions{})
	socks := r.client(clientOptions{serverPort: portOf(r.teeC.addr()), sni: sniRelay})
	if err := transfer(socks, r.target); err != nil {
		t.Fatalf("%v\n%s", err, r.dump())
	}
	for i := 0; i < 20; i++ {
		if err := fetchOK(socks, r.target); err != nil {
			t.Fatalf("repeat %d: %v", i, err)
		}
	}
	const connections = 3 + 20
	clientSide, landingSide := r.teeC.settled(t, connections), r.teeL.settled(t, connections)
	if len(clientSide) != len(landingSide) {
		t.Fatalf("%d connections at the client, %d at the landing", len(clientSide), len(landingSide))
	}
	for i := range clientSide {
		for _, s2c := range []bool{false, true} {
			a, an := clientSide[i].sum(s2c)
			b, bn := landingSide[i].sum(s2c)
			if a != b || an != bn {
				t.Errorf("connection %d (server to client %v): %d bytes at the client, %d at the landing, or they differ", i, s2c, an, bn)
			}
		}
	}
	if n := r.defaultHits(); n != 0 {
		t.Errorf("default site saw %d connections", n)
	}
}

// TestFrontDefaultsToTheExternalSite sends every connection no route names to
// the external default: an unknown SNI, an absent one, plain HTTP. It must go
// to the site's address, never to the name the client sniffed: that name here
// is one that cannot be resolved at all.
func TestFrontDefaultsToTheExternalSite(t *testing.T) {
	r := newRig(t, rigOptions{})
	for _, name := range []string{"never-dial-this-name.invalid", "unknown.example.com", ""} {
		got, _, err := probe(r.frontAddr(), name)
		if err != nil {
			t.Fatalf("sni %q: %v\n%s", name, err, r.dump())
		}
		if got != r.site.cert {
			t.Errorf("sni %q did not reach the default site", name)
		}
	}
	// A name that is a route's but for its case is no route's name: it is an
	// unknown SNI to the default, not the listener.
	body, took, err := httpPlain(r.frontAddr())
	if err != nil || !strings.Contains(body, "site:default.example.com") {
		t.Fatalf("plain HTTP: %v %q", err, body)
	}
	if took > 6*time.Second {
		t.Errorf("plain HTTP took %s; the sniff should give up in about a second", took)
	}
	t.Logf("plain HTTP reached the default in %s", took)
	if got := r.defaultHits(); got != 4 {
		t.Errorf("default site saw %d connections, want 4", got)
	}
	// None of it reached the REALITY decoy of the own listeners.
	if n := r.decoyHits(); n != 0 {
		t.Errorf("the REALITY decoy saw %d connections", n)
	}
}

// TestFrontFromARemoteAddress reaches the front from an address that is not
// loopback, as a real client does: Xray treats a connection from a remote
// address differently from one from this machine, and everything the front
// hands to a loopback port (the listeners, the link) must still work. The
// front's own freedom outbounds carry what lets them.
func TestFrontFromARemoteAddress(t *testing.T) {
	r := newRig(t, rigOptions{})
	host := nonLoopbackIP(t)
	for _, c := range []struct{ name, sni, uuid string }{{"lst_1", sniOwn, uuidOne}, {"lst_2", sniOwn2, uuidTwo}, {"lnk_5", sniLink, linkUUID}} {
		t.Run(c.name, func(t *testing.T) {
			socks := r.client(clientOptions{serverHost: host, serverPort: r.layout.frontPort, sni: c.sni, uuid: c.uuid, sourceIP: host})
			if err := transfer(socks, r.target); err != nil {
				t.Fatalf("%v\n%s", err, r.dump())
			}
		})
	}
	t.Run("default", func(t *testing.T) {
		if got, _, err := probe(net.JoinHostPort(host, fmt.Sprint(r.layout.frontPort)), "unknown.example.com"); err != nil || got != r.site.cert {
			t.Fatalf("default: %v\n%s", err, r.dump())
		}
	})
}

// TestFrontDefaultsToAListener makes a fronted listener the default: what no
// route names reaches it, so a probe sees what the listener shows a probe (its
// REALITY target), and the front's own destination is then a loopback address
// the freedom outbound must be allowed to reach.
func TestFrontDefaultsToAListener(t *testing.T) {
	r := newRig(t, rigOptions{defaultListener: true})
	got, _, err := probe(r.frontAddr(), "unknown.example.com")
	if err != nil || got != r.decoy.cert {
		t.Fatalf("an unknown SNI did not reach the listener's decoy: %v\n%s", err, r.dump())
	}
	if _, _, err := probe(r.frontAddr(), ""); err != nil {
		t.Fatalf("no SNI: %v", err)
	}
	socks := r.client(clientOptions{serverPort: r.layout.frontPort, sni: sniOwn})
	if err := transfer(socks, r.target); err != nil {
		t.Fatalf("%v\n%s", err, r.dump())
	}
	if n := r.defaultHits(); n != 0 {
		t.Errorf("the external site saw %d connections", n)
	}
}

// TestFrontIsNotJudgedByThePolicy blocks the address of the default site in the
// destination policy and shows the front still hands connections to it: the
// policy judges what a user asks of the core, and a front's connection is not
// that (the user connection it becomes, behind a fronted listener, is).
func TestFrontIsNotJudgedByThePolicy(t *testing.T) {
	r := newRig(t, rigOptions{policy: func(l layout) *protocol.DestinationPolicy {
		return &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
			{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{l.external.Host + "/32"}},
			{ID: "p2", Action: protocol.RuleBlock, Ports: fmt.Sprint(l.external.Port)},
		}}
	}})
	got, _, err := probe(r.frontAddr(), "unknown.example.com")
	if err != nil || got != r.site.cert {
		t.Fatalf("the default site is not reached through a policy that blocks it: %v\n%s", err, r.dump())
	}
	// And the policy is in force for a user: it cannot reach the site through
	// the fronted listener.
	socks := r.client(clientOptions{serverPort: r.layout.frontPort, sni: sniOwn})
	if err := fetchOK(socks, r.target); err != nil {
		t.Fatalf("a user's ordinary fetch: %v", err)
	}
	site := fmt.Sprintf("%s:%d", r.layout.external.Host, r.layout.external.Port)
	if conn, err := dialSOCKS(socks, site); err == nil {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		buffer := make([]byte, 64)
		if n, _ := conn.Read(buffer); n > 0 {
			t.Errorf("a user reached the blocked site through the fronted listener: %q", buffer[:n])
		}
		_ = conn.Close()
	}
}

// TestFrontPassesTheClientsAddress shows that the listener behind the front
// sees the client's own address, not the front's: the online address of its
// user, and a source-CIDR block on the fronted listener.
func TestFrontPassesTheClientsAddress(t *testing.T) {
	r := newRig(t, rigOptions{policy: func(layout) *protocol.DestinationPolicy {
		return &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{{
			ID: "s1", Action: protocol.RuleBlock, SourceCIDRs: []string{"127.0.0.2/32"},
			Inbounds: []protocol.ListenerKey{protocol.NewListenerKey(1)},
		}}}
	}})
	collect := r.meter()

	t.Run("online address", func(t *testing.T) {
		socks := r.client(clientOptions{serverPort: r.layout.frontPort, sni: sniOwn, sourceIP: "127.0.0.3"})
		hold, err := dialSOCKS(socks, r.target)
		if err != nil {
			t.Fatal(err)
		}
		defer hold.Close()
		_, _ = hold.Write([]byte("GET /small HTTP/1.1\r\nHost: x\r\n"))
		counters := waitCounters(t, collect, r.dump, func(c agentcore.Counters) bool {
			for _, client := range c.Clients {
				if client.Key == protocol.NewClientKey(1) && len(client.LiveIPs) > 0 {
					return true
				}
			}
			return false
		})
		for _, client := range counters.Clients {
			if client.Key != protocol.NewClientKey(1) {
				continue
			}
			if len(client.LiveIPs) != 1 || client.LiveIPs[0] != "127.0.0.3" {
				t.Fatalf("online addresses = %v, want [127.0.0.3] (not the front's 127.0.0.1)", client.LiveIPs)
			}
		}
	})
	t.Run("source block", func(t *testing.T) {
		allowed := r.client(clientOptions{serverPort: r.layout.frontPort, sni: sniOwn, sourceIP: "127.0.0.4"})
		blocked := r.client(clientOptions{serverPort: r.layout.frontPort, sni: sniOwn, sourceIP: "127.0.0.2"})
		if err := fetchOK(allowed, r.target); err != nil {
			t.Fatalf("127.0.0.4 should pass: %v\n%s", err, r.dump())
		}
		if err := fetchOK(blocked, r.target); err == nil {
			t.Fatal("127.0.0.2/32 was not blocked on the fronted listener")
		}
		// The block is scoped to lst_1: the same source passes on lst_2.
		other := r.client(clientOptions{serverPort: r.layout.frontPort, sni: sniOwn2, uuid: uuidTwo, sourceIP: "127.0.0.2"})
		if err := fetchOK(other, r.target); err != nil {
			t.Fatalf("127.0.0.2 should pass on lst_2: %v", err)
		}
	})
}

// TestFrontCounts shows what the node reports for a front: the user counted
// once, on its listener; the front never a user; each forward counted by the
// bytes its relay carried.
func TestFrontCounts(t *testing.T) {
	r := newRig(t, rigOptions{})
	collect := r.meter()

	own := r.client(clientOptions{serverPort: r.layout.frontPort, sni: sniOwn})
	if err := transfer(own, r.target); err != nil {
		t.Fatalf("%v\n%s", err, r.dump())
	}
	relay := r.client(clientOptions{serverPort: portOf(r.teeC.addr()), sni: sniRelay})
	if err := transfer(relay, r.target); err != nil {
		t.Fatalf("%v\n%s", err, r.dump())
	}
	landingSide := r.teeL.settled(t, 3)
	var up, down int64
	for _, c := range landingSide {
		_, n := c.sum(false)
		up += n
		_, n = c.sum(true)
		down += n
	}

	counters := waitCounters(t, collect, r.dump, func(c agentcore.Counters) bool {
		return len(c.Forwards) == 1 && c.Forwards[0].UpBytes >= up && c.Forwards[0].DownBytes >= down
	})
	if forward := counters.Forwards[0]; !forward.Present || forward.Key != protocol.NewForwardKey(1) || forward.UpBytes != up || forward.DownBytes != down {
		t.Errorf("forward counters = %+v, the landing side carried up %d down %d", forward, up, down)
	}
	// One user, once: the 1 MiB download is counted on the listener's user a
	// single time, not once for the front and once for the listener.
	const megabyte = 1 << 20
	var counted int
	for _, client := range counters.Clients {
		switch {
		case client.Key == protocol.NewClientKey(1):
			counted++
			if !client.Present || client.DownBytes < megabyte || client.DownBytes > megabyte*11/10 || client.UpBytes < megabyte || client.UpBytes > megabyte*11/10 {
				t.Errorf("user counters = %+v, want about 1 MiB each way, once", client)
			}
		case client.UpBytes != 0 || client.DownBytes != 0:
			t.Errorf("client %s moved: %+v", client.Key, client)
		}
	}
	if counted != 1 {
		t.Errorf("the user is reported %d times", counted)
	}
	for _, listener := range counters.Listeners {
		if listener.Key == protocol.NewListenerKey(1) && (!listener.Present || listener.DownBytes < megabyte || listener.DownBytes > megabyte*11/10) {
			t.Errorf("listener counters = %+v", listener)
		}
		if strings.HasPrefix(string(listener.Key), "fnt_") {
			t.Errorf("a front is reported as a listener: %+v", listener)
		}
	}
	// The core's own counters: the only users it counts are the roster's, and
	// the front, which has none, is counted as no one.
	for name := range xrayStats(t, r.release, r.frontAPI) {
		if strings.HasPrefix(name, "user>>>") && !strings.HasPrefix(name, "user>>>"+emailOne+">>>") && !strings.HasPrefix(name, "user>>>"+emailTwo+">>>") {
			t.Errorf("counter %q is not a roster user's", name)
		}
	}
}

// TestFrontLink reaches an incoming link through the front by its server name.
func TestFrontLink(t *testing.T) {
	r := newRig(t, rigOptions{})
	collect := r.meter()
	socks := r.client(clientOptions{serverPort: r.layout.frontPort, sni: sniLink, uuid: linkUUID})
	if err := transfer(socks, r.target); err != nil {
		t.Fatalf("%v\n%s", err, r.dump())
	}
	counters := waitCounters(t, collect, r.dump, func(c agentcore.Counters) bool {
		return len(c.Links) == 1 && c.Links[0].UpBytes > 0 && c.Links[0].DownBytes > 0
	})
	if link := counters.Links[0]; !link.Present || link.Key != protocol.NewLinkKey(5) || link.DownBytes < 1<<20 || link.DownBytes > (1<<20)*11/10 {
		t.Errorf("link counters = %+v", link)
	}
	if n := r.defaultHits(); n != 0 {
		t.Errorf("default site saw %d connections", n)
	}
}

// TestFrontTLSProbe runs the node's prober against the front: a TLS probe of
// the forward sends the route's name through the front and the relay and gets
// a ServerHello from the landing, and fails when the landing is gone.
func TestFrontTLSProbe(t *testing.T) {
	r := newRig(t, rigOptions{})
	configBody, _ := json.Marshal(protocol.ConfigBody{Transit: r.snapshot.Transit})
	deployment := state.CoreDeployment{ConfigDigest: "live", Artifact: r.artifact.Config, ConfigBody: configBody}
	// The prober dials the forward's own bind, which is the front's: the forward
	// has no socket of its own.
	prober, err := agent.NewProber(agent.ProberOptions{
		Deployment: func(context.Context) (state.CoreDeployment, error) { return deployment, nil },
		Status: func() agentcore.Status {
			return agentcore.Status{State: agentcore.ProcessRunning, ConfigDigest: "live"}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := func() protocol.ProbeResult {
		for _, entry := range prober.Results() {
			if entry.Key == "fwd_1" && entry.Kind == protocol.ProbeKindForward {
				return entry
			}
		}
		t.Fatalf("no forward result in %+v", prober.Results())
		return protocol.ProbeResult{}
	}
	for i := 0; i < 3; i++ {
		prober.Round(t.Context())
	}
	if got := result(); got.Attempts != 3 || got.Failures != 0 || got.LastSuccessMS == 0 {
		t.Fatalf("forward probe through the front = %+v\n%s", got, r.dump())
	}
	r.landing.Stop(t)
	failing := false
	for i := 0; i < 10 && !failing; i++ {
		prober.Round(t.Context())
		failing = result().Failures > 0
	}
	if !failing {
		t.Fatalf("the probe does not notice the landing is gone: %+v", result())
	}
	if err := protocol.ValidateProbeResults(prober.Results()); err != nil {
		t.Fatal(err)
	}
}

// TestFrontsAcrossXrayVersions runs the core of the matrix on every Xray release
// named in the environment: an own listener, the raw relay, the default.
func TestFrontsAcrossXrayVersions(t *testing.T) {
	for _, rel := range releases(t) {
		t.Run(rel.version, func(t *testing.T) {
			r := newRig(t, rigOptions{release: rel})
			own := r.client(clientOptions{serverPort: r.layout.frontPort, sni: sniOwn})
			if err := transfer(own, r.target); err != nil {
				t.Fatalf("own listener: %v\n%s", err, r.dump())
			}
			relay := r.client(clientOptions{serverPort: r.layout.frontPort, sni: sniRelay})
			if err := transfer(relay, r.target); err != nil {
				t.Fatalf("relay: %v\n%s", err, r.dump())
			}
			link := r.client(clientOptions{serverPort: r.layout.frontPort, sni: sniLink, uuid: linkUUID})
			if err := fetchOK(link, r.target); err != nil {
				t.Fatalf("link: %v\n%s", err, r.dump())
			}
			if got, _, err := probe(r.frontAddr(), "unknown.example.com"); err != nil || got != r.site.cert {
				t.Fatalf("default: %v", err)
			}
		})
	}
}

// TestSingBoxRefusesFronts compiles the same snapshot for sing-box: the front
// and everything it fronts are left out and reported rejected, and no fronted
// listener is bound on its public port by itself. The rest still compiles.
func TestSingBoxRefusesFronts(t *testing.T) {
	l := layout{frontPort: 20443, loopOne: 20001, loopTwo: 20002, landingPort: 20003, decoy: "127.0.0.1:20004", relayTarget: "127.0.0.1:20005",
		external: protocol.FrontExternal{Host: "203.0.113.5", Port: 443}}
	artifact, err := (singbox.Compiler{APIListen: "127.0.0.1:20006", APISecret: strings.Repeat("s", 32)}).Compile(context.Background(), frontSnapshot(l, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(artifact.Rejected) != 1 || !strings.Contains(artifact.Rejected[0].Error(), agentcore.FrontsRequireXray) {
		t.Fatalf("rejected = %v", artifact.Rejected)
	}
	for _, key := range []string{"fnt_1", "lst_1", "lst_2", "fwd_1", "lnk_5"} {
		if !artifact.Rejected[0].Names(protocol.StreamConfig, key) {
			t.Errorf("%s is not named by %v", key, artifact.Rejected[0])
		}
	}
	if strings.Contains(string(artifact.Config), "20443") {
		t.Errorf("something is bound on the front's port:\n%s", artifact.Config)
	}
}

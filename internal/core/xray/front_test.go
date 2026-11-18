package xray

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	statesqlite "github.com/KazuhaHub/passwall-node/v4/internal/state/sqlite"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

type frontConfig struct {
	Policy    map[string]any `json:"policy"`
	Inbounds  []map[string]any
	Outbounds []map[string]any
	Routing   struct {
		Rules []map[string]any `json:"rules"`
	} `json:"routing"`
}

func compileFronts(t *testing.T, snapshot agentcore.Snapshot) (frontConfig, agentcore.Artifact) {
	t.Helper()
	artifact, err := (Compiler{}).Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var config frontConfig
	if err := json.Unmarshal(artifact.Config, &config); err != nil {
		t.Fatal(err)
	}
	return config, artifact
}

func (c frontConfig) inbound(t *testing.T, tag string) map[string]any {
	t.Helper()
	for _, inbound := range c.Inbounds {
		if inbound["tag"] == tag {
			return inbound
		}
	}
	return nil
}

func (c frontConfig) outbound(tag string) map[string]any {
	for _, outbound := range c.Outbounds {
		if outbound["tag"] == tag {
			return outbound
		}
	}
	return nil
}

func settingsOf(m map[string]any) map[string]any {
	settings, _ := m["settings"].(map[string]any)
	return settings
}

func TestCompilerFrontIsASniffingDokodemoOnTheSharedPort(t *testing.T) {
	config, _ := compileFronts(t, frontSnapshot())
	front := config.inbound(t, "transit-fnt_1")
	if front == nil || front["protocol"] != "dokodemo-door" || front["port"] != float64(443) {
		t.Fatalf("front = %v", front)
	}
	if _, bound := front["listen"]; bound {
		t.Errorf("an empty listen must bind every address: %v", front)
	}
	// The destination of a connection no rule claims is the default's, and the
	// sniffed name never replaces it.
	if got := settingsOf(front); got["address"] != "www.example.org" || got["port"] != float64(443) || got["network"] != "tcp" {
		t.Errorf("front destination = %v", got)
	}
	if !reflect.DeepEqual(front["sniffing"], map[string]any{"enabled": true, "destOverride": []any{"tls"}, "routeOnly": true}) {
		t.Errorf("sniffing = %v", front["sniffing"])
	}
}

func TestCompilerFrontMovesListenersToLoopbackWithProxyProtocol(t *testing.T) {
	config, _ := compileFronts(t, frontSnapshot())
	for tag, port := range map[string]float64{"psp-lst_1": 20001, "psp-lst_2": 20002} {
		inbound := config.inbound(t, tag)
		if inbound == nil || inbound["listen"] != "127.0.0.1" || inbound["port"] != port {
			t.Fatalf("%s = %v", tag, inbound)
		}
		stream := inbound["streamSettings"].(map[string]any)
		if stream["security"] != "reality" || stream["sockopt"].(map[string]any)["acceptProxyProtocol"] != true {
			t.Errorf("%s stream = %v", tag, stream)
		}
	}
	// The link is reached through the front too, on a port the agent chose.
	link := config.inbound(t, "transit-lnk_4")
	port, _ := link["port"].(float64)
	if link["listen"] != "127.0.0.1" || port < agentcore.ProbePortFirst || port > agentcore.ProbePortLast ||
		link["streamSettings"].(map[string]any)["sockopt"].(map[string]any)["acceptProxyProtocol"] != true {
		t.Errorf("link = %v", link)
	}
	// A forward behind a front has no inbound of its own.
	if config.inbound(t, "transit-fwd_3") != nil {
		t.Error("the fronted forward kept its own inbound")
	}
	// Nothing else is bound on the public port but the front.
	for _, inbound := range config.Inbounds {
		if inbound["port"] == float64(443) && inbound["tag"] != "transit-fnt_1" {
			t.Errorf("%v is bound on the front's port", inbound["tag"])
		}
	}
}

func TestCompilerFrontOutboundsRedirectExplicitly(t *testing.T) {
	config, _ := compileFronts(t, frontSnapshot())
	linkPort := config.inbound(t, "transit-lnk_4")["port"].(float64)
	loopback := func(tag string, port float64) {
		t.Helper()
		settings := settingsOf(config.outbound(tag))
		if settings["redirect"] != fmt.Sprintf("127.0.0.1:%d", int(port)) || settings["proxyProtocol"] != float64(2) {
			t.Errorf("%s = %v", tag, settings)
		}
		rules := settings["finalRules"].([]any)[0].(map[string]any)
		if rules["action"] != "allow" || !reflect.DeepEqual(rules["ip"], []any{"127.0.0.1"}) {
			t.Errorf("%s finalRules = %v", tag, rules)
		}
	}
	loopback("transit-fnt_1-lst_1", 20001)
	loopback("transit-fnt_1-lst_2", 20002)
	loopback("transit-fnt_1-lnk_4", linkPort)
	// A forward's relay is raw: no PROXY header, no loopback permission.
	if got := settingsOf(config.outbound("transit-fwd_3")); !reflect.DeepEqual(got, map[string]any{"redirect": "203.0.113.9:8443"}) {
		t.Errorf("forward outbound = %v", got)
	}
	// The default is dialed at its own address, which is no loopback.
	if got := settingsOf(config.outbound("transit-fnt_1-external")); !reflect.DeepEqual(got, map[string]any{"redirect": "www.example.org:443"}) {
		t.Errorf("external outbound = %v", got)
	}
}

func TestCompilerFrontRulesComeFirstAndEndWithTheDefault(t *testing.T) {
	snapshot := frontSnapshot()
	snapshot.DestinationPolicy = &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, Private: true}}}
	config, _ := compileFronts(t, snapshot)
	var tags []string
	for _, rule := range config.Routing.Rules {
		tags = append(tags, fmt.Sprint(rule["ruleTag"]))
	}
	want := []string{"transit-fnt_1-r1", "transit-fnt_1-r2", "transit-fnt_1-r3", "transit-fnt_1-r4", "transit-fnt_1-default", "transit-forwards"}
	if len(tags) < len(want) || !reflect.DeepEqual(tags[:len(want)], want) {
		t.Fatalf("rules begin %v, want %v", tags, want)
	}
	byTag := map[string]map[string]any{}
	for _, rule := range config.Routing.Rules {
		byTag[fmt.Sprint(rule["ruleTag"])] = rule
	}
	if rule := byTag["transit-fnt_1-r3"]; !reflect.DeepEqual(rule["domain"], []any{"full:relay.example.com", "full:relay2.example.com"}) ||
		rule["outboundTag"] != "transit-fwd_3" || !reflect.DeepEqual(rule["inboundTag"], []any{"transit-fnt_1"}) {
		t.Errorf("relay rule = %v", rule)
	}
	if rule := byTag["transit-fnt_1-default"]; rule["outboundTag"] != "transit-fnt_1-external" || rule["domain"] != nil {
		t.Errorf("default rule = %v", rule)
	}
	// The transit rule no longer lists the forward (it has no inbound), and
	// still lists the link.
	if tags := byTag["transit-forwards"]["inboundTag"]; !reflect.DeepEqual(tags, []any{"transit-lnk_4"}) {
		t.Errorf("transit rule inbounds = %v", tags)
	}
}

func TestCompilerFrontsSwitchOnOutboundStatisticsForTheirForwards(t *testing.T) {
	config, _ := compileFronts(t, frontSnapshot())
	system := config.Policy["system"].(map[string]any)
	if system["statsOutboundUplink"] != true || system["statsOutboundDownlink"] != true {
		t.Errorf("system policy = %v", system)
	}
	// A front with no forward behind it leaves the policy as it was.
	snapshot := frontSnapshot()
	snapshot.Transit.Forwards = nil
	snapshot.Transit.Fronts[0].Routes = append(snapshot.Transit.Fronts[0].Routes[:2:2], snapshot.Transit.Fronts[0].Routes[3])
	config, _ = compileFronts(t, snapshot)
	if _, on := config.Policy["system"].(map[string]any)["statsOutboundUplink"]; on {
		t.Error("outbound statistics are on without a fronted forward")
	}
}

func TestCompilerFrontRejectsWhatCannotSitBehindIt(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*agentcore.Snapshot)
		want   string
	}{
		{"websocket listener", func(s *agentcore.Snapshot) {
			stream := realityStream("a.example.com")
			stream["network"] = "ws"
			s.Listeners[0] = frontListener(1, 443, stream)
		}, `"ws" transport`},
		{"no TLS or REALITY", func(s *agentcore.Snapshot) {
			s.Listeners[0] = frontListener(1, 443, map[string]any{"network": "raw", "security": "none"})
		}, "no TLS or REALITY"},
		{"a port that is not the front's", func(s *agentcore.Snapshot) {
			s.Listeners[1] = frontListener(2, 8443, realityStream("b.example.com"))
		}, "its own port is 8443"},
		{"disabled listener", func(s *agentcore.Snapshot) {
			s.Listeners[1].Config = []byte(strings.Replace(string(s.Listeners[1].Config), `"enabled":true`, `"enabled":false`, 1))
		}, "does not serve"},
		{"another listener on the front's port", func(s *agentcore.Snapshot) {
			s.Listeners = append(s.Listeners, frontListener(9, 443, realityStream("c.example.com")))
		}, "conflicts with lst_9"},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := frontSnapshot()
			test.mutate(&snapshot)
			// A second, healthy front with its own listener: it must survive.
			snapshot.Listeners = append(snapshot.Listeners, frontListener(5, 8443, realityStream("e.example.com")), frontListener(6, 9443, realityStream("f.example.com")))
			snapshot.Transit.Fronts = append(snapshot.Transit.Fronts, protocol.Front{
				Key: "fnt_2", Port: 8443, Listeners: []protocol.FrontedListener{{Listener: "lst_5", LoopbackPort: 20005}},
				Routes:  []protocol.FrontRoute{{ServerNames: []string{"e.example.com"}, Target: protocol.FrontTarget{Listener: "lst_5"}}},
				Default: protocol.FrontTarget{External: &protocol.FrontExternal{Host: "www.example.org", Port: 443}},
			})
			config, artifact := compileFronts(t, snapshot)
			if len(artifact.Rejected) != 1 {
				t.Fatalf("rejected = %v", artifact.Rejected)
			}
			rejected := artifact.Rejected[0]
			if rejected.Stream != protocol.StreamConfig || rejected.Code != "core_config_rejected" || !strings.Contains(rejected.Error(), test.want) {
				t.Fatalf("rejected = %v, want %q", rejected, test.want)
			}
			// The front and everything it fronts are rejected together, and only they.
			for _, key := range []string{"fnt_1", "lst_1", "lst_2", "fwd_3", "lnk_4"} {
				if !rejected.Names(protocol.StreamConfig, key) {
					t.Errorf("%s is not rejected", key)
				}
			}
			for _, key := range []string{"fnt_2", "lst_5", "lst_6", "lst_9"} {
				if rejected.Names(protocol.StreamConfig, key) {
					t.Errorf("%s is rejected with a front that is not its own", key)
				}
			}
			// Nothing of the rejected front is deployed, in particular nothing is
			// bound on its public port; the other front and listener are.
			for _, tag := range []string{"transit-fnt_1", "psp-lst_1", "psp-lst_2", "transit-fwd_3", "transit-lnk_4"} {
				if config.inbound(t, tag) != nil {
					t.Errorf("%s is deployed", tag)
				}
			}
			if front := config.inbound(t, "transit-fnt_2"); front == nil || config.inbound(t, "psp-lst_5")["port"] != float64(20005) || config.inbound(t, "psp-lst_6") == nil {
				t.Errorf("the rest of the configuration did not compile: %v", config.Inbounds)
			}
			for _, inbound := range config.Inbounds {
				if inbound["port"] == float64(443) && inbound["tag"] != "psp-lst_9" {
					t.Errorf("%v is bound on the rejected front's port", inbound["tag"])
				}
			}
		})
	}
}

// Fronted listeners share a public port, which two listeners may not do: it is
// the front that holds it.
func TestCompilerStillRefusesTwoListenersOnOnePortWithoutAFront(t *testing.T) {
	snapshot := frontSnapshot()
	snapshot.Transit = nil
	if _, err := (Compiler{}).Compile(context.Background(), snapshot); err == nil || !strings.Contains(err.Error(), "conflicts with listener") {
		t.Fatalf("err = %v", err)
	}
}

func TestTelemetryKnowsAFrontedForwardByItsOutboundAndNeverCountsAFront(t *testing.T) {
	config, artifact := compileFronts(t, frontSnapshot())
	_ = config
	ctx := context.Background()
	store, err := statesqlite.Open(ctx, filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	snapshot := frontSnapshot()
	configBody, _ := json.Marshal(protocol.ConfigBody{Listeners: snapshot.Listeners, Transit: snapshot.Transit})
	rosterBody, _ := json.Marshal(protocol.RosterBody{Clients: snapshot.Clients})
	digest := fmt.Sprintf("%x", sha256.Sum256(artifact.Config))
	if err := store.SaveCoreDeployment(ctx, state.CoreDeployment{
		Engine: "xray", Version: "26.6.27", ConfigDigest: digest, Artifact: artifact.Config,
		ConfigBody: configBody, RosterBody: rosterBody, AppliedAtMS: 1,
	}); err != nil {
		t.Fatal(err)
	}
	status := agentcore.Status{State: agentcore.ProcessRunning, Engine: "xray", Version: "26.6.27", BinaryPath: "/xray", ConfigDigest: digest, LastChangedAt: time.Unix(10, 0)}
	telemetry, err := NewTelemetry(TelemetryOptions{
		Store: store, Status: func() agentcore.Status { return status },
		RunCommand: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if len(args) > 1 && args[1] == "statsquery" {
				return []byte(`{"stat":[
					{"name":"outbound>>>transit-fwd_3>>>traffic>>>uplink","value":"21"},
					{"name":"outbound>>>transit-fwd_3>>>traffic>>>downlink","value":"22"},
					{"name":"inbound>>>transit-fnt_1>>>traffic>>>uplink","value":"999"},
					{"name":"inbound>>>transit-fnt_1>>>traffic>>>downlink","value":"999"},
					{"name":"inbound>>>transit-lnk_4>>>traffic>>>uplink","value":"31"},
					{"name":"inbound>>>transit-lnk_4>>>traffic>>>downlink","value":"32"},
					{"name":"inbound>>>psp-lst_1>>>traffic>>>uplink","value":"41"},
					{"name":"inbound>>>psp-lst_1>>>traffic>>>downlink","value":"42"},
					{"name":"user>>>u1@x>>>traffic>>>uplink","value":"41"},
					{"name":"user>>>u1@x>>>traffic>>>downlink","value":"42"}
				]}`), nil
			}
			return []byte(`{"users":[{"email":"u1@x","ips":[{"ip":"192.0.2.7"}]}]}`), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := telemetry.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	epoch := got.Clients[0].CounterEpoch
	if want := []agentcore.ForwardCounters{{Key: "fwd_3", Present: true, UpBytes: 21, DownBytes: 22, CounterEpoch: epoch}}; !reflect.DeepEqual(got.Forwards, want) {
		t.Errorf("forwards = %+v, want %+v", got.Forwards, want)
	}
	if want := []agentcore.LinkCounters{{Key: "lnk_4", Present: true, UpBytes: 31, DownBytes: 32, CounterEpoch: epoch}}; !reflect.DeepEqual(got.Links, want) {
		t.Errorf("links = %+v, want %+v", got.Links, want)
	}
	if len(got.Clients) != 1 || got.Clients[0].UpBytes != 41 || got.Clients[0].DownBytes != 42 || !reflect.DeepEqual(got.Clients[0].LiveIPs, []string{"192.0.2.7"}) {
		t.Errorf("clients = %+v", got.Clients)
	}
	for _, listener := range got.Listeners {
		if listener.Key == "lst_1" && (!listener.Present || listener.UpBytes != 41 || listener.DownBytes != 42) {
			t.Errorf("listener = %+v", listener)
		}
		if listener.UpBytes == 999 || listener.DownBytes == 999 {
			t.Errorf("the front's traffic is attributed to %+v", listener)
		}
	}
}

// Two clients of a listener with one credential are one user to the core. The
// later one (clients are in key order) is left off that listener and reported
// rejected as itself; the compile goes ahead with everything else.
func TestCompilerRejectsOnlyTheLaterClientOfADuplicateCredential(t *testing.T) {
	const uuid = "0f62f495-b5ca-4509-b6cd-54a040deafd5"
	for _, test := range []struct {
		name     string
		protocol string
		first    protocol.Credential
		second   protocol.Credential
		dup      bool
	}{
		{"vless uuid", "vless", protocol.Credential{UUID: uuid}, protocol.Credential{UUID: uuid}, true},
		{"vless uuid differing in bytes 6 and 7", "vless", protocol.Credential{UUID: uuid}, protocol.Credential{UUID: "0f62f495-b5ca-1111-b6cd-54a040deafd5"}, true},
		{"vless uuid differing elsewhere", "vless", protocol.Credential{UUID: uuid}, protocol.Credential{UUID: "0f62f495-b5ca-4509-b6cd-54a040deafd6"}, false},
		{"vmess keys by the whole uuid", "vmess", protocol.Credential{UUID: uuid}, protocol.Credential{UUID: "0f62f495-b5ca-1111-b6cd-54a040deafd5"}, false},
		{"trojan password", "trojan", protocol.Credential{Password: "pw"}, protocol.Credential{Password: "pw"}, true},
		{"shadowsocks password", "shadowsocks", protocol.Credential{Password: "pw"}, protocol.Credential{Password: "pw"}, true},
		{"shadowsocks passwords", "shadowsocks", protocol.Credential{Password: "pw"}, protocol.Credential{Password: "pw2"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			settings := `{"decryption":"none"}`
			if test.protocol == "shadowsocks" {
				settings = `{"method":"aes-256-gcm","network":"tcp,udp"}`
			}
			spec := func(port int) []byte {
				config, _ := json.Marshal(map[string]any{"enabled": true, "port": port, "protocol": test.protocol, "settings": settings})
				return config
			}
			snapshot := agentcore.Snapshot{Now: time.Unix(1, 0), Listeners: []protocol.Listener{{Key: "lst_1", Config: spec(20001)}, {Key: "lst_2", Config: spec(20002)}}}
			for i, credential := range []protocol.Credential{test.first, test.second, {UUID: "5d2c9a3e-8b1f-4c77-9e0a-6f3b1d7a2c48", Password: "other"}} {
				credential.Username = fmt.Sprintf("u%d@x", i+1)
				snapshot.Clients = append(snapshot.Clients, protocol.Client{
					Key: protocol.NewClientKey(int64(i + 1)), Subject: protocol.NewSubjectKey(int64(i + 1)), Enabled: true,
					Listeners: []protocol.ListenerKey{"lst_1"}, Credentials: credential,
				})
			}
			config, artifact := compileFronts(t, snapshot)
			emails := func(tag string) []string {
				var out []string
				for _, user := range settingsOf(config.inbound(t, tag))["clients"].([]any) {
					out = append(out, user.(map[string]any)["email"].(string))
				}
				return out
			}
			if !test.dup {
				if len(artifact.Rejected) != 0 || !reflect.DeepEqual(emails("psp-lst_1"), []string{"u1@x", "u2@x", "u3@x"}) {
					t.Fatalf("rejected %v, users %v", artifact.Rejected, emails("psp-lst_1"))
				}
				return
			}
			if len(artifact.Rejected) != 1 {
				t.Fatalf("rejected = %v", artifact.Rejected)
			}
			rejected := artifact.Rejected[0]
			if rejected.Stream != protocol.StreamRoster || rejected.Key != "cli_2" || rejected.Code != "core_config_rejected" || !strings.Contains(rejected.Error(), "duplicates client cli_1") {
				t.Fatalf("rejected = %v", rejected)
			}
			// The first is kept, the third (another credential) is untouched, and
			// the other listener compiled.
			if got := emails("psp-lst_1"); !reflect.DeepEqual(got, []string{"u1@x", "u3@x"}) {
				t.Fatalf("users = %v", got)
			}
			if config.inbound(t, "psp-lst_2") == nil {
				t.Fatal("the other listener is gone")
			}
			// The same credential on another listener is another user.
			snapshot.Clients[1].Listeners = []protocol.ListenerKey{"lst_2"}
			if _, artifact := compileFronts(t, snapshot); len(artifact.Rejected) != 0 {
				t.Fatalf("one credential on two listeners rejected: %v", artifact.Rejected)
			}
		})
	}
}

// An empty credential is "required", whatever the other clients have.
func TestCompilerAskForAUUIDBeforeComparingCredentials(t *testing.T) {
	snapshot := frontSnapshot()
	snapshot.Transit = nil
	snapshot.Listeners = snapshot.Listeners[:1]
	snapshot.Listeners[0] = frontListener(1, 443, realityStream("a.example.com"))
	for i := 2; i <= 3; i++ {
		snapshot.Clients = append(snapshot.Clients, protocol.Client{
			Key: protocol.NewClientKey(int64(i)), Subject: protocol.NewSubjectKey(int64(i)), Enabled: true,
			Listeners:   []protocol.ListenerKey{"lst_1"},
			Credentials: protocol.Credential{Username: fmt.Sprintf("u%d@x", i)},
		})
	}
	_, err := (Compiler{}).Compile(context.Background(), snapshot)
	var objectErr *agentcore.ObjectError
	if !errors.As(err, &objectErr) || objectErr.Stream != protocol.StreamRoster || objectErr.Key != "cli_2" || !strings.Contains(err.Error(), "UUID is required") {
		t.Fatalf("err = %v, want cli_2: UUID is required", err)
	}
}

func TestCompilerRefusesToFrontAListenerThatAcceptsProxyProtocolItself(t *testing.T) {
	for name, stream := range map[string]func(map[string]any){
		"sockopt":     func(s map[string]any) { s["sockopt"] = map[string]any{"acceptProxyProtocol": true} },
		"rawSettings": func(s map[string]any) { s["rawSettings"] = map[string]any{"acceptProxyProtocol": true} },
		"tcpSettings": func(s map[string]any) { s["tcpSettings"] = map[string]any{"acceptProxyProtocol": true} },
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := frontSnapshot()
			listener := realityStream("a.example.com")
			stream(listener)
			snapshot.Listeners[0] = frontListener(1, 443, listener)
			_, artifact := compileFronts(t, snapshot)
			if len(artifact.Rejected) != 1 {
				t.Fatalf("rejected = %v", artifact.Rejected)
			}
			if err := artifact.Rejected[0]; !strings.Contains(err.Error(), "acceptProxyProtocol") || !strings.Contains(err.Error(), "two") || !err.Names(protocol.StreamConfig, "fnt_1") {
				t.Fatalf("err = %v", err)
			}
			// Unfronted it is the listener's own business.
			snapshot.Transit = nil
			snapshot.Listeners[1] = frontListener(2, 444, realityStream("b.example.com"))
			if _, err := (Compiler{}).Compile(context.Background(), snapshot); err != nil {
				t.Fatalf("unfronted: %v", err)
			}
		})
	}
}

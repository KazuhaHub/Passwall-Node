package singbox

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// The egress split wraps logical rules and rewrites routes around sniff and
// resolve actions; sing-box's own check is the judge of whether the result is
// a configuration it runs.
func TestEgressSplitArtifactPassesPinnedSingBoxCheck(t *testing.T) {
	binary, ok := os.LookupEnv("PSP_TEST_SING_BOX_BIN")
	if !ok {
		t.Skip("set PSP_TEST_SING_BOX_BIN to the audited sing-box 1.14.0 binary")
	}
	snapshot := realitySnapshot(t)
	raw, _ := json.Marshal(listenerSpec{Enabled: true, Listen: "127.0.0.1", Port: 28444, Protocol: "vless", Settings: `{"decryption":"none","clients":[]}`})
	snapshot.Listeners = append(snapshot.Listeners, protocol.Listener{Key: protocol.NewListenerKey(42), Config: raw})
	snapshot.DestinationPolicy = &protocol.DestinationPolicy{Resolve: protocol.ResolveOnDemand, Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleAllow, Domains: []string{"full:allowed.example"}},
		{ID: "p5", Action: protocol.RuleAllow, Domains: []string{"domain:x.example"}, CIDRs: []string{"192.0.2.0/24"}},
		{ID: "p2", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
		{ID: "p4", Action: protocol.RuleBlock, Private: true},
		{ID: "p3", Action: protocol.RuleObserve, CIDRs: []string{"10.0.0.0/8"}},
	}}
	snapshot.Transit = &protocol.Transit{
		LinksOut: []protocol.LinkOut{{Key: protocol.NewLinkKey(7), Address: "exit.example.com", Port: 30001, Protocol: protocol.LinkProtocolSS2022, SS: &protocol.LinkSS{Method: "2022-blake3-aes-128-gcm", Password: "glwKkLUrNxQ4VbjbZG4svg=="}}},
		Egress:   []protocol.EgressBinding{{Listener: protocol.NewListenerKey(42), Link: protocol.NewLinkKey(7)}},
	}
	artifact, err := (Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}).Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "c.json")
	_ = os.WriteFile(path, artifact.Config, 0o600)
	if out, err := exec.Command(binary, "check", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("sing-box refused the split artifact: %v\n%s", err, out)
	}
}

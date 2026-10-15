//go:build telemetry_profile && linux

package xray

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
)

type telemetryModeCost struct {
	Mode          string `json:"mode"`
	Rounds        int    `json:"rounds"`
	WallNS        int64  `json:"wall_ns"`
	ParentCPUNS   uint64 `json:"parent_cpu_ns"`
	ChildCPUNS    uint64 `json:"child_cpu_ns"`
	Queries       int    `json:"queries"`
	OnlineQueries int    `json:"online_queries"`
	Closed        int    `json:"agent_connections_closed"`
}
type telemetryWireResult struct {
	Version   string              `json:"core_version"`
	Clients   int                 `json:"clients"`
	Listeners int                 `json:"listeners"`
	IPv4      int                 `json:"live_ipv4_verified"`
	IPv6      int                 `json:"live_ipv6_verified"`
	Traffic   int                 `json:"traffic_equivalent"`
	Modes     []telemetryModeCost `json:"modes"`
}
type telemetryCountConnection struct {
	grpc.ClientConnInterface
	queries, online *int
}

func (c telemetryCountConnection) Invoke(ctx context.Context, method string, request, response any, options ...grpc.CallOption) error {
	if method == queryStatsMethod {
		*c.queries += 1
	}
	if method == getUsersStatsMethod {
		*c.online += 1
	}
	return c.ClientConnInterface.Invoke(ctx, method, request, response, options...)
}

func TestRealXrayStatsWireCompatibility(t *testing.T) {
	source := os.Getenv("GITHUB_SHA")
	run, err := strconv.ParseUint(os.Getenv("GITHUB_RUN_ID"), 10, 64)
	if err != nil || run == 0 || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(source) {
		t.Fatal("wire profile requires immutable owned run metadata")
	}
	evidence := os.Getenv("PSP_STATS_WIRE_METRICS")
	root, e1 := filepath.EvalSymlinks(os.Getenv("RUNNER_TEMP"))
	dir, e2 := filepath.EvalSymlinks(filepath.Dir(evidence))
	if e1 != nil || e2 != nil || root != dir || !filepath.IsAbs(evidence) || filepath.Base(evidence) != "xray-stats-wire.json" {
		t.Fatal("wire profile requires owned evidence storage")
	}
	var results []telemetryWireResult
	for _, pin := range []struct{ version, env string }{{"26.6.27", "PSP_TEST_XRAY_26627_BIN"}, {"26.7.28", "PSP_TEST_XRAY_26728_BIN"}, {"26.9.9", "PSP_TEST_XRAY_2699_BIN"}} {
		t.Run(pin.version, func(t *testing.T) {
			binary := os.Getenv(pin.env)
			info, err := os.Stat(binary)
			if err != nil || !filepath.IsAbs(binary) || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
				t.Fatal("wire profile requires exact prepared official core")
			}
			results = append(results, exerciseRealStatsWire(t, binary, pin.version))
		})
	}
	if t.Failed() || len(results) != 3 {
		t.Fatal("wire profile did not complete all official versions")
	}
	result := struct {
		Schema      int                   `json:"schema_version"`
		Source      string                `json:"node_source"`
		Run         uint64                `json:"run_id"`
		LogicalCPUs int                   `json:"logical_cpus"`
		Versions    []telemetryWireResult `json:"versions"`
	}{1, source, run, runtime.NumCPU(), results}
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatal("encode bounded wire profile")
	}
	if err := os.WriteFile(evidence, append(body, '\n'), 0600); err != nil {
		t.Fatal("write bounded wire profile")
	}
}

func exerciseRealStatsWire(t *testing.T, binary, version string) telemetryWireResult {
	t.Helper()
	// Xray deliberately excludes 127.0.0.1 and [::1] from its online map.
	// Keep both actual families observable using exclusively owned local sources.
	const sourceIPv4, sourceIPv6 = "127.0.0.2", "2001:db8:7073:74::2"
	if os.Geteuid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("GITHUB_REPOSITORY") != "KazuhaHub/Passwall-Node" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Fatal("dual-stack source fixture requires the owned disposable hosted runner")
	}
	addresses, err := exec.CommandContext(t.Context(), "ip", "-j", "-6", "addr", "show", "dev", "lo").Output()
	if err != nil {
		t.Fatal("inspect owned IPv6 source fixture")
	}
	var devices []struct {
		Addresses []struct {
			Local string `json:"local"`
		} `json:"addr_info"`
	}
	if json.Unmarshal(addresses, &devices) != nil {
		t.Fatal("decode owned IPv6 source fixture")
	}
	for _, device := range devices {
		for _, address := range device.Addresses {
			if net.ParseIP(address.Local).Equal(net.ParseIP(sourceIPv6)) {
				t.Fatal("IPv6 source fixture is already owned")
			}
		}
	}
	if exec.CommandContext(t.Context(), "ip", "-6", "addr", "add", sourceIPv6+"/128", "dev", "lo", "scope", "host", "nodad").Run() != nil {
		t.Fatal("add exclusive IPv6 source fixture")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if exec.CommandContext(ctx, "ip", "-6", "addr", "del", sourceIPv6+"/128", "dev", "lo").Run() != nil {
			t.Error("remove exclusive IPv6 source fixture")
		}
	})
	const payload = "owned-wire-traffic"
	hold := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		_, _ = io.WriteString(w, payload)
		w.(http.Flusher).Flush()
		select {
		case <-hold:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(hold); target.Close() })
	_, targetPortText, err := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
	if err != nil {
		t.Fatal("bind owned wire target")
	}
	targetPort, err := strconv.Atoi(targetPortText)
	if err != nil {
		t.Fatal("bind owned wire target port")
	}
	f := newTelemetryProfileCore(t, binary, version, targetPort, true)
	queries, online, closed := 0, 0, 0
	wire, err := NewTelemetry(TelemetryOptions{Store: f.store, Status: f.supervisor.Status, APIListen: f.apiListen, Dial: func(ctx context.Context, endpoint string) (grpc.ClientConnInterface, io.Closer, error) {
		connection, closer, err := dialStats(ctx, endpoint)
		if err != nil {
			return connection, closer, err
		}
		return telemetryCountConnection{connection, &queries, &online}, statsCloseFunc(func() error { closed++; return closer.Close() }), nil
	}})
	if err != nil {
		t.Fatal("create real wire telemetry")
	}
	cliQueries, cliOnline := 0, 0
	cli, err := NewTelemetry(TelemetryOptions{Store: f.store, Status: f.supervisor.Status, APIListen: f.apiListen, RunCommand: func(ctx context.Context, binary string, args ...string) ([]byte, error) {
		switch args[1] {
		case "statsquery":
			cliQueries++
		case "statsonlineiplist":
			cliOnline++
		default:
			t.Fatal("unexpected selected CLI query")
		}
		return runTelemetryCommand(ctx, binary, args...)
	}})
	if err != nil {
		t.Fatal("create selected-binary reference telemetry")
	}
	collect := func(telemetry *Telemetry) agentcore.Counters {
		value, err := telemetry.Collect(t.Context())
		if err != nil {
			t.Fatal("real wire conformance query failed; private details withheld")
		}
		if len(value.Clients) != 200 || len(value.Listeners) != 2 {
			t.Fatal("real wire conformance lost complete enumeration")
		}
		return value
	}
	baseline := collect(cli)
	if !reflect.DeepEqual(collect(wire), baseline) {
		t.Fatal("real idle CLI and wire disagree")
	}
	handle, live := f.supervisor.ProcessHandle()
	status := f.supervisor.Status()
	if !live || status.State != agentcore.ProcessRunning {
		t.Fatal("real comparison core is not live")
	}
	stable := func() {
		current, live := f.supervisor.ProcessHandle()
		if !live || current != handle || f.supervisor.Status() != status {
			t.Fatal("core changed during paired comparison")
		}
	}
	cpu := func(who int) uint64 {
		var r syscall.Rusage
		if syscall.Getrusage(who, &r) != nil {
			t.Fatal("read paired CPU")
		}
		return uint64(r.Utime.Sec+r.Stime.Sec)*uint64(time.Second) + uint64(r.Utime.Usec+r.Stime.Usec)*uint64(time.Microsecond)
	}
	result := telemetryWireResult{Version: version, Clients: 200, Listeners: 2}
	for _, mode := range []struct {
		name      string
		telemetry *Telemetry
	}{{"cli", cli}, {"wire", wire}} {
		queries, online, closed, cliQueries, cliOnline = 0, 0, 0, 0, 0
		parentBefore, childBefore := cpu(syscall.RUSAGE_SELF), cpu(syscall.RUSAGE_CHILDREN)
		started := time.Now()
		for range 20 {
			if !reflect.DeepEqual(collect(mode.telemetry), baseline) {
				t.Fatal("paired idle state changed")
			}
			stable()
		}
		elapsed := time.Since(started).Nanoseconds()
		parentAfter, childAfter := cpu(syscall.RUSAGE_SELF), cpu(syscall.RUSAGE_CHILDREN)
		if parentAfter < parentBefore || childAfter < childBefore {
			t.Fatal("paired CPU regressed")
		}
		cost := telemetryModeCost{Mode: mode.name, Rounds: 20, WallNS: elapsed, ParentCPUNS: parentAfter - parentBefore, ChildCPUNS: childAfter - childBefore, Queries: queries, OnlineQueries: online, Closed: closed}
		if mode.name == "cli" {
			cost.Queries, cost.OnlineQueries = cliQueries, cliOnline
			if cliQueries != 20 || cliOnline != 20 {
				t.Fatal("CLI comparison omitted a current query")
			}
		} else if queries != 20 || online != 20 || closed != 20 || cost.ChildCPUNS != 0 {
			t.Fatal("wire comparison skipped a query, leaked or spawned a child")
		}
		result.Modes = append(result.Modes, cost)
		for name, value := range map[string]uint64{mode.name + "_wall_ns": uint64(cost.WallNS), mode.name + "_parent_cpu_ns": cost.ParentCPUNS, mode.name + "_child_cpu_ns": cost.ChildCPUNS} {
			t.Logf("wire fact: %s=%d", name, value)
		}
	}
	// Keep one real connection through each IP family open after its payload is
	// received. Counters are then quiescent, while online IPs remain observable.
	for i, inbound := range f.inbounds {
		source := sourceIPv4
		if i == 1 {
			source = sourceIPv6
		}
		connection, err := (&net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}).DialContext(t.Context(), "tcp", inbound)
		if err != nil {
			t.Fatal("connect real VLESS client")
		}
		t.Cleanup(func() { _ = connection.Close() })
		_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
		id, err := hex.DecodeString(strings.ReplaceAll(f.clients[0].Credentials.UUID, "-", ""))
		if err != nil {
			t.Fatal("encode real VLESS credential")
		}
		header := append([]byte{0}, id...)
		header = append(header, 0, 1, byte(targetPort>>8), byte(targetPort), 1, 127, 0, 0, 1)
		header = append(header, []byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")...)
		if _, err := connection.Write(header); err != nil {
			t.Fatal("send real VLESS payload")
		}
		var responseHeader [2]byte
		if _, err := io.ReadFull(connection, responseHeader[:]); err != nil || responseHeader[0] != 0 {
			t.Fatal("read real VLESS response")
		}
		if _, err := io.CopyN(io.Discard, connection, int64(responseHeader[1])); err != nil {
			t.Fatal("read VLESS response addons")
		}
		response, err := http.ReadResponse(bufio.NewReader(connection), nil)
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatal("read owned VLESS HTTP response")
		}
		body := make([]byte, len(payload))
		if _, err := io.ReadFull(response.Body, body); err != nil || string(body) != payload {
			t.Fatal("real traffic did not reach owned target")
		}
	}
	canonical := func(value agentcore.Counters) agentcore.Counters {
		for i := range value.Clients {
			slices.Sort(value.Clients[i].LiveIPs)
		}
		return value
	}
	deadline := time.Now().Add(5 * time.Second)
	hasSource := func(ips []string, source string) bool {
		for _, ip := range ips {
			if net.ParseIP(strings.Trim(ip, "[]")).Equal(net.ParseIP(source)) {
				return true
			}
		}
		return false
	}
	for {
		cliValue, wireValue := canonical(collect(cli)), canonical(collect(wire))
		stable()
		first := wireValue.Clients[0]
		ips := first.LiveIPs
		if reflect.DeepEqual(cliValue, wireValue) && first.UpBytes > 0 && first.DownBytes > 0 && hasSource(ips, sourceIPv4) && hasSource(ips, sourceIPv6) {
			for _, listener := range wireValue.Listeners {
				if listener.UpBytes <= 0 || listener.DownBytes <= 0 {
					t.Fatal("wire lost actual listener traffic")
				}
			}
			for i := range wireValue.Clients {
				if wireValue.Clients[i].CounterEpoch != baseline.Clients[i].CounterEpoch {
					t.Fatal("read-only queries changed counter epoch")
				}
			}
			result.IPv4, result.IPv6, result.Traffic = 1, 1, 1
			break
		}
		if time.Now().After(deadline) {
			boolean := func(value bool) uint64 {
				if value {
					return 1
				}
				return 0
			}
			for name, value := range map[string]uint64{
				"equal": boolean(reflect.DeepEqual(cliValue, wireValue)), "clients_equal": boolean(reflect.DeepEqual(cliValue.Clients, wireValue.Clients)), "listeners_equal": boolean(reflect.DeepEqual(cliValue.Listeners, wireValue.Listeners)),
				"v4": boolean(hasSource(ips, sourceIPv4)), "v6": boolean(hasSource(ips, sourceIPv6)), "first_key": boolean(first.Key == f.clients[0].Key),
				"cli_ips": uint64(len(cliValue.Clients[0].LiveIPs)), "wire_ips": uint64(len(ips)),
				"cli_up": uint64(cliValue.Clients[0].UpBytes), "cli_down": uint64(cliValue.Clients[0].DownBytes), "wire_up": uint64(first.UpBytes), "wire_down": uint64(first.DownBytes),
			} {
				t.Logf("wire fact: %s=%d", name, value)
			}
			t.Fatal("CLI and wire differ for real counters or dual-stack online IPs")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return result
}

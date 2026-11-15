//go:build !windows

package xray

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/testutil/policylive"
	"github.com/KazuhaHub/passwall-protocol/protocol"
	"golang.org/x/net/proxy"
)

// This file is an opt-in measurement, not a gate: it compares what per-site
// usage costs a real Xray and the receiver. It runs only with
// PSP_TEST_USAGE_LOAD=1 (and the binaries the live tests use).
//
//	PSP_TEST_USAGE_LOAD=1 go test ./internal/core/xray -run TestUsageLoadOverhead -v -timeout 30m
//
// The load generator is this test binary run again as a child process, so the
// CPU of the process that holds the receiver is the receiver's and not the
// generator's. Connections are held open for a while, which makes the
// concurrency what it is on a real node, and are paced, because every
// connection spends one loopback port per hop in TIME_WAIT and an unpaced run
// would exhaust a laptop's ephemeral ports instead of measuring Xray.
//
// Environment: PSP_TEST_LOAD_CONNECTIONS (default 20000), PSP_TEST_LOAD_CONCURRENT
// (default 500), PSP_TEST_LOAD_ROUNDS (default 2), PSP_TEST_LOAD_COOLDOWN_SECONDS
// (default 35, which outlasts macOS's 2*MSL), PSP_TEST_LOAD_RATE (new connections
// per second, default 50: each connection spends three loopback ports, and
// macOS has about 16,000 of them for 30 seconds each, so a faster pace measures
// port exhaustion instead of Xray).

// usageLoadEnv is the one switch that lets anything in this package open more
// than a few dozen connections. Run it only where a runaway cannot reach the
// owner's network: inside a VM, with the client and the server both in it.
const loadGeneratorEnv = "PSP_TEST_LOAD_GENERATOR"

type loadOutcome struct {
	OK, Failed, Peak int64
}

func loadInt(name string, fallback int) int {
	if value, err := strconv.Atoi(os.Getenv(name)); err == nil && value > 0 {
		return value
	}
	return fallback
}

// TestUsageLoadGenerator is the child process. It does nothing in a normal run.
func TestUsageLoadGenerator(t *testing.T) {
	if os.Getenv(loadGeneratorEnv) != "1" {
		t.Skip("helper process of TestUsageLoadOverhead")
	}
	socks := loadInt("LOAD_SOCKS", 0)
	sink := loadInt("LOAD_SINK", 0)
	total := loadInt("LOAD_TOTAL", 0)
	concurrent := loadInt("LOAD_CONCURRENT", 0)
	hold := time.Duration(loadInt("LOAD_HOLD_MS", 0)) * time.Millisecond
	hosts := strings.Split(os.Getenv("LOAD_HOSTS"), ",")
	// Little's law: concurrent = rate * hold.
	interval := hold / time.Duration(concurrent)
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socks), nil, &net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	var inflight, peak, okCount, failed atomic.Int64
	var wg sync.WaitGroup
	next := time.Now()
	for i := 0; i < total; i++ {
		next = next.Add(interval)
		time.Sleep(time.Until(next))
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			now := inflight.Add(1)
			defer inflight.Add(-1)
			for {
				old := peak.Load()
				if now <= old || peak.CompareAndSwap(old, now) {
					break
				}
			}
			conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", host, sink))
			if err != nil {
				if failed.Add(1) == 1 || failed.Load()%2000 == 0 {
					fmt.Fprintf(os.Stderr, "dial failure #%d at connection start: %v\n", failed.Load(), err)
				}
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(hold + 5*time.Second))
			if _, err := conn.Write(httpRequest(host)); err != nil {
				failed.Add(1)
				return
			}
			time.Sleep(hold)
			okCount.Add(1)
		}(hosts[i%len(hosts)])
	}
	wg.Wait()
	outcome, _ := json.Marshal(loadOutcome{OK: okCount.Load(), Failed: failed.Load(), Peak: peak.Load()})
	if err := os.WriteFile(os.Getenv("LOAD_RESULT"), outcome, 0o600); err != nil {
		t.Fatal(err)
	}
}

// processCPU is the CPU seconds a process has used, as ps reports them.
func processCPU(t *testing.T, pid int) float64 {
	t.Helper()
	out, err := exec.Command("ps", "-o", "cputime=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		t.Fatalf("ps: %v", err)
	}
	var seconds float64
	for _, part := range strings.Split(strings.TrimSpace(string(out)), ":") {
		value, err := strconv.ParseFloat(part, 64)
		if err != nil {
			t.Fatalf("cputime %q: %v", out, err)
		}
		seconds = seconds*60 + value
	}
	return seconds
}

func selfCPU(t *testing.T) float64 {
	t.Helper()
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	return float64(usage.Utime.Sec) + float64(usage.Utime.Usec)/1e6 + float64(usage.Stime.Sec) + float64(usage.Stime.Usec)/1e6
}

type loadRun struct {
	mode                      string
	wall                      time.Duration
	xrayCPU, receiverCPU      float64
	ok, failed, peak          int64
	counted                   uint64
	unmatched, droppedUsage   uint64
	unauthorized, droppedHits uint64
	rowCount                  int
}

func runLoad(t *testing.T, usage bool) loadRun {
	t.Helper()
	server := liveAuditVersions(t)[0]
	collect, mode := protocol.CollectHits, "usage off (hits)"
	if usage {
		collect, mode = protocol.CollectHitsAndUsage, "usage on"
	}
	const sites = 20
	hosts := make([]string, sites)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("www.site%d.example", i)
	}
	// A policy of a few rules, as a node has: nothing in the load matches them,
	// so every connection is one the usage record is for.
	policy := &protocol.DestinationPolicy{Collect: collect, Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"full:blocked.example"}},
		{ID: "p2", Action: protocol.RuleObserve, Domains: []string{"full:watched.example"}},
	}}
	live := startLiveAuditServer(t, server.binary, server.version, policy, hosts...)
	total, concurrent := loadInt("PSP_TEST_LOAD_CONNECTIONS", 20000), loadInt("PSP_TEST_LOAD_CONCURRENT", 500)
	result := policylive.WriteFile(t, "load.json", nil)

	command := exec.Command(os.Args[0], "-test.run=^TestUsageLoadGenerator$", "-test.count=1")
	command.Env = append(os.Environ(), loadGeneratorEnv+"=1",
		"LOAD_SOCKS="+strconv.Itoa(live.socksPort), "LOAD_SINK="+strconv.Itoa(live.sinkPort),
		"LOAD_TOTAL="+strconv.Itoa(total), "LOAD_CONCURRENT="+strconv.Itoa(concurrent),
		"LOAD_HOLD_MS="+strconv.Itoa(1000*concurrent/loadInt("PSP_TEST_LOAD_RATE", 50)), "LOAD_HOSTS="+strings.Join(hosts, ","), "LOAD_RESULT="+result)

	xrayBefore, selfBefore, started := processCPU(t, live.serverPID), selfCPU(t), time.Now()
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("load generator: %v\n%s", err, output)
	}
	if lines := strings.Split(strings.TrimSpace(string(output)), "\n"); len(lines) > 0 {
		for _, line := range lines {
			if strings.HasPrefix(line, "dial failure") {
				t.Log(line)
			}
		}
	}
	// The generator is done; give the last webhooks time to arrive.
	run := loadRun{mode: mode}
	var quiet int
	for quiet < 20 {
		taken := live.sink.Take()
		if len(taken.Usage) == 0 && taken.Unmatched == 0 && taken.DroppedUsage == 0 && len(taken.Hits) == 0 {
			quiet++
		} else {
			quiet = 0
		}
		for _, row := range taken.Usage {
			run.counted += uint64(row.Count)
		}
		run.rowCount += len(taken.Usage)
		run.unmatched += taken.Unmatched
		run.droppedUsage += taken.DroppedUsage
		run.droppedHits += taken.DroppedHits
		time.Sleep(100 * time.Millisecond)
	}
	run.wall = time.Since(started) - 2*time.Second
	run.xrayCPU = processCPU(t, live.serverPID) - xrayBefore
	run.receiverCPU = selfCPU(t) - selfBefore - 0 // the drain loop above is idle sleeping
	run.unauthorized = live.sink.Stats().Unauthorized
	raw, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var outcome loadOutcome
	if err := json.Unmarshal(raw, &outcome); err != nil {
		t.Fatalf("generator result %q: %v", raw, err)
	}
	run.ok, run.failed, run.peak = outcome.OK, outcome.Failed, outcome.Peak
	return run
}

func TestUsageLoadOverhead(t *testing.T) {
	if os.Getenv(usageLoadEnv) != "1" {
		t.Skip("set PSP_TEST_USAGE_LOAD=1 to run the usage load measurement")
	}
	rounds := loadInt("PSP_TEST_LOAD_ROUNDS", 2)
	cooldown := time.Duration(loadInt("PSP_TEST_LOAD_COOLDOWN_SECONDS", 35)) * time.Second
	var runs []loadRun
	for round := 0; round < rounds; round++ {
		for _, usage := range []bool{false, true} {
			if mode := os.Getenv("PSP_TEST_LOAD_MODES"); (mode == "off" && usage) || (mode == "on" && !usage) {
				continue
			}
			runs = append(runs, runLoad(t, usage))
			last := runs[len(runs)-1]
			t.Logf("%-17s wall %5.1fs  xray cpu %6.2fs  receiver cpu %6.2fs  ok %d failed %d peak concurrent %d  counted %d rows %d unmatched %d dropped_usage %d dropped_hits %d unauthorized %d",
				last.mode, last.wall.Seconds(), last.xrayCPU, last.receiverCPU, last.ok, last.failed, last.peak,
				last.counted, last.rowCount, last.unmatched, last.droppedUsage, last.droppedHits, last.unauthorized)
			time.Sleep(cooldown)
		}
	}
}

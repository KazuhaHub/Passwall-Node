package host

import (
	"encoding/binary"
	"os"
	"testing"

	agentcore "github.com/KazuhaHub/passwall-node/internal/core"
	"github.com/KazuhaHub/passwall-node/protocol"
)

const (
	corePID       = 4321
	coreStartTick = 700000
	// 1789000000000 is the pinned wall clock; 86400530 ms is the fixture's
	// uptime, so the boot instant is the difference.
	fixtureBootMS = int64(1789000000000) - 86400530
)

// coreFixture is the systemd host with a core process the handle can name.
func coreFixture(t *testing.T, coreStartTicks uint64) *fixture {
	return systemdHostFixture(t).
		proc("4321/stat", procStatLine(corePID, "xray", 400, 50, 40, coreStartTicks, 8000)).
		proc("4321/limits", "Max open files            1048576              1048576              files\n").
		fdEntries("4321/fd", 60)
}

// coreOptions wires a handle pointing at the fixture's core process.
func coreOptions(t *testing.T, startTicks uint64) Options {
	options := coreFixture(t, startTicks).options()
	options.Core = func() (agentcore.ProcessHandle, bool) {
		return agentcore.ProcessHandle{PID: corePID, StartTicks: startTicks}, true
	}
	return options
}

func TestCollectReadsTheAgentProcess(t *testing.T) {
	observation, err := newFixtureCollector(systemdHostFixture(t).options()).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	processes := observation.Processes
	if processes == nil {
		t.Fatal("processes is absent")
	}
	agent := processes.Agent
	if agent.Threads != 12 {
		t.Fatalf("threads = %d", agent.Threads)
	}
	// RSS is reported in pages by the kernel and in bytes by the protocol.
	if agent.RSSBytes != 12000*uint64(os.Getpagesize()) {
		t.Fatalf("rss = %d, want 12000 pages of %d bytes", agent.RSSBytes, os.Getpagesize())
	}
	if agent.FDLimit == nil || *agent.FDLimit != 1024 {
		t.Fatalf("fd limit = %v, want the SOFT limit", agent.FDLimit)
	}
	if agent.OpenFDs != 24 {
		t.Fatalf("open fds = %d", agent.OpenFDs)
	}
	// 900 + 100 ticks at 100 ticks per second.
	if agent.CPUTime == nil || *agent.CPUTime != 1000 {
		t.Fatalf("cpu time = %v", agent.CPUTime)
	}
	if agent.CPUTimeUnitsPerSecond == nil || *agent.CPUTimeUnitsPerSecond != clockTicks {
		t.Fatalf("cpu units = %v", agent.CPUTimeUnitsPerSecond)
	}
	// Boot instant plus the process's own offset from boot.
	want := fixtureBootMS + int64(agentStartTick)*1000/clockTicks
	if agent.StartedAtMS != want {
		t.Fatalf("started_at = %d, want %d", agent.StartedAtMS, want)
	}
	// No PID, no command line, no environment: the protocol has nowhere to put
	// them, and this asserts the collector did not invent a place.
	if err := protocol.ValidateHostObservation(observation); err != nil {
		t.Fatalf("the sample is invalid: %v", err)
	}
}

func TestCollectReadsTheCoreProcessWhenItsIdentityMatches(t *testing.T) {
	observation, err := newFixtureCollector(coreOptions(t, coreStartTick)).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	core := observation.Processes.Core
	if core == nil {
		t.Fatal("core is absent while a verified core is running")
	}
	if core.Threads != 40 || core.OpenFDs != 60 {
		t.Fatalf("core = %#v", core)
	}
	if core.CPUTime == nil || *core.CPUTime != 450 {
		t.Fatalf("core cpu time = %v", core.CPUTime)
	}
	if core.StartedAtMS != fixtureBootMS+int64(coreStartTick)*1000/clockTicks {
		t.Fatalf("core started_at = %d", core.StartedAtMS)
	}
	if containsToken(observation.Unavailable, protocol.UnavailableProcessCore) {
		t.Fatal("a readable core was reported as unavailable")
	}
}

// THE RE-CHECK THIS EXISTS FOR. The handle's start time came from the spawn; the
// file's came from the read the counters came from. A disagreement means the PID
// was recycled, and reporting another process's counters as the core's is worse
// than reporting nothing.
func TestCollectDropsTheCoreSectionWhenThePIDWasRecycled(t *testing.T) {
	options := coreOptions(t, coreStartTick)
	// The process in the fixture is not the process the handle named.
	options.Core = func() (agentcore.ProcessHandle, bool) {
		return agentcore.ProcessHandle{PID: corePID, StartTicks: coreStartTick + 1}, true
	}
	observation, err := newFixtureCollector(options).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if observation.Processes.Core != nil {
		t.Fatalf("a recycled PID was reported as the core: %#v", observation.Processes.Core)
	}
	if !containsToken(observation.Unavailable, protocol.UnavailableProcessCore) {
		t.Fatalf("unavailable = %v, want %s", observation.Unavailable, protocol.UnavailableProcessCore)
	}
	// The agent's own section is unaffected.
	if observation.Processes.Agent.RSSBytes == 0 {
		t.Fatal("the agent section was dropped with the core's")
	}
}

// A core that should be running but cannot be read is a token. A core that is
// simply not running is a business state with no token — and the two must stay
// distinguishable, which is why ProcessHandle returns a separate bool.
func TestCollectDistinguishesAStoppedCoreFromAnUnreadableOne(t *testing.T) {
	stopped := systemdHostFixture(t).options()
	stopped.Core = func() (agentcore.ProcessHandle, bool) { return agentcore.ProcessHandle{}, false }
	observation, err := newFixtureCollector(stopped).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if observation.Processes.Core != nil {
		t.Fatal("a stopped core was reported")
	}
	if containsToken(observation.Unavailable, protocol.UnavailableProcessCore) {
		t.Fatal("a stopped core was reported as an unreadable one")
	}

	// Running, but the handle carries no verifiable identity.
	unverifiable := systemdHostFixture(t).options()
	unverifiable.Core = func() (agentcore.ProcessHandle, bool) {
		return agentcore.ProcessHandle{PID: corePID}, true
	}
	observation, err = newFixtureCollector(unverifiable).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !containsToken(observation.Unavailable, protocol.UnavailableProcessCore) {
		t.Fatalf("unavailable = %v, want %s for an unverifiable handle",
			observation.Unavailable, protocol.UnavailableProcessCore)
	}
}

func TestParseProcStatSurvivesACommWithSpacesAndParentheses(t *testing.T) {
	stat, err := parseProcStat([]byte(procStatLine(4321, "xray) (deleted", 400, 50, 40, 700000, 8000)))
	if err != nil {
		t.Fatal(err)
	}
	if stat.StartTicks != 700000 || stat.UTime != 400 || stat.STime != 50 || stat.Threads != 40 || stat.RSSPages != 8000 {
		t.Fatalf("parsed = %#v", stat)
	}
}

func TestParseProcStatRejectsUnusableLines(t *testing.T) {
	if _, err := parseProcStat([]byte("1234 xray S 1 2 3")); err == nil {
		t.Fatal("a line with no comm delimiter was accepted")
	}
	// A zero start time means the column was read from the wrong position, and
	// it would compare equal to any later unreadable read.
	if _, err := parseProcStat([]byte(procStatLine(1, "x", 1, 1, 1, 0, 1))); err == nil {
		t.Fatal("a zero start time was accepted")
	}
	if _, err := parseProcStat([]byte("1 (x) S 1 2")); err == nil {
		t.Fatal("a truncated line was accepted")
	}
}

// auxv does not describe its own word size, so both layouts have to be tried.
func TestParseClockTicksHandlesBothWordSizes(t *testing.T) {
	if ticks, ok := parseClockTicks(auxvClockTicks(250), binary.NativeEndian); !ok || ticks != 250 {
		t.Fatalf("64-bit layout parsed as (%d, %v)", ticks, ok)
	}
	// The 32-bit layout: AT_CLKTCK followed by its value, four bytes each.
	narrow := make([]byte, 0, 16)
	for _, field := range []uint32{17, 250, 0, 0} {
		var encoded [4]byte
		binary.NativeEndian.PutUint32(encoded[:], field)
		narrow = append(narrow, encoded[:]...)
	}
	if ticks, ok := parseClockTicks(narrow, binary.NativeEndian); !ok || ticks != 250 {
		t.Fatalf("32-bit layout parsed as (%d, %v)", ticks, ok)
	}
	if _, ok := parseClockTicks(nil, binary.NativeEndian); ok {
		t.Fatal("an empty auxv yielded a clock rate")
	}
	if _, ok := parseClockTicks(auxvClockTicks(0), binary.NativeEndian); ok {
		t.Fatal("a zero tick rate was accepted")
	}
}

// Without AT_CLKTCK there is no honest way to report CPU time or a wall-clock
// start time, and a guessed tick rate would be wrong by an unknown factor.
func TestCollectOmitsProcessCPUTimeWithoutAClockRate(t *testing.T) {
	options := systemdHostFixture(t).options()
	removeFixtureFile(t, options.ProcRoot, "self/auxv")
	observation, err := newFixtureCollector(options).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// The whole processes section is omitted: a start time is required by the
	// protocol and is not derivable without the clock rate.
	if observation.Processes != nil {
		t.Fatalf("processes = %#v, want it omitted", observation.Processes)
	}
	if !containsToken(observation.Unavailable, protocol.UnavailableProcessAgent) {
		t.Fatalf("unavailable = %v, want %s", observation.Unavailable, protocol.UnavailableProcessAgent)
	}
}

func TestParseFileDescriptorLimitReadsTheSoftLimit(t *testing.T) {
	raw := []byte("Limit                     Soft Limit           Hard Limit           Units\n" +
		"Max open files            1024                 1048576              files\n" +
		"Max processes             63000                63000                processes\n")
	limit := parseFileDescriptorLimit(raw)
	if limit == nil || *limit != 1024 {
		t.Fatalf("limit = %v, want the soft limit", limit)
	}
	if parseFileDescriptorLimit([]byte("Max processes 1 2 3\n")) != nil {
		t.Fatal("a limits file with no open-file row produced a limit")
	}
}

func TestCollectReadsTheReadOnlyTuningSection(t *testing.T) {
	observation, err := newFixtureCollector(systemdHostFixture(t).options()).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	tuning := observation.Tuning
	if tuning == nil {
		t.Fatal("tuning is absent")
	}
	// Sorted and deduplicated, so an unchanged host encodes identically.
	want := []string{"bbr", "cubic", "reno"}
	if len(tuning.TCPAvailableCongestionControls) != len(want) {
		t.Fatalf("controls = %v", tuning.TCPAvailableCongestionControls)
	}
	for index, control := range want {
		if tuning.TCPAvailableCongestionControls[index] != control {
			t.Fatalf("controls = %v, want %v", tuning.TCPAvailableCongestionControls, want)
		}
	}
	if tuning.TCPDefaultCongestionControl != "cubic" {
		t.Fatalf("default congestion control = %q", tuning.TCPDefaultCongestionControl)
	}
	if tuning.DefaultQdisc != "fq_codel" {
		t.Fatalf("default qdisc = %q", tuning.DefaultQdisc)
	}
}

// The values are rendered to an administrator, and the protocol refuses anything
// that is not a lowercase token — so an unexpected value is dropped here rather
// than carried to the wire, where it would cost the whole sample.
func TestParseTokenListDropsNonTokensAndDuplicates(t *testing.T) {
	tokens := parseTokenList([]byte("reno CUBIC cubic ../../etc/passwd reno"), 32, 32)
	if len(tokens) != 2 || tokens[0] != "cubic" || tokens[1] != "reno" {
		t.Fatalf("tokens = %v", tokens)
	}
	if parseTokenList([]byte("   \n"), 32, 32) != nil {
		t.Fatal("an empty list produced entries")
	}
	// The bound is applied before anything is kept, so an absurd file cannot
	// produce an oversized observation.
	if tokens := parseTokenList([]byte("a b c d e f g h i j"), 3, 32); len(tokens) != 3 {
		t.Fatalf("tokens = %v, want the count bound applied", tokens)
	}
	if tokens := parseTokenList([]byte("aaaaaaaa"), 32, 4); tokens != nil {
		t.Fatalf("an oversized token was kept: %v", tokens)
	}
}

func TestCollectMarksTuningUnavailableWhenAbsent(t *testing.T) {
	options := systemdHostFixture(t).options()
	removeFixtureFile(t, options.ProcRoot, "sys/net/ipv4/tcp_congestion_control")
	removeFixtureFile(t, options.ProcRoot, "sys/net/core/default_qdisc")
	observation, err := newFixtureCollector(options).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// The qdisc is gone and the controls are gone, so the section has a partial
	// answer at most: it must say what is missing rather than look complete.
	for _, token := range []string{protocol.UnavailableTuningCC, protocol.UnavailableTuningQdisc} {
		if !containsToken(observation.Unavailable, token) {
			t.Fatalf("unavailable = %v, want %s", observation.Unavailable, token)
		}
	}
	if observation.Tuning.TCPAvailableCongestionControls == nil {
		t.Fatal("the readable list was dropped with the unreadable scalar")
	}
	if err := protocol.ValidateHostObservation(observation); err != nil {
		t.Fatalf("the sample is invalid: %v", err)
	}
}

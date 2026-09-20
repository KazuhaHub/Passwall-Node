package host

import (
	"strings"
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func TestParseUptimeReadsSecondsAndIgnoresTheIdleTotal(t *testing.T) {
	uptimeMS, err := parseUptime([]byte("86400.53 123456.78\n"))
	if err != nil {
		t.Fatal(err)
	}
	if uptimeMS != 86400530 {
		t.Fatalf("uptimeMS = %d, want 86400530", uptimeMS)
	}
}

func TestParseUptimeRejectsUnusableContent(t *testing.T) {
	for _, raw := range []string{"", "\n", "not-a-number 1.0", "-5.0 1.0"} {
		if _, err := parseUptime([]byte(raw)); err == nil {
			t.Fatalf("uptime %q was accepted", raw)
		}
	}
}

func TestParseBootIDTrimsAndBounds(t *testing.T) {
	bootID, err := parseBootID([]byte("6f1c0f5e-1b1c-4d3f-9c4e-2a5b6c7d8e9f\n"))
	if err != nil {
		t.Fatal(err)
	}
	if bootID != "6f1c0f5e-1b1c-4d3f-9c4e-2a5b6c7d8e9f" {
		t.Fatalf("bootID = %q", bootID)
	}
	if _, err := parseBootID([]byte("\n")); err == nil {
		t.Fatal("an empty boot id was accepted")
	}
	if _, err := parseBootID([]byte(strings.Repeat("b", protocol.MaxBootIDBytes+1))); err == nil {
		t.Fatal("an oversized boot id was accepted")
	}
}

func TestParseOSReleaseHandlesQuotingAndComments(t *testing.T) {
	raw := []byte(`# this is a comment
NAME="Debian GNU/Linux"
ID=debian
VERSION_ID="12"
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
`)
	distributionID, versionID := parseOSRelease(raw)
	if distributionID != "debian" || versionID != "12" {
		t.Fatalf("os-release parsed as (%q, %q)", distributionID, versionID)
	}
}

func TestParseOSReleaseAcceptsSingleQuotesAndBareValues(t *testing.T) {
	distributionID, versionID := parseOSRelease([]byte("ID='ubuntu'\nVERSION_ID=24.04\n"))
	if distributionID != "ubuntu" || versionID != "24.04" {
		t.Fatalf("os-release parsed as (%q, %q)", distributionID, versionID)
	}
}

// Escape sequences are left alone on purpose: the value is displayed to an
// administrator, and expanding "\n" would put a control character into a field
// the protocol validates as printable UTF-8.
func TestParseOSReleaseDoesNotInterpretEscapes(t *testing.T) {
	_, versionID := parseOSRelease([]byte(`VERSION_ID="12\n13"`))
	if versionID != `12\n13` {
		t.Fatalf("versionID = %q, want the literal backslash-n preserved", versionID)
	}
}

func TestParseLoadAvgReadsThreeAverages(t *testing.T) {
	load, err := parseLoadAvg([]byte("0.52 0.58 0.59 2/812 4194304\n"))
	if err != nil {
		t.Fatal(err)
	}
	if load.Load1 != 0.52 || load.Load5 != 0.58 || load.Load15 != 0.59 {
		t.Fatalf("load = %#v", load)
	}
}

func TestParseLoadAvgRejectsUnusableContent(t *testing.T) {
	for _, raw := range []string{"", "1.0 2.0", "a b c", "-1.0 2.0 3.0"} {
		if _, err := parseLoadAvg([]byte(raw)); err == nil {
			t.Fatalf("loadavg %q was accepted", raw)
		}
	}
}

func TestParseSystemCPUKeepsGuestOutOfTheTotal(t *testing.T) {
	// user 100, nice 20, system 30, idle 800, iowait 15, irq 5, softirq 10,
	// steal 20, then guest 40 and guest_nice 5 — which the kernel has ALREADY
	// counted inside user and nice.
	raw := []byte("cpu  100 20 30 800 15 5 10 20 40 5\ncpu0 50 10 15 400 7 2 5 10 20 2\n")
	cpu, err := parseSystemCPU(raw)
	if err != nil {
		t.Fatal(err)
	}
	const wantTotal = 100 + 20 + 30 + 800 + 15 + 5 + 10 + 20
	if cpu.Total != wantTotal {
		t.Fatalf("total = %d, want %d (guest must not be added again)", cpu.Total, wantTotal)
	}
	if cpu.Idle != 800 || cpu.IOWait != 15 || cpu.Steal != 20 {
		t.Fatalf("cpu = %#v", cpu)
	}
}

// A kernel that predates steal (and the other later columns) does not account
// for them at all, so the zero is the kernel's own answer rather than a
// stand-in for a read that failed.
func TestParseSystemCPUAcceptsAnOlderKernelsShorterLine(t *testing.T) {
	cpu, err := parseSystemCPU([]byte("cpu  100 20 30 800\ncpu0 50 10 15 400\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cpu.Total != 950 || cpu.Idle != 800 || cpu.IOWait != 0 || cpu.Steal != 0 {
		t.Fatalf("cpu = %#v", cpu)
	}
}

func TestParseSystemCPURejectsUnusableContent(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"no aggregate line", "cpu0 1 2 3 4\nintr 1 2 3\n"},
		{"too few columns", "cpu 1 2 3\n"},
		{"non-numeric column", "cpu 1 x 3 4\n"},
		{"all-zero counters", "cpu 0 0 0 0 0 0 0 0\n"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := parseSystemCPU([]byte(testCase.raw)); err == nil {
				t.Fatalf("proc stat %q was accepted", testCase.raw)
			}
		})
	}
}

func TestParseMeminfoConvertsKilobytesAndReadsSwap(t *testing.T) {
	raw := []byte(`MemTotal:       16384000 kB
MemFree:         1234567 kB
MemAvailable:    9123456 kB
Buffers:          123456 kB
Cached:          4567890 kB
SwapTotal:       2097152 kB
SwapFree:        1999999 kB
`)
	memory, ok := parseMeminfo(raw)
	if !ok {
		t.Fatal("meminfo was rejected")
	}
	if memory.TotalBytes != 16384000*1024 {
		t.Fatalf("total = %d", memory.TotalBytes)
	}
	if memory.SwapTotalBytes != 2097152*1024 || memory.SwapFreeBytes != 1999999*1024 {
		t.Fatalf("swap = %d / %d", memory.SwapTotalBytes, memory.SwapFreeBytes)
	}
	if memory.AvailableBytes == nil || *memory.AvailableBytes != 9123456*1024 {
		t.Fatalf("available = %v", memory.AvailableBytes)
	}
}

// An old kernel has no MemAvailable, and the estimate everyone reaches for
// tracks it loosely and diverges most under load. Absence must survive as an
// absence so the panel can say so.
func TestParseMeminfoPreservesAMissingMemAvailable(t *testing.T) {
	raw := []byte("MemTotal: 16384000 kB\nMemFree: 1234567 kB\nBuffers: 123456 kB\nCached: 4567890 kB\n")
	memory, ok := parseMeminfo(raw)
	if !ok {
		t.Fatal("meminfo without MemAvailable was rejected")
	}
	if memory.AvailableBytes != nil {
		t.Fatalf("a missing MemAvailable was estimated as %d", *memory.AvailableBytes)
	}
}

func TestParseMeminfoReportsAMissingTotalRatherThanZero(t *testing.T) {
	if memory, ok := parseMeminfo([]byte("MemFree: 1234567 kB\n")); ok {
		t.Fatalf("meminfo without MemTotal was accepted as %#v", memory)
	}
	if _, ok := parseMeminfo([]byte("")); ok {
		t.Fatal("an empty meminfo was accepted")
	}
}

// A host with no swap configured reports zero, which is a real measurement and
// must not be confused with the section being unreadable.
func TestParseMeminfoAcceptsZeroSwap(t *testing.T) {
	memory, ok := parseMeminfo([]byte("MemTotal: 1000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n"))
	if !ok {
		t.Fatal("meminfo was rejected")
	}
	if memory.SwapTotalBytes != 0 || memory.SwapFreeBytes != 0 {
		t.Fatalf("swap = %d / %d", memory.SwapTotalBytes, memory.SwapFreeBytes)
	}
}

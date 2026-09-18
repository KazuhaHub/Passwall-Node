package host

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// THE RULE THIS ENFORCES IS NOT A PERFORMANCE ONE. A program found on PATH has a
// version, a locale, an output format and a privilege set this process does not
// control, and each of them is a way for one request to mean two different
// things on two hosts. It is also the widest command-injection surface
// available. Nothing in this package needs it: every value comes from a fixed
// kernel path.
//
// It is checked by reading the source rather than by trying to observe a program
// being spawned, because the failure being guarded against is someone ADDING the
// import later — and by then nothing at runtime would notice. syscall is
// deliberately allowed: statfs is a system call, not a subprocess.
func TestPackageExecutesNoExternalProgram(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{`"os/exec"`, "exec.Command", "exec.CommandContext", "os.StartProcess"}
	scanned := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		for _, pattern := range forbidden {
			if strings.Contains(string(source), pattern) {
				t.Fatalf("%s uses %s; host telemetry must read fixed kernel paths only", name, pattern)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no source files were scanned")
	}
}

// THE READ-PATH RULE IS WHAT MAKES THE REST OF THIS SUITE MEANINGFUL. Every file
// the collector opens is a constant joined onto an injected root, so pointing
// those roots somewhere empty must hide the real machine completely — otherwise
// the fixtures below would be testing the developer's host, not the fixture.
func TestTheInjectedRootsAreTheOnlySourceOfData(t *testing.T) {
	empty := newFixtureCollector(Options{
		ProcRoot: filepath.Join(t.TempDir(), "proc"),
		SysRoot:  filepath.Join(t.TempDir(), "sys"),
		EtcRoot:  filepath.Join(t.TempDir(), "etc"),
		DataDir:  t.TempDir(),
		Now:      systemdHostFixture(t).options().Now,
	})
	// Uptime is the one fatal read, so an empty root fails outright rather than
	// producing a sample — either way, nothing about this host was read.
	if observation, err := empty.Collect(t.Context()); err == nil {
		t.Fatalf("a collector with empty roots produced a sample: %#v", observation)
	}

	populated := newFixtureCollector(systemdHostFixture(t).options())
	observation, err := populated.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if observation.CPU == nil || observation.Network == nil {
		t.Fatal("the same collector read nothing from a populated root")
	}
}

// BenchmarkCollect reports the cost of one collection.
//
// Run it with -benchtime=100x to reproduce the WP1 acceptance figure. The
// allocation count matters more than the nanoseconds: this runs on the agent's
// own sync loop, and an allocation that grew with the number of interfaces would
// turn observability into the thing being observed.
func BenchmarkCollect(b *testing.B) {
	collector := newFixtureCollector(systemdHostFixture(b).options())
	b.ReportAllocs()
	for b.Loop() {
		if _, err := collector.Collect(b.Context()); err != nil {
			b.Fatal(err)
		}
	}
}

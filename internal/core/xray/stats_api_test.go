package xray

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protowire"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	statesqlite "github.com/KazuhaHub/passwall-node/v4/internal/state/sqlite"
)

// The server returns independently encoded wire bytes, not the client's Go
// message types. Field numbers come from the three pinned official protos.
type statsRawCodec struct{}

func (statsRawCodec) Name() string                      { return "proto" }
func (statsRawCodec) Marshal(value any) ([]byte, error) { return value.([]byte), nil }
func (statsRawCodec) Unmarshal(data []byte, value any) error {
	*value.(*[]byte) = append([]byte(nil), data...)
	return nil
}

func statsBytes(field protowire.Number, value []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(nil, field, protowire.BytesType), value)
}
func statsNumber(field protowire.Number, value uint64) []byte {
	return protowire.AppendVarint(protowire.AppendTag(nil, field, protowire.VarintType), value)
}
func rawStat(name string, value int64) []byte {
	return statsBytes(1, append(statsBytes(1, []byte(name)), statsNumber(2, uint64(value))...))
}
func rawOnline(email string, ips ...string) []byte {
	user := statsBytes(1, []byte(email))
	for _, ip := range ips {
		user = append(user, statsBytes(2, statsBytes(1, []byte(ip)))...)
	}
	return statsBytes(1, user)
}

type statsEpochStore struct {
	state.Store
	claims atomic.Int64
}

func (s *statsEpochStore) ClaimCoreCounterEpoch(ctx context.Context, identity string) (uint64, error) {
	s.claims.Add(1)
	return s.Store.ClaimCoreCounterEpoch(ctx, identity)
}

type statsWireFixture struct {
	telemetry *Telemetry
	store     *statsEpochStore
	status    atomic.Value
	closed    atomic.Int64
	called    atomic.Int64
}
type statsCountCloser struct {
	io.Closer
	closed *atomic.Int64
}

func (c statsCountCloser) Close() error { c.closed.Add(1); return c.Closer.Close() }

func newStatsWireFixture(t *testing.T, response func(context.Context, string) ([]byte, error)) *statsWireFixture {
	t.Helper()
	f := new(statsWireFixture)
	store, err := statesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "stats.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	f.store = &statsEpochStore{Store: store}
	artifact := []byte(`{"inbounds":[{"tag":"psp-lst_1","settings":{"clients":[{"email":"one@example.invalid"}]}}]}`)
	digest := fmt.Sprintf("%x", sha256.Sum256(artifact))
	if err := store.SaveCoreDeployment(t.Context(), state.CoreDeployment{Engine: "xray", Version: "26.6.27", ConfigDigest: digest, Artifact: artifact,
		ConfigBody: []byte(`{"listeners":[{"key":"lst_1"},{"key":"lst_2"}]}`),
		RosterBody: []byte(`{"clients":[{"key":"cli_1","credentials":{"username":"one@example.invalid"}},{"key":"cli_2","credentials":{"username":"two@example.invalid"}}]}`), AppliedAtMS: 1}); err != nil {
		t.Fatal(err)
	}
	f.status.Store(agentcore.Status{State: agentcore.ProcessRunning, Engine: "xray", Version: "26.6.27", BinaryPath: "/xray", ConfigDigest: digest, LastChangedAt: time.Unix(10, 0)})
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.ForceServerCodec(statsRawCodec{}))
	method := func(name string) grpc.MethodDesc {
		return grpc.MethodDesc{MethodName: name, Handler: func(_ any, ctx context.Context, decode func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
			var request []byte
			if err := decode(&request); err != nil {
				return nil, err
			}
			if len(request) != 0 {
				t.Error("Stats request changed empty pattern, reset=false or include_traffic=false")
			}
			f.called.Add(1)
			return response(ctx, name)
		}}
	}
	server.RegisterService(&grpc.ServiceDesc{ServiceName: "xray.app.stats.command.StatsService", HandlerType: (*interface{})(nil), Methods: []grpc.MethodDesc{method("QueryStats"), method("GetUsersStats")}}, struct{}{})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	f.telemetry, err = NewTelemetry(TelemetryOptions{Store: f.store, Status: func() agentcore.Status { return f.status.Load().(agentcore.Status) },
		Dial: func(ctx context.Context, _ string) (grpc.ClientConnInterface, io.Closer, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Error("Stats dial has no request deadline")
			}
			connection, err := grpc.NewClient("passthrough:///stats-test", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }))
			if err != nil {
				return nil, nil, err
			}
			return connection, statsCountCloser{connection, &f.closed}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestStatsWireMatchesCLICompleteCountersAndOwnedResults(t *testing.T) {
	const wide = int64(1<<53 + 7)
	stats := append(rawStat("user>>>one@example.invalid>>>traffic>>>uplink", wide), rawStat("inbound>>>psp-lst_1>>>traffic>>>downlink", 33)...)
	online := rawOnline("one@example.invalid", "2001:db8::1", "192.0.2.1")
	f := newStatsWireFixture(t, func(_ context.Context, method string) ([]byte, error) {
		if method == "QueryStats" {
			return stats, nil
		}
		return online, nil
	})
	cli, err := NewTelemetry(TelemetryOptions{Store: f.store, Status: f.telemetry.status, RunCommand: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[1] == "statsquery" {
			return []byte(fmt.Sprintf(`{"stat":[{"name":"user>>>one@example.invalid>>>traffic>>>uplink","value":"%d"},{"name":"inbound>>>psp-lst_1>>>traffic>>>downlink","value":33}]}`, wide)), nil
		}
		return []byte(`{"users":[{"email":"one@example.invalid","ips":[{"ip":"2001:db8::1"},{"ip":"192.0.2.1"}]}]}`), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	want, err := cli.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.telemetry.Collect(t.Context())
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("wire and selected-binary semantics differ", err)
	}
	if len(got.Clients) != 2 || len(got.Listeners) != 2 || got.Clients[0].UpBytes != wide || !got.Clients[0].Present || got.Clients[1].Present || got.Listeners[1].Present {
		t.Fatal("wire lost complete applied presence or integer precision")
	}
	got.Clients[0].LiveIPs[0] = "mutated"
	next, err := f.telemetry.Collect(t.Context())
	if err != nil || !reflect.DeepEqual(next, want) {
		t.Fatal("wire reused old or caller-owned response data", err)
	}
	if f.closed.Load() != 2 || f.called.Load() != 4 {
		t.Fatal("wire did not close each connection or execute both current reads")
	}
}

func TestStatsWireRejectsInvalidOrOversizedResponsesWithoutEpochClaim(t *testing.T) {
	for _, test := range []struct {
		name, method string
		body         []byte
		message      string
	}{
		{"counter_negative", "QueryStats", rawStat("counter", -1), "invalid counter"},
		{"counter_duplicate", "QueryStats", append(rawStat("counter", 1), rawStat("counter", 2)...), "duplicate counter"},
		{"counter_empty", "QueryStats", rawStat("", 1), "invalid counter"},
		{"online_no_email", "GetUsersStats", rawOnline("", "192.0.2.1"), "without email"},
		{"online_duplicate", "GetUsersStats", append(rawOnline("one", "192.0.2.1"), rawOnline("one", "192.0.2.2")...), "duplicate online user"},
		{"online_empty_ip", "GetUsersStats", rawOnline("one", ""), "empty online IP"},
		{"wire_limit", "QueryStats", make([]byte, maxStatsWireBytes+1), "larger than max"},
		{"json_limit", "QueryStats", rawStat(strings.Repeat("\x00", 3<<20), 1), "output exceeds"},
		{"malformed_wire", "QueryStats", []byte{0x0a, 0xff}, "unmarshal"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newStatsWireFixture(t, func(_ context.Context, method string) ([]byte, error) {
				if method == test.method {
					return test.body, nil
				}
				return nil, nil
			})
			got, err := f.telemetry.Collect(t.Context())
			if err == nil || !strings.Contains(err.Error(), test.message) || len(got.Clients) != 0 || len(got.Listeners) != 0 || f.store.claims.Load() != 0 || f.closed.Load() != 1 {
				t.Fatal("invalid wire response escaped, claimed epoch or leaked connection", err)
			}
		})
	}
}

func TestStatsWireCancellationAndDeadlineReleaseConnection(t *testing.T) {
	for _, method := range []string{"QueryStats", "GetUsersStats"} {
		t.Run(method, func(t *testing.T) {
			started := make(chan struct{})
			f := newStatsWireFixture(t, func(ctx context.Context, name string) ([]byte, error) {
				if name == method {
					close(started)
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return nil, nil
			})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := f.telemetry.Collect(ctx); done <- err }()
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("wire request did not start")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("wire cancellation changed", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("wire ignored cancellation")
			}
			if f.closed.Load() != 1 || f.store.claims.Load() != 0 {
				t.Fatal("canceled wire leaked or claimed epoch")
			}
		})
	}
	f := newStatsWireFixture(t, func(ctx context.Context, _ string) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() })
	f.telemetry.timeout = 100 * time.Millisecond
	if _, err := f.telemetry.Collect(t.Context()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("wire did not honor command deadline", err)
	}
	if f.closed.Load() != 1 || f.store.claims.Load() != 0 {
		t.Fatal("expired wire leaked or claimed epoch")
	}
}

func TestStatsWireRejectsProcessChangeAndRecoversAfterFailure(t *testing.T) {
	var change atomic.Bool
	change.Store(true)
	var f *statsWireFixture
	f = newStatsWireFixture(t, func(_ context.Context, method string) ([]byte, error) {
		if method == "GetUsersStats" && change.Swap(false) {
			s := f.status.Load().(agentcore.Status)
			s.RestartCount++
			f.status.Store(s)
		}
		return nil, nil
	})
	if _, err := f.telemetry.Collect(t.Context()); err == nil || !strings.Contains(err.Error(), "changed during telemetry") || f.store.claims.Load() != 0 {
		t.Fatal("wire claimed mixed process counters", err)
	}
	if got, err := f.telemetry.Collect(t.Context()); err != nil || len(got.Clients) != 2 || f.store.claims.Load() != 1 || f.closed.Load() != 2 {
		t.Fatal("wire did not recover with current process identity", err)
	}
}

type statsInvokeFunc func(context.Context, string, any, any, ...grpc.CallOption) error

func (f statsInvokeFunc) Invoke(ctx context.Context, method string, request, response any, options ...grpc.CallOption) error {
	return f(ctx, method, request, response, options...)
}
func (statsInvokeFunc) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errors.New("unexpected streaming API")
}

type statsCloseFunc func() error

func (f statsCloseFunc) Close() error { return f() }

func TestStatsWireUsesFreshTimeoutForSecondReadAndClosesFailedDial(t *testing.T) {
	f := newStatsWireFixture(t, func(context.Context, string) ([]byte, error) { return nil, nil })
	var first context.Context
	f.telemetry.dial = func(ctx context.Context, _ string) (grpc.ClientConnInterface, io.Closer, error) {
		return statsInvokeFunc(func(ctx context.Context, method string, _, _ any, _ ...grpc.CallOption) error {
			if method == queryStatsMethod {
				first = ctx
				return nil
			}
			before, _ := first.Deadline()
			after, _ := ctx.Deadline()
			if first.Err() != context.Canceled || ctx.Err() != nil || !after.After(before) {
				t.Error("second wire call reused the first timeout budget")
			}
			return nil
		}), statsCloseFunc(func() error { f.closed.Add(1); return nil }), nil
	}
	if _, err := f.telemetry.Collect(t.Context()); err != nil {
		t.Fatal(err)
	}
	dialFailure := errors.New("injected dial failure")
	f.telemetry.dial = func(context.Context, string) (grpc.ClientConnInterface, io.Closer, error) {
		return nil, statsCloseFunc(func() error { f.closed.Add(1); return nil }), dialFailure
	}
	if _, err := f.telemetry.Collect(t.Context()); !errors.Is(err, dialFailure) || f.closed.Load() != 2 {
		t.Fatal("failed wire dial leaked resources or lost its cause", err)
	}
}

func TestStatsWireVersionGateAndJSONBudget(t *testing.T) {
	for _, version := range []string{"26.6.27", "26.7.28", "26.9.9"} {
		if !supportsStatsWire(version) {
			t.Fatal("audited wire version missing")
		}
	}
	for _, version := range []string{"", "v26.6.27", "26.7.11", "26.10.0", "latest"} {
		if supportsStatsWire(version) {
			t.Fatal("unaudited version lost the selected-binary CLI path")
		}
	}
	body, err := encodeStatsJSON(&statsQueryResponse{Stats: []*statsValue{{Name: "<counter>", Value: 1<<53 + 7}}})
	if err != nil || strings.Contains(string(body), `\u003c`) || !strings.HasSuffix(string(body), "\n\n") {
		t.Fatal("wire changed CLI JSON escaping or output budget", err)
	}
	var response map[string]any
	if json.Unmarshal(body, &response) != nil {
		t.Fatal("wire output is not JSON")
	}
}

func TestStatsWireUnverifiedVersionRetainsCurrentCLIReads(t *testing.T) {
	f := newStatsWireFixture(t, func(context.Context, string) ([]byte, error) { return nil, errors.New("wire must not run") })
	deployment, err := f.store.CoreDeployment(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	deployment.Version = "26.7.11"
	if err := f.store.SaveCoreDeployment(t.Context(), deployment); err != nil {
		t.Fatal(err)
	}
	s := f.status.Load().(agentcore.Status)
	s.Version = deployment.Version
	f.status.Store(s)
	calls := 0
	f.telemetry.runCommand = func(context.Context, string, ...string) ([]byte, error) { calls++; return []byte(`{}`), nil }
	f.telemetry.dial = func(context.Context, string) (grpc.ClientConnInterface, io.Closer, error) {
		t.Fatal("unaudited core used wire")
		return nil, nil, nil
	}
	if got, err := f.telemetry.Collect(t.Context()); err != nil || len(got.Clients) != 2 || calls != 2 {
		t.Fatal("unaudited core lost complete current CLI reads", err)
	}
}

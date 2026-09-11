package singbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/internal/core"
	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const (
	connectionEventNew    = 0
	connectionEventUpdate = 1
	connectionEventClosed = 2
	streamInterval        = time.Second
	statusPollInterval    = 250 * time.Millisecond
	streamRetryMax        = 5 * time.Second
	maxGRPCMessageBytes   = 16 << 20
)

type trafficStore interface {
	CoreDeployment(context.Context) (state.CoreDeployment, error)
	ClaimCoreCounterEpoch(context.Context, string) (uint64, error)
	ApplyCoreTrafficEvents(context.Context, string, bool, []state.CoreTrafficEvent) error
	CoreTrafficSnapshot(context.Context, string) (state.CoreTrafficSnapshot, error)
}

type TelemetryOptions struct {
	Store     trafficStore
	Status    func() agentcore.Status
	APIListen string
	APISecret string
	OnError   func(error)
	Dial      func(context.Context, string) (grpc.ClientConnInterface, io.Closer, error)
}

// Telemetry continuously journals sing-box connection events before exposing
// cumulative counters to the normal observation loop. This is required because
// sing-box exposes per-connection deltas, not a durable per-user counter query.
type Telemetry struct {
	store     trafficStore
	status    func() agentcore.Status
	apiListen string
	apiSecret string
	onError   func(error)
	dial      func(context.Context, string) (grpc.ClientConnInterface, io.Closer, error)
}

func NewTelemetry(options TelemetryOptions) (*Telemetry, error) {
	if options.Store == nil || options.Status == nil {
		return nil, errors.New("state store and core status provider are required")
	}
	if err := validateLoopbackEndpoint(options.APIListen); err != nil {
		return nil, fmt.Errorf("sing-box telemetry API listen: %w", err)
	}
	if strings.TrimSpace(options.APISecret) != options.APISecret || len(options.APISecret) < 32 {
		return nil, errors.New("sing-box telemetry API secret must be at least 32 canonical characters")
	}
	if options.OnError == nil {
		options.OnError = func(error) {}
	}
	if options.Dial == nil {
		options.Dial = func(_ context.Context, endpoint string) (grpc.ClientConnInterface, io.Closer, error) {
			connection, err := grpc.NewClient(endpoint,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxGRPCMessageBytes)),
			)
			return connection, connection, err
		}
	}
	return &Telemetry{
		store: options.Store, status: options.Status, apiListen: options.APIListen,
		apiSecret: options.APISecret, onError: options.OnError, dial: options.Dial,
	}, nil
}

func (t *Telemetry) Run(ctx context.Context) error {
	retry := statusPollInterval
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		status := t.status()
		if status.State != agentcore.ProcessRunning || status.Engine != "sing-box" {
			if !waitContext(ctx, statusPollInterval) {
				return nil
			}
			retry = statusPollInterval
			continue
		}
		if err := t.stream(ctx, status); err != nil && ctx.Err() == nil {
			t.onError(fmt.Errorf("sing-box telemetry stream: %w", err))
			if !waitContext(ctx, retry) {
				return nil
			}
			retry *= 2
			if retry > streamRetryMax {
				retry = streamRetryMax
			}
			continue
		}
		retry = statusPollInterval
	}
}

func (t *Telemetry) Collect(ctx context.Context) (agentcore.Counters, error) {
	status := t.status()
	if status.State != agentcore.ProcessRunning {
		return agentcore.Counters{}, fmt.Errorf("sing-box process is %s", status.State)
	}
	if status.Engine != "sing-box" {
		return agentcore.Counters{}, fmt.Errorf("running core engine is %q, not sing-box", status.Engine)
	}
	deployment, mapping, err := t.confirmedMapping(ctx, status)
	if err != nil {
		return agentcore.Counters{}, err
	}
	identity := processIdentity(status)
	snapshot, err := t.store.CoreTrafficSnapshot(ctx, identity)
	if err != nil {
		return agentcore.Counters{}, err
	}
	if !snapshot.Ready {
		return agentcore.Counters{}, errors.New("sing-box telemetry stream has not completed its initial snapshot")
	}
	epoch, err := t.store.ClaimCoreCounterEpoch(ctx, identity)
	if err != nil {
		return agentcore.Counters{}, err
	}
	return assembleSingBoxCounters(deployment, mapping, snapshot, epoch), nil
}

func (t *Telemetry) stream(ctx context.Context, observed agentcore.Status) error {
	_, mapping, err := t.confirmedMapping(ctx, observed)
	if err != nil {
		return err
	}
	identity := processIdentity(observed)
	connection, closer, err := t.dial(ctx, t.apiListen)
	if err != nil {
		return fmt.Errorf("dial API: %w", err)
	}
	defer closer.Close()
	streamCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+t.apiSecret)
	stream, err := subscribeConnections(streamCtx, connection, int64(streamInterval))
	if err != nil {
		return fmt.Errorf("subscribe connections: %w", err)
	}
	connections := make(map[string]connectionIdentity)
	first := true
	for {
		message, err := stream.Recv()
		if err != nil {
			return err
		}
		if first && !message.Reset_ {
			return errors.New("initial connection event batch is not a reset snapshot")
		}
		if current := t.status(); processIdentity(current) != identity || current.Engine != "sing-box" || current.State != agentcore.ProcessRunning {
			return errors.New("running core changed during telemetry stream")
		}
		events, nextConnections, err := translateConnectionEvents(message, mapping, connections)
		if err != nil {
			return err
		}
		if err := t.store.ApplyCoreTrafficEvents(ctx, identity, message.Reset_, events); err != nil {
			return err
		}
		connections = nextConnections
		first = false
	}
}

type telemetryMapping struct {
	listeners       []protocol.ListenerKey
	clients         []protocol.Client
	listenerByTag   map[string]protocol.ListenerKey
	clientByName    map[string]protocol.ClientKey
	presentListener map[protocol.ListenerKey]bool
	presentClient   map[protocol.ClientKey]bool
}

func (t *Telemetry) confirmedMapping(ctx context.Context, status agentcore.Status) (state.CoreDeployment, telemetryMapping, error) {
	if status.Engine != "sing-box" || status.Version == "" || status.BinaryPath == "" || status.ConfigDigest == "" || status.LastChangedAt.IsZero() {
		return state.CoreDeployment{}, telemetryMapping{}, errors.New("running sing-box status is incomplete")
	}
	deployment, err := t.store.CoreDeployment(ctx)
	if err != nil {
		return state.CoreDeployment{}, telemetryMapping{}, err
	}
	if deployment.Engine != "sing-box" || deployment.Version != status.Version || deployment.ConfigDigest != status.ConfigDigest {
		return state.CoreDeployment{}, telemetryMapping{}, errors.New("running sing-box status does not match the confirmed deployment snapshot")
	}
	mapping, err := decodeTelemetryMapping(deployment)
	return deployment, mapping, err
}

type connectionIdentity struct {
	client   protocol.ClientKey
	listener protocol.ListenerKey
	sourceIP string
}

func translateConnectionEvents(message *connectionEvents, mapping telemetryMapping, current map[string]connectionIdentity) ([]state.CoreTrafficEvent, map[string]connectionIdentity, error) {
	if message == nil {
		return nil, nil, errors.New("nil sing-box connection event batch")
	}
	next := make(map[string]connectionIdentity, len(current)+len(message.Events))
	if !message.Reset_ {
		for key, value := range current {
			next[key] = value
		}
	}
	result := make([]state.CoreTrafficEvent, 0, len(message.Events))
	for _, event := range message.Events {
		if event == nil || strings.TrimSpace(event.ID) == "" || event.UplinkDelta < 0 || event.DownlinkDelta < 0 {
			return nil, nil, errors.New("sing-box returned an invalid connection event")
		}
		identity, exists := next[event.ID]
		if event.Connection != nil {
			var err error
			identity, err = identifyConnection(event.Connection, mapping)
			if err != nil {
				return nil, nil, fmt.Errorf("connection %s: %w", event.ID, err)
			}
			exists = true
		}
		if !exists {
			return nil, nil, fmt.Errorf("connection %s event arrived without metadata", event.ID)
		}
		translated := state.CoreTrafficEvent{
			ConnectionID: event.ID, ClientKey: identity.client, ListenerKey: identity.listener, SourceIP: identity.sourceIP,
		}
		switch event.Type {
		case connectionEventNew:
			if event.Connection == nil || event.Connection.UplinkTotal < 0 || event.Connection.DownlinkTotal < 0 {
				return nil, nil, fmt.Errorf("connection %s new event lacks valid absolute counters", event.ID)
			}
			translated.Absolute = true
			translated.UpBytes = event.Connection.UplinkTotal
			translated.DownBytes = event.Connection.DownlinkTotal
			translated.Closed = event.Connection.ClosedAt > 0
			translated.ClosedAtMS = event.Connection.ClosedAt
		case connectionEventUpdate:
			translated.UpBytes = event.UplinkDelta
			translated.DownBytes = event.DownlinkDelta
		case connectionEventClosed:
			if event.Connection == nil || event.Connection.UplinkTotal < 0 || event.Connection.DownlinkTotal < 0 {
				return nil, nil, fmt.Errorf("connection %s close event lacks valid absolute counters", event.ID)
			}
			translated.Absolute = true
			translated.UpBytes = event.Connection.UplinkTotal
			translated.DownBytes = event.Connection.DownlinkTotal
			translated.Closed = true
			translated.ClosedAtMS = firstPositive(event.ClosedAt, event.Connection.ClosedAt)
			if translated.ClosedAtMS <= 0 {
				return nil, nil, fmt.Errorf("connection %s close event lacks timestamp", event.ID)
			}
		default:
			return nil, nil, fmt.Errorf("connection %s has unknown event type %d", event.ID, event.Type)
		}
		result = append(result, translated)
		if translated.Closed {
			delete(next, event.ID)
		} else {
			next[event.ID] = identity
		}
	}
	return result, next, nil
}

func identifyConnection(value *connection, mapping telemetryMapping) (connectionIdentity, error) {
	listener, exists := mapping.listenerByTag[value.Inbound]
	if !exists {
		return connectionIdentity{}, fmt.Errorf("unknown managed inbound %q", value.Inbound)
	}
	client, exists := mapping.clientByName[value.User]
	if !exists {
		return connectionIdentity{}, fmt.Errorf("unknown managed user %q", value.User)
	}
	host, _, err := net.SplitHostPort(value.Source)
	if err != nil {
		return connectionIdentity{}, fmt.Errorf("source %q: %w", value.Source, err)
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return connectionIdentity{}, fmt.Errorf("source IP %q: %w", host, err)
	}
	return connectionIdentity{client: client, listener: listener, sourceIP: address.Unmap().String()}, nil
}

func decodeTelemetryMapping(deployment state.CoreDeployment) (telemetryMapping, error) {
	var desiredConfig protocol.ConfigBody
	if err := json.Unmarshal(deployment.ConfigBody, &desiredConfig); err != nil {
		return telemetryMapping{}, fmt.Errorf("decode applied config: %w", err)
	}
	var desiredRoster protocol.RosterBody
	if err := json.Unmarshal(deployment.RosterBody, &desiredRoster); err != nil {
		return telemetryMapping{}, fmt.Errorf("decode applied roster: %w", err)
	}
	result := telemetryMapping{
		clients:       append([]protocol.Client(nil), desiredRoster.Clients...),
		listenerByTag: make(map[string]protocol.ListenerKey), clientByName: make(map[string]protocol.ClientKey),
		presentListener: make(map[protocol.ListenerKey]bool), presentClient: make(map[protocol.ClientKey]bool),
	}
	for _, listener := range desiredConfig.Listeners {
		if _, err := listener.Key.RowID(); err != nil {
			return telemetryMapping{}, fmt.Errorf("applied listener key %q: %w", listener.Key, err)
		}
		result.listeners = append(result.listeners, listener.Key)
		result.listenerByTag["psp-"+string(listener.Key)] = listener.Key
	}
	for _, client := range desiredRoster.Clients {
		if _, err := client.Key.RowID(); err != nil {
			return telemetryMapping{}, fmt.Errorf("applied client key %q: %w", client.Key, err)
		}
		name := client.Credentials.Username
		if name == "" {
			return telemetryMapping{}, fmt.Errorf("applied client %s has no statistics username", client.Key)
		}
		if other, exists := result.clientByName[name]; exists {
			return telemetryMapping{}, fmt.Errorf("statistics username %q belongs to both %s and %s", name, other, client.Key)
		}
		result.clientByName[name] = client.Key
	}
	var artifact struct {
		Inbounds []struct {
			Tag   string `json:"tag"`
			Users []struct {
				Name string `json:"name"`
			} `json:"users"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(deployment.Artifact, &artifact); err != nil {
		return telemetryMapping{}, fmt.Errorf("decode applied sing-box artifact: %w", err)
	}
	for _, inbound := range artifact.Inbounds {
		listener, exists := result.listenerByTag[inbound.Tag]
		if !exists {
			return telemetryMapping{}, fmt.Errorf("applied sing-box contains unknown inbound %q", inbound.Tag)
		}
		result.presentListener[listener] = true
		for _, user := range inbound.Users {
			client, exists := result.clientByName[user.Name]
			if !exists {
				return telemetryMapping{}, fmt.Errorf("applied sing-box inbound %s contains unknown user %q", listener, user.Name)
			}
			result.presentClient[client] = true
		}
	}
	sort.Slice(result.listeners, func(i, j int) bool { return result.listeners[i] < result.listeners[j] })
	sort.Slice(result.clients, func(i, j int) bool { return result.clients[i].Key < result.clients[j].Key })
	return result, nil
}

func assembleSingBoxCounters(_ state.CoreDeployment, mapping telemetryMapping, snapshot state.CoreTrafficSnapshot, epoch uint64) agentcore.Counters {
	result := agentcore.Counters{
		Clients:   make([]agentcore.ClientCounters, 0, len(mapping.clients)),
		Listeners: make([]agentcore.ListenerCounters, 0, len(mapping.listeners)),
	}
	for _, client := range mapping.clients {
		value := snapshot.Clients[client.Key]
		result.Clients = append(result.Clients, agentcore.ClientCounters{
			Key: client.Key, Present: mapping.presentClient[client.Key], UpBytes: value.UpBytes,
			DownBytes: value.DownBytes, CounterEpoch: epoch, LiveIPs: append([]string(nil), value.LiveIPs...),
		})
	}
	for _, listener := range mapping.listeners {
		value := snapshot.Listeners[listener]
		result.Listeners = append(result.Listeners, agentcore.ListenerCounters{
			Key: listener, Present: mapping.presentListener[listener], UpBytes: value.UpBytes,
			DownBytes: value.DownBytes, CounterEpoch: epoch,
		})
	}
	return result
}

func processIdentity(status agentcore.Status) string {
	return fmt.Sprintf("%s|%s|%s|%s|%d|%d", status.Engine, status.Version, status.BinaryPath,
		status.ConfigDigest, status.RestartCount, status.LastChangedAt.UnixNano())
}

func firstPositive(values ...int64) int64 {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func waitContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

var _ agentcore.Telemetry = (*Telemetry)(nil)

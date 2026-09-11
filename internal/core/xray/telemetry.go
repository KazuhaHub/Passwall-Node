package xray

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/internal/core"
	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

const (
	defaultTelemetryTimeout = 5 * time.Second
	maxTelemetryOutput      = 16 << 20
)

type CommandRunner func(context.Context, string, ...string) ([]byte, error)

type TelemetryOptions struct {
	Store          state.Store
	Status         func() agentcore.Status
	APIListen      string
	CommandTimeout time.Duration
	RunCommand     CommandRunner
}

// Telemetry queries the running Xray binary's own CLI. This deliberately
// avoids linking one Xray Go API version into the agent while the selected
// child binary may be another audited release. Mapping uses the last confirmed
// deployment snapshot, never the newer received desired documents.
type Telemetry struct {
	store      state.Store
	status     func() agentcore.Status
	apiListen  string
	timeout    time.Duration
	runCommand CommandRunner
}

func NewTelemetry(options TelemetryOptions) (*Telemetry, error) {
	if options.Store == nil || options.Status == nil {
		return nil, errors.New("state store and core status provider are required")
	}
	apiListen := strings.TrimSpace(options.APIListen)
	if apiListen == "" {
		apiListen = defaultAPIListen
	}
	if err := validateLoopbackEndpoint(apiListen); err != nil {
		return nil, fmt.Errorf("xray telemetry API listen: %w", err)
	}
	if options.CommandTimeout <= 0 {
		options.CommandTimeout = defaultTelemetryTimeout
	}
	if options.RunCommand == nil {
		options.RunCommand = runTelemetryCommand
	}
	return &Telemetry{
		store: options.Store, status: options.Status, apiListen: apiListen,
		timeout: options.CommandTimeout, runCommand: options.RunCommand,
	}, nil
}

func (t *Telemetry) Collect(ctx context.Context) (agentcore.Counters, error) {
	status := t.status()
	if status.State != agentcore.ProcessRunning {
		return agentcore.Counters{}, fmt.Errorf("xray process is %s", status.State)
	}
	if status.Engine != "xray" {
		return agentcore.Counters{}, fmt.Errorf("running core engine is %q, not xray", status.Engine)
	}
	if status.Version == "" || status.BinaryPath == "" || status.ConfigDigest == "" || status.LastChangedAt.IsZero() {
		return agentcore.Counters{}, errors.New("running Xray status is incomplete")
	}
	deployment, err := t.store.CoreDeployment(ctx)
	if err != nil {
		return agentcore.Counters{}, err
	}
	if deployment.Engine != "xray" || deployment.Version != status.Version || deployment.ConfigDigest != status.ConfigDigest {
		return agentcore.Counters{}, errors.New("running Xray status does not match the confirmed deployment snapshot")
	}
	listeners, err := decodeTelemetryConfig(deployment.ConfigBody)
	if err != nil {
		return agentcore.Counters{}, err
	}
	roster, clientByEmail, err := decodeTelemetryRoster(deployment.RosterBody)
	if err != nil {
		return agentcore.Counters{}, err
	}
	presentListeners, presentClients, err := decodeXrayPresence(deployment.Artifact, clientByEmail)
	if err != nil {
		return agentcore.Counters{}, err
	}

	timeoutSeconds := int((t.timeout + time.Second - 1) / time.Second)
	if timeoutSeconds < 1 {
		timeoutSeconds = 1
	}
	statsJSON, err := t.command(ctx, status.BinaryPath, "api", "statsquery",
		"--server="+t.apiListen, "--timeout="+strconv.Itoa(timeoutSeconds))
	if err != nil {
		return agentcore.Counters{}, fmt.Errorf("query Xray counters: %w", err)
	}
	onlineJSON, err := t.command(ctx, status.BinaryPath, "api", "statsonlineiplist",
		"--server="+t.apiListen, "--timeout="+strconv.Itoa(timeoutSeconds), "-all")
	if err != nil {
		return agentcore.Counters{}, fmt.Errorf("query Xray online IPs: %w", err)
	}
	stats, err := decodeStats(statsJSON)
	if err != nil {
		return agentcore.Counters{}, err
	}
	online, err := decodeOnline(onlineJSON)
	if err != nil {
		return agentcore.Counters{}, err
	}
	identity := fmt.Sprintf("%s|%s|%s|%d|%d", status.Version, status.BinaryPath, status.ConfigDigest,
		status.RestartCount, status.LastChangedAt.UnixNano())
	epoch, err := t.store.ClaimCoreCounterEpoch(ctx, identity)
	if err != nil {
		return agentcore.Counters{}, err
	}
	return assembleCounters(listeners, roster, clientByEmail, presentListeners, presentClients, stats, online, epoch), nil
}

func (t *Telemetry) command(ctx context.Context, binary string, args ...string) ([]byte, error) {
	commandCtx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	output, err := t.runCommand(commandCtx, binary, args...)
	if err != nil {
		if commandCtx.Err() != nil {
			return nil, commandCtx.Err()
		}
		return nil, err
	}
	if len(output) > maxTelemetryOutput {
		return nil, fmt.Errorf("Xray API output exceeds %d bytes", maxTelemetryOutput)
	}
	return output, nil
}

type telemetryRoster struct {
	Clients []protocol.Client `json:"clients"`
}

func decodeTelemetryConfig(body []byte) ([]protocol.ListenerKey, error) {
	var config protocol.ConfigBody
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, fmt.Errorf("decode applied config: %w", err)
	}
	listeners := make([]protocol.ListenerKey, 0, len(config.Listeners))
	seen := make(map[protocol.ListenerKey]struct{}, len(config.Listeners))
	for _, listener := range config.Listeners {
		if _, err := listener.Key.RowID(); err != nil {
			return nil, fmt.Errorf("applied listener key %q: %w", listener.Key, err)
		}
		if _, exists := seen[listener.Key]; exists {
			return nil, fmt.Errorf("applied listener %s is duplicated", listener.Key)
		}
		seen[listener.Key] = struct{}{}
		listeners = append(listeners, listener.Key)
	}
	return listeners, nil
}

func decodeTelemetryRoster(body []byte) (telemetryRoster, map[string]protocol.ClientKey, error) {
	var roster telemetryRoster
	if err := json.Unmarshal(body, &roster); err != nil {
		return telemetryRoster{}, nil, fmt.Errorf("decode applied roster: %w", err)
	}
	byEmail := make(map[string]protocol.ClientKey, len(roster.Clients))
	for _, client := range roster.Clients {
		email := client.Credentials.Username
		if email == "" {
			return telemetryRoster{}, nil, fmt.Errorf("applied client %s has no statistics username", client.Key)
		}
		if other, exists := byEmail[email]; exists {
			return telemetryRoster{}, nil, fmt.Errorf("statistics username %q belongs to both %s and %s", email, other, client.Key)
		}
		byEmail[email] = client.Key
	}
	return roster, byEmail, nil
}

func decodeXrayPresence(artifact []byte, clientByEmail map[string]protocol.ClientKey) (map[protocol.ListenerKey]bool, map[protocol.ClientKey]bool, error) {
	var config struct {
		Inbounds []struct {
			Tag      string          `json:"tag"`
			Settings json.RawMessage `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(artifact, &config); err != nil {
		return nil, nil, fmt.Errorf("decode applied Xray artifact: %w", err)
	}
	listeners := make(map[protocol.ListenerKey]bool)
	clients := make(map[protocol.ClientKey]bool)
	for _, inbound := range config.Inbounds {
		keyText, managed := strings.CutPrefix(inbound.Tag, "psp-")
		if !managed {
			continue
		}
		key := protocol.ListenerKey(keyText)
		if _, err := key.RowID(); err != nil {
			return nil, nil, fmt.Errorf("applied Xray inbound tag %q: %w", inbound.Tag, err)
		}
		listeners[key] = true
		var settings struct {
			Clients []struct {
				Email string `json:"email"`
			} `json:"clients"`
		}
		if len(inbound.Settings) != 0 {
			if err := json.Unmarshal(inbound.Settings, &settings); err != nil {
				return nil, nil, fmt.Errorf("decode applied Xray inbound %s clients: %w", key, err)
			}
		}
		for _, user := range settings.Clients {
			clientKey, exists := clientByEmail[user.Email]
			if !exists {
				return nil, nil, fmt.Errorf("applied Xray inbound %s contains unknown statistics username %q", key, user.Email)
			}
			clients[clientKey] = true
		}
	}
	return listeners, clients, nil
}

type statValue struct {
	Name  string    `json:"name"`
	Value jsonInt64 `json:"value"`
}

func decodeStats(body []byte) (map[string]int64, error) {
	var response struct {
		Stats []statValue `json:"stat"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("decode Xray counters: %w", err)
	}
	result := make(map[string]int64, len(response.Stats))
	for _, stat := range response.Stats {
		if stat.Name == "" || stat.Value < 0 {
			return nil, errors.New("Xray returned an invalid counter name or value")
		}
		if _, exists := result[stat.Name]; exists {
			return nil, fmt.Errorf("Xray returned duplicate counter %q", stat.Name)
		}
		result[stat.Name] = int64(stat.Value)
	}
	return result, nil
}

func decodeOnline(body []byte) (map[string][]string, error) {
	var response struct {
		Users []struct {
			Email string `json:"email"`
			IPs   []struct {
				IP string `json:"ip"`
			} `json:"ips"`
		} `json:"users"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("decode Xray online IPs: %w", err)
	}
	result := make(map[string][]string, len(response.Users))
	for _, user := range response.Users {
		if user.Email == "" {
			return nil, errors.New("Xray returned an online user without email")
		}
		if _, exists := result[user.Email]; exists {
			return nil, fmt.Errorf("Xray returned duplicate online user %q", user.Email)
		}
		for _, entry := range user.IPs {
			if entry.IP == "" {
				return nil, fmt.Errorf("Xray returned an empty online IP for %q", user.Email)
			}
			result[user.Email] = append(result[user.Email], entry.IP)
		}
	}
	return result, nil
}

func assembleCounters(
	listeners []protocol.ListenerKey,
	roster telemetryRoster,
	clientByEmail map[string]protocol.ClientKey,
	presentListeners map[protocol.ListenerKey]bool,
	presentClients map[protocol.ClientKey]bool,
	stats map[string]int64,
	online map[string][]string,
	epoch uint64,
) agentcore.Counters {
	clientEmail := make(map[protocol.ClientKey]string, len(clientByEmail))
	for email, key := range clientByEmail {
		clientEmail[key] = email
	}
	result := agentcore.Counters{
		Clients:   make([]agentcore.ClientCounters, 0, len(roster.Clients)),
		Listeners: make([]agentcore.ListenerCounters, 0, len(listeners)),
	}
	for _, client := range roster.Clients {
		email := clientEmail[client.Key]
		result.Clients = append(result.Clients, agentcore.ClientCounters{
			Key: client.Key, Present: presentClients[client.Key],
			UpBytes:      stats["user>>>"+email+">>>traffic>>>uplink"],
			DownBytes:    stats["user>>>"+email+">>>traffic>>>downlink"],
			CounterEpoch: epoch, LiveIPs: append([]string(nil), online[email]...),
		})
	}
	for _, key := range listeners {
		tag := "psp-" + string(key)
		result.Listeners = append(result.Listeners, agentcore.ListenerCounters{
			Key: key, Present: presentListeners[key],
			UpBytes:      stats["inbound>>>"+tag+">>>traffic>>>uplink"],
			DownBytes:    stats["inbound>>>"+tag+">>>traffic>>>downlink"],
			CounterEpoch: epoch,
		})
	}
	sort.Slice(result.Clients, func(i, j int) bool { return result.Clients[i].Key < result.Clients[j].Key })
	sort.Slice(result.Listeners, func(i, j int) bool { return result.Listeners[i].Key < result.Listeners[j].Key })
	return result
}

type jsonInt64 int64

func (v *jsonInt64) UnmarshalJSON(body []byte) error {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return errors.New("empty integer")
	}
	text := string(body)
	if body[0] == '"' {
		var quoted string
		if err := json.Unmarshal(body, &quoted); err != nil {
			return err
		}
		text = quoted
	}
	parsed, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return err
	}
	*v = jsonInt64(parsed)
	return nil
}

type boundedOutput struct {
	buffer bytes.Buffer
	limit  int
}

func (b *boundedOutput) Write(value []byte) (int, error) {
	original := len(value)
	if b.buffer.Len() < b.limit {
		remaining := b.limit - b.buffer.Len()
		if len(value) > remaining {
			value = value[:remaining]
		}
		_, _ = b.buffer.Write(value)
	}
	return original, nil
}

func runTelemetryCommand(ctx context.Context, binary string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, binary, args...)
	output := &boundedOutput{limit: maxTelemetryOutput + 1}
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(output.buffer.String()))
	}
	return append([]byte(nil), output.buffer.Bytes()...), nil
}

var _ agentcore.Telemetry = (*Telemetry)(nil)

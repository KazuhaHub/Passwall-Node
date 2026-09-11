// Package xray implements the Xray-core production adapter.
package xray

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"

	"github.com/KazuhaHub/passwall-node/corecatalog"
	agentcore "github.com/KazuhaHub/passwall-node/internal/core"
	"github.com/KazuhaHub/passwall-node/protocol"
)

const (
	defaultAPIListen      = "127.0.0.1:10085"
	objectRejected        = "core_config_rejected"
	realityClientRejected = "reality_client_incompatible"
)

// Compiler emits one complete Xray JSON configuration. Full regeneration is
// intentional: Xray's HandlerService supports only a subset of protocols and
// some Shadowsocks-2022 configurations cannot accept AddUser at runtime. A
// closed snapshot keeps support uniform and lets the supervisor validate and
// roll back one artifact per sync round.
type Compiler struct {
	APIListen string
	LogLevel  string
	AccessLog string
	ErrorLog  string
	// CoreVersion selects the compatibility policy applied while compiling.
	// Empty means the release marked recommended in the shared core catalog.
	CoreVersion string
	// AllowRestrictedReality is an explicit escape hatch for operators whose
	// subscribers all use a verified target handshake: a current Xray client,
	// or compatible Mihomo with chrome plus support-x25519mlkem768. It remains
	// false by default because PSP also advertises sing-box and URI clients.
	AllowRestrictedReality bool
}

type listenerSpec struct {
	Enabled        bool   `json:"enabled"`
	Listen         string `json:"listen"`
	Port           int    `json:"port"`
	Protocol       string `json:"protocol"`
	Remark         string `json:"remark"`
	Settings       string `json:"settings"`
	StreamSettings string `json:"stream_settings"`
	Sniffing       string `json:"sniffing"`
	Allocate       string `json:"allocate"`
	ExpiryTime     int64  `json:"expiry_time"`
}

// CompileError identifies the desired object that cannot be represented by
// Xray. The stable Code is suitable for a rejected object status and Issue.
type CompileError struct {
	Stream string
	Key    string
	Code   string
	Err    error
}

func (e *CompileError) Error() string {
	if e == nil {
		return "xray compile error"
	}
	return fmt.Sprintf("xray compile %s %s: %v", e.Stream, e.Key, e.Err)
}

func (e *CompileError) Unwrap() error { return e.Err }

type xrayConfig struct {
	Log       map[string]any   `json:"log"`
	API       map[string]any   `json:"api"`
	Stats     map[string]any   `json:"stats"`
	Policy    map[string]any   `json:"policy"`
	Inbounds  []map[string]any `json:"inbounds"`
	Outbounds []map[string]any `json:"outbounds"`
}

func (c Compiler) Compile(ctx context.Context, snapshot agentcore.Snapshot) (agentcore.Artifact, error) {
	if err := ctx.Err(); err != nil {
		return agentcore.Artifact{}, err
	}
	release, err := c.resolveCoreRelease()
	if err != nil {
		return agentcore.Artifact{}, fmt.Errorf("resolve Xray core release: %w", err)
	}
	apiListen := strings.TrimSpace(c.APIListen)
	if apiListen == "" {
		apiListen = defaultAPIListen
	}
	if err := validateLoopbackEndpoint(apiListen); err != nil {
		return agentcore.Artifact{}, fmt.Errorf("xray api listen: %w", err)
	}
	logLevel := strings.TrimSpace(c.LogLevel)
	if logLevel == "" {
		logLevel = "warning"
	}
	if !validLogLevel(logLevel) {
		return agentcore.Artifact{}, fmt.Errorf("xray log level %q is invalid", logLevel)
	}

	listeners := append([]protocol.Listener(nil), snapshot.Listeners...)
	clients := append([]protocol.Client(nil), snapshot.Clients...)
	sort.Slice(listeners, func(i, j int) bool { return listeners[i].Key < listeners[j].Key })
	sort.Slice(clients, func(i, j int) bool { return clients[i].Key < clients[j].Key })
	clientByListener := make(map[protocol.ListenerKey][]protocol.Client)
	clientByUsername := make(map[string]protocol.ClientKey, len(clients))
	for _, client := range clients {
		if _, err := client.Key.RowID(); err != nil {
			return agentcore.Artifact{}, compileClientError(client.Key, err)
		}
		if _, err := client.Subject.RowID(); err != nil {
			return agentcore.Artifact{}, compileClientError(client.Key, err)
		}
		if client.Credentials.Flow != "" && client.Credentials.Flow != "xtls-rprx-vision" {
			return agentcore.Artifact{}, compileClientError(client.Key, fmt.Errorf("unsupported VLESS flow %q", client.Credentials.Flow))
		}
		username := strings.TrimSpace(client.Credentials.Username)
		if username == "" {
			return agentcore.Artifact{}, compileClientError(client.Key, errors.New("username/email is required for stable statistics"))
		}
		if other, exists := clientByUsername[username]; exists {
			return agentcore.Artifact{}, compileClientError(client.Key, fmt.Errorf("username/email duplicates client %s", other))
		}
		clientByUsername[username] = client.Key
		if !client.Enabled || (client.ExpiresAtMS > 0 && !snapshot.Now.IsZero() && snapshot.Now.UnixMilli() >= client.ExpiresAtMS) {
			continue
		}
		seen := make(map[protocol.ListenerKey]struct{}, len(client.Listeners))
		for _, key := range client.Listeners {
			if _, exists := seen[key]; exists {
				return agentcore.Artifact{}, compileClientError(client.Key, fmt.Errorf("listener %s is repeated", key))
			}
			seen[key] = struct{}{}
			clientByListener[key] = append(clientByListener[key], client)
		}
	}

	config := xrayConfig{
		Log: map[string]any{"loglevel": logLevel},
		API: map[string]any{
			"tag": "psp-api", "listen": apiListen,
			"services": []string{"StatsService"},
		},
		Stats: map[string]any{},
		Policy: map[string]any{
			"levels": map[string]any{"0": map[string]any{
				"statsUserUplink": true, "statsUserDownlink": true, "statsUserOnline": true,
			}},
			"system": map[string]any{"statsInboundUplink": true, "statsInboundDownlink": true},
		},
		Inbounds: make([]map[string]any, 0, len(listeners)),
		Outbounds: []map[string]any{
			{"tag": "direct", "protocol": "freedom", "settings": map[string]any{}},
			{"tag": "blocked", "protocol": "blackhole", "settings": map[string]any{}},
		},
	}
	if c.AccessLog != "" {
		config.Log["access"] = c.AccessLog
	}
	if c.ErrorLog != "" {
		config.Log["error"] = c.ErrorLog
	}

	seenListeners := make(map[protocol.ListenerKey]struct{}, len(listeners))
	binds := make(map[string]protocol.ListenerKey, len(listeners))
	for _, listener := range listeners {
		if err := ctx.Err(); err != nil {
			return agentcore.Artifact{}, err
		}
		if _, err := listener.Key.RowID(); err != nil {
			return agentcore.Artifact{}, compileListenerError(listener.Key, err)
		}
		if _, exists := seenListeners[listener.Key]; exists {
			return agentcore.Artifact{}, compileListenerError(listener.Key, errors.New("duplicate listener key"))
		}
		seenListeners[listener.Key] = struct{}{}
		inbound, enabled, bind, err := c.compileInbound(release, listener, clientByListener[listener.Key])
		if err != nil {
			var clientErr *CompileError
			if errors.As(err, &clientErr) {
				return agentcore.Artifact{}, err
			}
			var rejected *RejectedError
			if errors.As(err, &rejected) {
				return agentcore.Artifact{}, &CompileError{
					Stream: protocol.StreamConfig, Key: string(listener.Key), Code: rejected.Code, Err: rejected,
				}
			}
			return agentcore.Artifact{}, compileListenerError(listener.Key, err)
		}
		if !enabled {
			continue
		}
		if other, exists := binds[bind]; exists {
			return agentcore.Artifact{}, compileListenerError(listener.Key, fmt.Errorf("bind %s conflicts with listener %s", bind, other))
		}
		binds[bind] = listener.Key
		config.Inbounds = append(config.Inbounds, inbound)
	}
	for key := range clientByListener {
		if _, exists := seenListeners[key]; !exists {
			return agentcore.Artifact{}, &CompileError{
				Stream: protocol.StreamRoster, Key: string(key), Code: "attachment_unknown_listener",
				Err: fmt.Errorf("attachment names missing listener %s", key),
			}
		}
	}

	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return agentcore.Artifact{}, fmt.Errorf("encode xray config: %w", err)
	}
	encoded = append(encoded, '\n')
	digest := sha256.Sum256(encoded)
	return agentcore.Artifact{Config: encoded, Digest: hex.EncodeToString(digest[:])}, nil
}

func (c Compiler) compileInbound(release corecatalog.Release, listener protocol.Listener, clients []protocol.Client) (map[string]any, bool, string, error) {
	var spec listenerSpec
	if err := strictJSON(listener.Config, &spec); err != nil {
		return nil, false, "", fmt.Errorf("decode listener config: %w", err)
	}
	if !spec.Enabled {
		return nil, false, "", nil
	}
	if spec.Port < 1 || spec.Port > 65535 {
		return nil, false, "", fmt.Errorf("port %d is outside 1..65535", spec.Port)
	}
	protocolName := strings.ToLower(strings.TrimSpace(spec.Protocol))
	switch protocolName {
	case "vless", "vmess", "trojan", "shadowsocks":
	default:
		return nil, false, "", fmt.Errorf("protocol %q is not supported by the Xray compiler", spec.Protocol)
	}
	settings, err := jsonObject(spec.Settings)
	if err != nil {
		return nil, false, "", fmt.Errorf("settings: %w", err)
	}
	users := make([]any, 0, len(clients))
	for _, client := range clients {
		user, err := compileUser(protocolName, client)
		if err != nil {
			return nil, false, "", compileClientError(client.Key, err)
		}
		users = append(users, user)
	}
	settings["clients"] = users
	inbound := map[string]any{
		"tag": "psp-" + string(listener.Key), "port": spec.Port,
		"protocol": protocolName, "settings": settings,
	}
	listen := strings.TrimSpace(spec.Listen)
	if listen != "" {
		inbound["listen"] = listen
	}
	if stream, present, err := optionalJSONObject(spec.StreamSettings); err != nil {
		return nil, false, "", fmt.Errorf("stream_settings: %w", err)
	} else if present {
		if err := c.applyRealityCompatibility(release, stream); err != nil {
			return nil, false, "", err
		}
		inbound["streamSettings"] = stream
	}
	if sniffing, present, err := optionalJSONObject(spec.Sniffing); err != nil {
		return nil, false, "", fmt.Errorf("sniffing: %w", err)
	} else if present {
		inbound["sniffing"] = sniffing
	}
	if allocate, present, err := optionalJSONObject(spec.Allocate); err != nil {
		return nil, false, "", fmt.Errorf("allocate: %w", err)
	} else if present {
		inbound["allocate"] = allocate
	}
	bindHost := listen
	if bindHost == "" {
		bindHost = "0.0.0.0"
	}
	return inbound, true, net.JoinHostPort(bindHost, fmt.Sprintf("%d", spec.Port)), nil
}

func compileUser(protocolName string, client protocol.Client) (map[string]any, error) {
	credential := client.Credentials
	if strings.TrimSpace(credential.Username) == "" {
		return nil, errors.New("username/email is required for stable statistics")
	}
	user := map[string]any{"email": credential.Username, "level": 0}
	switch protocolName {
	case "vless":
		if strings.TrimSpace(credential.UUID) == "" {
			return nil, errors.New("UUID is required for VLESS")
		}
		user["id"] = credential.UUID
		if credential.Flow != "" {
			user["flow"] = credential.Flow
		}
	case "vmess":
		if strings.TrimSpace(credential.UUID) == "" {
			return nil, errors.New("UUID is required for VMess")
		}
		user["id"] = credential.UUID
		user["alterId"] = 0
	case "trojan":
		if credential.Password == "" {
			return nil, errors.New("password is required for Trojan")
		}
		user["password"] = credential.Password
	case "shadowsocks":
		if credential.Password == "" {
			return nil, errors.New("password is required for Shadowsocks")
		}
		user["password"] = credential.Password
	}
	return user, nil
}

func strictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return fmt.Errorf("trailing JSON value: %w", err)
	}
	return nil
}

func jsonObject(raw string) (map[string]any, error) {
	if strings.TrimSpace(raw) == "" {
		return map[string]any{}, nil
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("must be a JSON object")
	}
	return result, nil
}

func optionalJSONObject(raw string) (map[string]any, bool, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, false, nil
	}
	object, err := jsonObject(raw)
	return object, true, err
}

func validateLoopbackEndpoint(endpoint string) error {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || port == "" {
		return errors.New("must be a loopback IP and port")
	}
	return nil
}

func validLogLevel(level string) bool {
	switch level {
	case "none", "error", "warning", "info", "debug":
		return true
	default:
		return false
	}
}

func compileListenerError(key protocol.ListenerKey, err error) error {
	return &CompileError{Stream: protocol.StreamConfig, Key: string(key), Code: objectRejected, Err: err}
}

func compileClientError(key protocol.ClientKey, err error) error {
	return &CompileError{Stream: protocol.StreamRoster, Key: string(key), Code: objectRejected, Err: err}
}

var _ agentcore.Compiler = Compiler{}

// Package singbox implements the sing-box production core adapter.
package singbox

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
	"strconv"
	"strings"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

const objectRejected = "core_config_rejected"

// Compiler translates PSP's stable Xray-shaped listener envelope into a
// native sing-box 1.14 configuration. APISecret must be a persistent local
// secret so the loopback telemetry API is never exposed without authentication.
type Compiler struct {
	APIListen string
	APISecret string
	LogLevel  string
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

type config struct {
	Log       map[string]any   `json:"log"`
	Services  []map[string]any `json:"services"`
	Inbounds  []map[string]any `json:"inbounds"`
	Outbounds []map[string]any `json:"outbounds"`
	Route     map[string]any   `json:"route"`
	// routed holds the rules of the routed listeners until the egress split has
	// run on the rest (see applyRoutes); it is never encoded.
	routed *routedRules
}

func (c Compiler) Compile(ctx context.Context, snapshot agentcore.Snapshot) (agentcore.Artifact, error) {
	if err := ctx.Err(); err != nil {
		return agentcore.Artifact{}, err
	}
	apiListen := strings.TrimSpace(c.APIListen)
	if err := validateLoopbackEndpoint(apiListen); err != nil {
		return agentcore.Artifact{}, fmt.Errorf("sing-box API listen: %w", err)
	}
	apiHost, apiPortText, _ := net.SplitHostPort(apiListen)
	apiPort, _ := strconv.Atoi(apiPortText)
	if strings.TrimSpace(c.APISecret) != c.APISecret || len(c.APISecret) < 32 {
		return agentcore.Artifact{}, errors.New("sing-box API secret must be at least 32 canonical characters")
	}
	logLevel := strings.TrimSpace(c.LogLevel)
	if logLevel == "" {
		logLevel = "warn"
	}
	if !validLogLevel(logLevel) {
		return agentcore.Artifact{}, fmt.Errorf("sing-box log level %q is invalid", logLevel)
	}

	// An engine that cannot front leaves every front, and what it fronts, out
	// of the compile and reports them rejected: a fronted listener must never
	// be bound on its public port by itself, and the rest of the configuration
	// still applies.
	var rejected []*agentcore.ObjectError
	snapshot, frontRejection := agentcore.WithoutFronts(snapshot)
	if frontRejection != nil {
		rejected = append(rejected, frontRejection)
	}
	listeners := append([]protocol.Listener(nil), snapshot.Listeners...)
	clients := append([]protocol.Client(nil), snapshot.Clients...)
	sort.Slice(listeners, func(i, j int) bool { return listeners[i].Key < listeners[j].Key })
	sort.Slice(clients, func(i, j int) bool { return clients[i].Key < clients[j].Key })
	clientByListener := make(map[protocol.ListenerKey][]protocol.Client)
	clientByName := make(map[string]protocol.ClientKey, len(clients))
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
		name := strings.TrimSpace(client.Credentials.Username)
		if name == "" {
			return agentcore.Artifact{}, compileClientError(client.Key, errors.New("username is required for stable statistics"))
		}
		if other, exists := clientByName[name]; exists {
			return agentcore.Artifact{}, compileClientError(client.Key, fmt.Errorf("username duplicates client %s", other))
		}
		clientByName[name] = client.Key
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

	result := config{
		Log: map[string]any{"level": logLevel},
		Services: []map[string]any{{
			"type": "api", "tag": "psp-api", "listen": apiHost, "listen_port": apiPort, "secret": c.APISecret,
		}},
		Inbounds: make([]map[string]any, 0, len(listeners)),
		Outbounds: []map[string]any{
			{"type": "direct", "tag": "direct"},
			{"type": "block", "tag": "blocked"},
		},
		Route: map[string]any{"final": "direct"},
	}
	seenListeners := make(map[protocol.ListenerKey]struct{}, len(listeners))
	binds := make(map[string]protocol.ListenerKey, len(listeners))
	served := make([]protocol.ListenerKey, 0, len(listeners))
	// guardable are the served listeners the source guard can judge.
	var guardable []protocol.ListenerKey
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
		clients := clientByListener[listener.Key]
		mark := len(rejected)
		inbound, enabled, bind, err := c.compileInbound(listener, clients, &rejected)
		if err != nil {
			var objectErr *agentcore.ObjectError
			if errors.As(err, &objectErr) {
				return agentcore.Artifact{}, err
			}
			return agentcore.Artifact{}, compileListenerError(listener.Key, err)
		}
		if !enabled {
			continue
		}
		// Every sing-box transport carried over HTTP replaces the source with the
		// first X-Forwarded-For value and offers no way to turn that off. Such a
		// listener carries no deny rule, and a client whose line is an allow_from
		// is left off it (fail closed there, reported against the client); it is
		// compiled again without those clients, so a duplicate that only they
		// masked is judged on its own.
		if _, carried := inbound["transport"]; carried {
			if kept, dropped := agentcore.SplitAllowGuarded(clients, snapshot.Now); len(dropped) > 0 {
				rejected = rejected[:mark]
				for _, client := range dropped {
					rejected = append(rejected, agentcore.UnguardableClientRejection(client.Key, listener.Key, agentcore.UnguardableForwardedFor))
				}
				if inbound, enabled, bind, err = c.compileInbound(listener, kept, &rejected); err != nil {
					return agentcore.Artifact{}, compileListenerError(listener.Key, err)
				}
			}
		} else {
			guardable = append(guardable, listener.Key)
		}
		if other, exists := binds[bind]; exists {
			return agentcore.Artifact{}, compileListenerError(listener.Key, fmt.Errorf("bind %s conflicts with listener %s", bind, other))
		}
		binds[bind] = listener.Key
		result.Inbounds = append(result.Inbounds, inbound)
		served = append(served, listener.Key)
	}
	for key := range clientByListener {
		if _, exists := seenListeners[key]; !exists {
			return agentcore.Artifact{}, &agentcore.ObjectError{
				Stream: protocol.StreamRoster, Key: string(key), Code: "attachment_unknown_listener",
				Err: fmt.Errorf("attachment names missing listener %s", key),
			}
		}
	}
	occupied := make(map[string]string, len(binds))
	for bind, key := range binds {
		occupied[bind] = string(key)
	}
	transit, err := agentcore.PlanTransit(snapshot.Transit, occupied, served, "::", apiListen)
	if err != nil {
		return agentcore.Artifact{}, err
	}
	for _, link := range transit.LinksOut {
		result.Outbounds = append(result.Outbounds, compileLinkOut(link))
	}
	// A routed listener's rules are built by applyRoutes; the policy covers the
	// rest (see applyPolicy). Without routes this is exactly what it was.
	if snapshot.DestinationPolicy != nil || len(transit.Routes) > 0 {
		if err := c.applyPolicy(&result, snapshot, served, transit); err != nil {
			return agentcore.Artifact{}, err
		}
	}
	// Transit inbounds go after the policy: it indexes Inbounds by the
	// position of each served listener.
	for _, forward := range transit.Forwards {
		result.Inbounds = append(result.Inbounds, compileForward(forward))
	}
	for _, link := range transit.LinksIn {
		result.Inbounds = append(result.Inbounds, compileLinkIn(link))
	}
	for _, probe := range transit.Probes {
		result.Inbounds = append(result.Inbounds, compileProbeInbound(probe))
	}
	applyEgress(&result, transit.Unrouted(served), transit.Egress)
	finishRoutes(&result)
	// The guard goes first so routeTransit, which prepends, ends up ahead of it.
	if err := c.applyGuard(&result, snapshot, guardable); err != nil {
		return agentcore.Artifact{}, err
	}
	routeTransit(&result, transitInboundTags(transit))
	routeProbes(&result, transit.Probes)
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return agentcore.Artifact{}, fmt.Errorf("encode sing-box config: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > agentcore.MaxRoutedConfigBytes && len(transit.Routes) > 0 {
		for _, key := range served {
			if _, routed := transit.Routes[key]; routed {
				return agentcore.Artifact{}, agentcore.ListenerError(key,
					fmt.Errorf("the compiled configuration is %d bytes, more than the %d a routed compile may take", len(encoded), agentcore.MaxRoutedConfigBytes))
			}
		}
	}
	digest := sha256.Sum256(encoded)
	return agentcore.Artifact{Config: encoded, Digest: hex.EncodeToString(digest[:]), Rejected: agentcore.DedupeRejected(rejected)}, nil
}

// compileForward relays the port to the target unchanged: a direct inbound
// whose destination is overridden. It does no authentication; the landing
// behind it does.
func compileForward(forward protocol.Forward) map[string]any {
	listen := forward.Listen
	if listen == "" {
		listen = "::"
	}
	inbound := map[string]any{
		"type": "direct", "tag": agentcore.ForwardTag(forward.Key), "listen": listen, "listen_port": forward.Port,
		"override_address": forward.Target, "override_port": forward.TargetPort,
	}
	// An absent network is both TCP and UDP in sing-box.
	if forward.Network == protocol.ForwardNetworkTCP {
		inbound["network"] = "tcp"
	}
	return inbound
}

// routeTransit puts one rule FIRST that sends every forward and incoming link
// straight to the direct outbound, so the destination policy (and its sniff
// and resolve actions) never judges relayed traffic. A forward's destination
// is always the landing; a link's traffic was already judged by the entry.
func routeTransit(result *config, tags []string) {
	if len(tags) == 0 {
		return
	}
	rule := map[string]any{"inbound": tags, "action": "route", "outbound": "direct"}
	rules, _ := result.Route["rules"].([]map[string]any)
	result.Route["rules"] = append([]map[string]any{rule}, rules...)
}

// compileProbeInbound is a link's probe inbound: a loopback direct inbound
// whose destination is overridden to the link URL's endpoint. It has no user.
func compileProbeInbound(probe agentcore.ProbeInbound) map[string]any {
	return map[string]any{
		"type": "direct", "tag": agentcore.ProbeTag(probe.Link), "listen": agentcore.ProbeListen, "listen_port": probe.Port,
		"network": "tcp", "override_address": probe.Host, "override_port": probe.TargetPort,
	}
}

// routeProbes puts one rule per probe inbound ahead of everything, the transit
// rule included, so a probe leaves through the link it tests and is never
// judged by the destination policy (or its sniff and resolve actions).
func routeProbes(result *config, probes []agentcore.ProbeInbound) {
	if len(probes) == 0 {
		return
	}
	front := make([]map[string]any, 0, len(probes))
	for _, probe := range probes {
		front = append(front, map[string]any{
			"inbound": []string{agentcore.ProbeTag(probe.Link)}, "action": "route", "outbound": agentcore.LinkTag(probe.Link),
		})
	}
	rules, _ := result.Route["rules"].([]map[string]any)
	result.Route["rules"] = append(front, rules...)
}

func (c Compiler) compileInbound(listener protocol.Listener, clients []protocol.Client, rejected *[]*agentcore.ObjectError) (map[string]any, bool, string, error) {
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
	if !emptyJSON(spec.Allocate) {
		return nil, false, "", errors.New("sing-box does not support Xray inbound allocation settings")
	}
	if enabledSniffing(spec.Sniffing) {
		return nil, false, "", errors.New("sing-box 1.14 does not support legacy per-inbound sniffing settings")
	}
	protocolName := strings.ToLower(strings.TrimSpace(spec.Protocol))
	switch protocolName {
	case "vless", "vmess", "trojan", "shadowsocks":
	default:
		return nil, false, "", fmt.Errorf("protocol %q is not supported by the sing-box compiler", spec.Protocol)
	}
	settings, err := jsonObject(spec.Settings)
	if err != nil {
		return nil, false, "", fmt.Errorf("settings: %w", err)
	}
	inbound := map[string]any{
		"type": protocolName, "tag": "psp-" + string(listener.Key), "listen_port": spec.Port,
	}
	listen := strings.TrimSpace(spec.Listen)
	if listen == "" {
		listen = "::"
	}
	inbound["listen"] = listen
	users := make([]any, 0, len(clients))
	// sing-box keys VLESS users by the whole UUID, so nothing is masked.
	credentials := agentcore.NewCredentialSet(protocolName, false)
	for _, client := range clients {
		user, userErr := compileUser(protocolName, client)
		if userErr != nil {
			return nil, false, "", compileClientError(client.Key, userErr)
		}
		if original, duplicate := credentials.Add(client); duplicate {
			*rejected = append(*rejected, agentcore.DuplicateCredentialRejection(client.Key, original, listener.Key))
			continue
		}
		users = append(users, user)
	}
	if protocolName == "shadowsocks" {
		method, _ := settings["method"].(string)
		password, _ := settings["password"].(string)
		if !strings.HasPrefix(method, "2022-blake3-") || password == "" {
			return nil, false, "", errors.New("sing-box multi-user Shadowsocks requires a 2022 method and server password")
		}
		inbound["method"] = method
		inbound["password"] = password
		inbound["users"] = users
		if network, networkErr := compileNetwork(settings["network"]); networkErr != nil {
			return nil, false, "", networkErr
		} else if len(network) > 0 {
			inbound["network"] = network
		}
	} else {
		inbound["users"] = users
	}
	stream, err := jsonObject(spec.StreamSettings)
	if err != nil {
		return nil, false, "", fmt.Errorf("stream_settings: %w", err)
	}
	if protocolName != "shadowsocks" {
		transport, transportErr := compileTransport(stream)
		if transportErr != nil {
			return nil, false, "", transportErr
		}
		if transport != nil {
			inbound["transport"] = transport
		}
	} else if network := strings.ToLower(strings.TrimSpace(stringValue(stream["network"]))); network != "" && network != "tcp" && network != "raw" {
		return nil, false, "", fmt.Errorf("sing-box Shadowsocks does not support Xray transport %q", network)
	}
	tls, tlsErr := compileTLS(protocolName, stream)
	if tlsErr != nil {
		return nil, false, "", tlsErr
	}
	if tls != nil {
		inbound["tls"] = tls
	}
	if protocolName == "trojan" && tls == nil {
		return nil, false, "", errors.New("sing-box Trojan inbound requires TLS")
	}
	if err := compileSocket(inbound, stream); err != nil {
		return nil, false, "", err
	}
	return inbound, true, net.JoinHostPort(listen, strconv.Itoa(spec.Port)), nil
}

func compileUser(protocolName string, client protocol.Client) (map[string]any, error) {
	credential := client.Credentials
	name := strings.TrimSpace(credential.Username)
	if name == "" {
		return nil, errors.New("username is required for stable statistics")
	}
	user := map[string]any{"name": name}
	switch protocolName {
	case "vless", "vmess":
		if strings.TrimSpace(credential.UUID) == "" {
			return nil, fmt.Errorf("UUID is required for %s", strings.ToUpper(protocolName))
		}
		user["uuid"] = credential.UUID
		if protocolName == "vless" && credential.Flow != "" {
			user["flow"] = credential.Flow
		}
	case "trojan", "shadowsocks":
		if credential.Password == "" {
			return nil, fmt.Errorf("password is required for %s", protocolName)
		}
		user["password"] = credential.Password
	}
	return user, nil
}

func compileTransport(stream map[string]any) (map[string]any, error) {
	network := strings.ToLower(strings.TrimSpace(stringValue(stream["network"])))
	switch network {
	case "", "tcp", "raw":
		settings := mapValue(stream["tcpSettings"])
		if network == "raw" {
			settings = mapValue(stream["rawSettings"])
		}
		if boolValue(settings["acceptProxyProtocol"]) {
			return nil, errors.New("sing-box does not support Xray acceptProxyProtocol")
		}
		header := strings.ToLower(stringValue(mapValue(settings["header"])["type"]))
		if header != "" && header != "none" {
			return nil, fmt.Errorf("sing-box does not support Xray TCP header type %q", header)
		}
		return nil, nil
	case "ws":
		settings := mapValue(stream["wsSettings"])
		if boolValue(settings["acceptProxyProtocol"]) {
			return nil, errors.New("sing-box does not support Xray acceptProxyProtocol")
		}
		out := map[string]any{"type": "ws"}
		putNonEmpty(out, "path", stringValue(settings["path"]))
		if headers := mapValue(settings["headers"]); len(headers) > 0 {
			out["headers"] = headers
		} else if host := stringValue(settings["host"]); host != "" {
			out["headers"] = map[string]any{"Host": host}
		}
		return out, nil
	case "grpc":
		settings := mapValue(stream["grpcSettings"])
		if stringValue(settings["authority"]) != "" || boolValue(settings["multiMode"]) {
			return nil, errors.New("sing-box does not support Xray gRPC authority or multiMode")
		}
		out := map[string]any{"type": "grpc"}
		putNonEmpty(out, "service_name", stringValue(settings["serviceName"]))
		return out, nil
	case "httpupgrade":
		settings := mapValue(stream["httpupgradeSettings"])
		if boolValue(settings["acceptProxyProtocol"]) {
			return nil, errors.New("sing-box does not support Xray acceptProxyProtocol")
		}
		out := map[string]any{"type": "httpupgrade"}
		putNonEmpty(out, "host", stringValue(settings["host"]))
		putNonEmpty(out, "path", stringValue(settings["path"]))
		if headers := mapValue(settings["headers"]); len(headers) > 0 {
			out["headers"] = headers
		}
		return out, nil
	case "http", "h2":
		settings := mapValue(stream["httpSettings"])
		out := map[string]any{"type": "http"}
		putNonEmpty(out, "path", firstString(settings["path"]))
		if host := stringSlice(settings["host"]); len(host) > 0 {
			out["host"] = host
		}
		return out, nil
	default:
		return nil, fmt.Errorf("transport %q is not supported by the sing-box compiler", network)
	}
}

func compileTLS(protocolName string, stream map[string]any) (map[string]any, error) {
	security := strings.ToLower(strings.TrimSpace(stringValue(stream["security"])))
	if protocolName == "shadowsocks" && security != "" && security != "none" {
		return nil, errors.New("sing-box Shadowsocks does not support Xray TLS or REALITY transport security")
	}
	switch security {
	case "", "none":
		return nil, nil
	case "tls":
		settings := mapValue(stream["tlsSettings"])
		if boolValue(settings["rejectUnknownSni"]) {
			return nil, errors.New("sing-box does not support rejectUnknownSni")
		}
		out := map[string]any{"enabled": true}
		putNonEmpty(out, "server_name", stringValue(settings["serverName"]))
		putNonEmpty(out, "min_version", stringValue(settings["minVersion"]))
		putNonEmpty(out, "max_version", stringValue(settings["maxVersion"]))
		if alpn := stringSlice(settings["alpn"]); len(alpn) > 0 {
			out["alpn"] = alpn
		}
		certificates, _ := settings["certificates"].([]any)
		if len(certificates) == 0 {
			return nil, errors.New("sing-box TLS inbound requires a certificate and private key")
		}
		certificate := mapValue(certificates[0])
		certificatePath := stringValue(certificate["certificateFile"])
		keyPath := stringValue(certificate["keyFile"])
		certificatePEM := stringSlice(certificate["certificate"])
		keyPEM := stringSlice(certificate["key"])
		if (certificatePath == "") != (keyPath == "") || (len(certificatePEM) == 0) != (len(keyPEM) == 0) {
			return nil, errors.New("TLS certificate and key must be supplied together")
		}
		if certificatePath != "" {
			out["certificate_path"] = certificatePath
			out["key_path"] = keyPath
		} else if len(certificatePEM) > 0 {
			out["certificate"] = certificatePEM
			out["key"] = keyPEM
		} else {
			return nil, errors.New("sing-box TLS inbound requires a certificate and private key")
		}
		return out, nil
	case "reality":
		if protocolName != "vless" {
			return nil, errors.New("sing-box REALITY is supported only for VLESS")
		}
		settings := mapValue(stream["realitySettings"])
		if int64Value(settings["xver"]) != 0 || stringValue(settings["maxClientVer"]) != "" {
			return nil, errors.New("sing-box does not support Xray REALITY xver or client-version gates")
		}
		if minimum := stringValue(settings["minClientVer"]); minimum != "" && minimum != "1.0.0" {
			return nil, errors.New("sing-box does not support Xray REALITY minClientVer")
		}
		host, port := splitTarget(firstNonEmpty(stringValue(settings["target"]), stringValue(settings["dest"])))
		privateKey := stringValue(settings["privateKey"])
		serverNames := stringSlice(settings["serverNames"])
		if host == "" || port < 1 || privateKey == "" || len(serverNames) == 0 {
			return nil, errors.New("sing-box REALITY requires server name, handshake target, and private key")
		}
		reality := map[string]any{
			"enabled": true, "handshake": map[string]any{"server": host, "server_port": port},
			"private_key": privateKey,
		}
		if shortIDs := stringSlice(settings["shortIds"]); len(shortIDs) > 0 {
			reality["short_id"] = shortIDs
		}
		if difference := int64Value(settings["maxTimediff"]); difference > 0 {
			reality["max_time_difference"] = fmt.Sprintf("%dms", difference)
		}
		return map[string]any{"enabled": true, "server_name": serverNames[0], "reality": reality}, nil
	default:
		return nil, fmt.Errorf("security %q is not supported by the sing-box compiler", security)
	}
}

func compileSocket(inbound, stream map[string]any) error {
	settings := mapValue(stream["sockopt"])
	if boolValue(settings["acceptProxyProtocol"]) || int64Value(settings["tcpUserTimeout"]) > 0 ||
		(strings.TrimSpace(stringValue(settings["tproxy"])) != "" && stringValue(settings["tproxy"]) != "off") {
		return errors.New("sing-box does not support the requested Xray inbound socket options")
	}
	if mark := int64Value(settings["mark"]); mark > 0 {
		inbound["routing_mark"] = mark
	}
	if boolValue(settings["tcpFastOpen"]) {
		inbound["tcp_fast_open"] = true
	}
	if interval := int64Value(settings["tcpKeepAliveInterval"]); interval > 0 {
		inbound["tcp_keep_alive_interval"] = fmt.Sprintf("%ds", interval)
	}
	if idle := int64Value(settings["tcpKeepAliveIdle"]); idle > 0 {
		inbound["tcp_keep_alive"] = fmt.Sprintf("%ds", idle)
	}
	return nil
}

func compileNetwork(value any) ([]string, error) {
	raw := strings.ToLower(strings.ReplaceAll(stringValue(value), " ", ""))
	switch raw {
	case "", "tcp,udp", "udp,tcp":
		return nil, nil
	case "tcp":
		return []string{"tcp"}, nil
	case "udp":
		return []string{"udp"}, nil
	default:
		return nil, errors.New("Shadowsocks network must be tcp, udp, or both")
	}
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
	if strings.TrimSpace(raw) == "" || strings.TrimSpace(raw) == "null" {
		return map[string]any{}, nil
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, err
	}
	if result == nil {
		result = map[string]any{}
	}
	return result, nil
}

func emptyJSON(raw string) bool {
	object, err := jsonObject(raw)
	return err == nil && len(object) == 0
}

func enabledSniffing(raw string) bool {
	settings, err := jsonObject(raw)
	if err != nil || len(settings) == 0 {
		return err != nil
	}
	return boolValue(settings["enabled"]) || boolValue(settings["metadataOnly"]) || boolValue(settings["routeOnly"]) ||
		len(stringSlice(settings["destOverride"])) > 0
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
	case "panic", "fatal", "error", "warn", "info", "debug", "trace":
		return true
	default:
		return false
	}
}

func splitTarget(target string) (string, int) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", 0
	}
	if host, portText, err := net.SplitHostPort(target); err == nil {
		port, _ := strconv.Atoi(portText)
		return host, port
	}
	if index := strings.LastIndex(target, ":"); index > 0 {
		if port, err := strconv.Atoi(target[index+1:]); err == nil {
			return strings.Trim(target[:index], "[]"), port
		}
	}
	return strings.Trim(target, "[]"), 443
}

func mapValue(value any) map[string]any {
	result, _ := value.(map[string]any)
	if result == nil {
		return map[string]any{}
	}
	return result
}

func stringValue(value any) string { result, _ := value.(string); return result }
func boolValue(value any) bool     { result, _ := value.(bool); return result }
func int64Value(value any) int64 {
	switch number := value.(type) {
	case float64:
		return int64(number)
	case json.Number:
		result, _ := number.Int64()
		return result
	case int64:
		return number
	case int:
		return int64(number)
	default:
		return 0
	}
}

func stringSlice(value any) []string {
	switch typed := value.(type) {
	case string:
		if typed != "" {
			return []string{typed}
		}
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if text := stringValue(item); text != "" {
				result = append(result, text)
			}
		}
		return result
	case []string:
		return append([]string(nil), typed...)
	}
	return nil
}

func firstString(value any) string {
	items := stringSlice(value)
	if len(items) == 0 {
		return ""
	}
	return items[0]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func putNonEmpty(target map[string]any, key, value string) {
	if strings.TrimSpace(value) != "" {
		target[key] = value
	}
}

func compileListenerError(key protocol.ListenerKey, err error) error {
	return &agentcore.ObjectError{Stream: protocol.StreamConfig, Key: string(key), Code: objectRejected, Err: err}
}

func compileClientError(key protocol.ClientKey, err error) error {
	return &agentcore.ObjectError{Stream: protocol.StreamRoster, Key: string(key), Code: objectRejected, Err: err}
}

var _ agentcore.Compiler = Compiler{}

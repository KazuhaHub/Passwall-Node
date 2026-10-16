package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	queryStatsMethod    = "/xray.app.stats.command.StatsService/QueryStats"
	getUsersStatsMethod = "/xray.app.stats.command.StatsService/GetUsersStats"
	// The selected binary's CLI uses gRPC's default 4 MiB receive limit.
	// Keep it in addition to the existing 16 MiB JSON output limit.
	maxStatsWireBytes = 4 << 20
)

// Minimal protobuf-v1 messages, following the sing-box wire adapter. No core
// implementation is linked into the agent. These fields and the two CLI calls
// are identical in the audited v26.6.27, v26.7.28 and v26.9.9 releases:
// https://github.com/XTLS/Xray-core/blob/v26.6.27/app/stats/command/command.proto
type statsQueryRequest struct {
	Pattern      string `protobuf:"bytes,1,opt,name=pattern,proto3" json:"pattern,omitempty"`
	ResetCounter bool   `protobuf:"varint,2,opt,name=reset,proto3" json:"reset,omitempty"`
}

func (m *statsQueryRequest) Reset()       { *m = statsQueryRequest{} }
func (*statsQueryRequest) String() string { return "QueryStatsRequest" }
func (*statsQueryRequest) ProtoMessage()  {}

type statsValue struct {
	Name  string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Value int64  `protobuf:"varint,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (m *statsValue) Reset()       { *m = statsValue{} }
func (*statsValue) String() string { return "Stat" }
func (*statsValue) ProtoMessage()  {}

type statsQueryResponse struct {
	Stats []*statsValue `protobuf:"bytes,1,rep,name=stat,proto3" json:"stat,omitempty"`
}

func (m *statsQueryResponse) Reset()       { *m = statsQueryResponse{} }
func (*statsQueryResponse) String() string { return "QueryStatsResponse" }
func (*statsQueryResponse) ProtoMessage()  {}

type usersStatsRequest struct {
	IncludeTraffic bool `protobuf:"varint,1,opt,name=include_traffic,json=includeTraffic,proto3" json:"includeTraffic,omitempty"`
	ResetCounter   bool `protobuf:"varint,2,opt,name=reset,proto3" json:"reset,omitempty"`
}

func (m *usersStatsRequest) Reset()       { *m = usersStatsRequest{} }
func (*usersStatsRequest) String() string { return "GetUsersStatsRequest" }
func (*usersStatsRequest) ProtoMessage()  {}

type statsOnlineIP struct {
	IP       string `protobuf:"bytes,1,opt,name=ip,proto3" json:"ip,omitempty"`
	LastSeen int64  `protobuf:"varint,2,opt,name=last_seen,json=lastSeen,proto3" json:"lastSeen,omitempty"`
}

func (m *statsOnlineIP) Reset()       { *m = statsOnlineIP{} }
func (*statsOnlineIP) String() string { return "OnlineIPEntry" }
func (*statsOnlineIP) ProtoMessage()  {}

type statsTraffic struct {
	Uplink   int64 `protobuf:"varint,1,opt,name=uplink,proto3" json:"uplink,omitempty"`
	Downlink int64 `protobuf:"varint,2,opt,name=downlink,proto3" json:"downlink,omitempty"`
}

func (m *statsTraffic) Reset()       { *m = statsTraffic{} }
func (*statsTraffic) String() string { return "TrafficUserStat" }
func (*statsTraffic) ProtoMessage()  {}

type statsUser struct {
	Email   string           `protobuf:"bytes,1,opt,name=email,proto3" json:"email,omitempty"`
	IPs     []*statsOnlineIP `protobuf:"bytes,2,rep,name=ips,proto3" json:"ips,omitempty"`
	Traffic *statsTraffic    `protobuf:"bytes,3,opt,name=traffic,proto3" json:"traffic,omitempty"`
}

func (m *statsUser) Reset()       { *m = statsUser{} }
func (*statsUser) String() string { return "UserStat" }
func (*statsUser) ProtoMessage()  {}

type usersStatsResponse struct {
	Users []*statsUser `protobuf:"bytes,1,rep,name=users,proto3" json:"users,omitempty"`
}

func (m *usersStatsResponse) Reset()       { *m = usersStatsResponse{} }
func (*usersStatsResponse) String() string { return "GetUsersStatsResponse" }
func (*usersStatsResponse) ProtoMessage()  {}

func supportsStatsWire(version string) bool {
	switch version {
	case "26.6.27", "26.7.28", "26.9.9":
		return true
	default:
		return false
	}
}

func dialStats(_ context.Context, endpoint string) (grpc.ClientConnInterface, io.Closer, error) {
	connection, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, err
	}
	return connection, connection, nil
}

func (t *Telemetry) queryWire(ctx context.Context) ([]byte, []byte, error) {
	queryCtx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	connection, closer, err := t.dial(queryCtx, t.apiListen)
	if err != nil {
		if closer != nil {
			_ = closer.Close()
		}
		if queryCtx.Err() != nil {
			err = queryCtx.Err()
		}
		return nil, nil, fmt.Errorf("dial Xray counters: %w", err)
	}
	if closer != nil {
		defer closer.Close()
	}
	if connection == nil || closer == nil {
		return nil, nil, fmt.Errorf("Xray Stats transport is incomplete")
	}
	stats := new(statsQueryResponse)
	err = connection.Invoke(queryCtx, queryStatsMethod, &statsQueryRequest{}, stats, grpc.MaxCallRecvMsgSize(maxStatsWireBytes))
	if queryCtx.Err() != nil {
		err = queryCtx.Err()
	}
	if err != nil {
		return nil, nil, fmt.Errorf("query Xray counters: %w", err)
	}
	statsJSON, err := encodeStatsJSON(stats)
	if err != nil {
		return nil, nil, err
	}
	if queryCtx.Err() != nil {
		return nil, nil, queryCtx.Err()
	}
	cancel()
	// The original CLI receives a fresh timeout for its second command too.
	onlineCtx, onlineCancel := context.WithTimeout(ctx, t.timeout)
	defer onlineCancel()
	online := new(usersStatsResponse)
	err = connection.Invoke(onlineCtx, getUsersStatsMethod, &usersStatsRequest{}, online, grpc.MaxCallRecvMsgSize(maxStatsWireBytes))
	if onlineCtx.Err() != nil {
		err = onlineCtx.Err()
	}
	if err != nil {
		return nil, nil, fmt.Errorf("query Xray online IPs: %w", err)
	}
	onlineJSON, err := encodeStatsJSON(online)
	if err != nil {
		return nil, nil, err
	}
	if onlineCtx.Err() != nil {
		return nil, nil, onlineCtx.Err()
	}
	return statsJSON, onlineJSON, nil
}

func encodeStatsJSON(value any) ([]byte, error) {
	output := &boundedOutput{limit: maxTelemetryOutput + 1}
	encoder := json.NewEncoder(output)
	// Match the selected CLI's JSON representation, including its whitespace
	// budget and final Println, before using the original semantic decoders.
	encoder.SetIndent("", "    ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, fmt.Errorf("encode Xray Stats response: %w", err)
	}
	_, _ = output.Write([]byte{'\n'})
	if output.buffer.Len() > maxTelemetryOutput {
		return nil, fmt.Errorf("Xray API output exceeds %d bytes", maxTelemetryOutput)
	}
	return output.buffer.Bytes(), nil
}

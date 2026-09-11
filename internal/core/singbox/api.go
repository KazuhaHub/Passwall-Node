package singbox

import (
	"context"

	"google.golang.org/grpc"
)

const subscribeConnectionsMethod = "/daemon.StartedService/SubscribeConnections"

// These deliberately small protobuf-v1 compatible messages describe only the
// stable wire fields Passwall-Node consumes from sing-box's daemon API. gRPC's
// protobuf codec adapts MessageV1 values without linking sing-box itself.
type subscribeConnectionsRequest struct {
	Interval int64 `protobuf:"varint,1,opt,name=interval,proto3" json:"interval,omitempty"`
}

func (m *subscribeConnectionsRequest) Reset()       { *m = subscribeConnectionsRequest{} }
func (*subscribeConnectionsRequest) String() string { return "SubscribeConnectionsRequest" }
func (*subscribeConnectionsRequest) ProtoMessage()  {}

type connectionEvents struct {
	Events []*connectionEvent `protobuf:"bytes,1,rep,name=events,proto3" json:"events,omitempty"`
	Reset_ bool               `protobuf:"varint,2,opt,name=reset,proto3" json:"reset,omitempty"`
}

func (m *connectionEvents) Reset()       { *m = connectionEvents{} }
func (*connectionEvents) String() string { return "ConnectionEvents" }
func (*connectionEvents) ProtoMessage()  {}

type connectionEvent struct {
	Type          int32       `protobuf:"varint,1,opt,name=type,proto3" json:"type,omitempty"`
	ID            string      `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	Connection    *connection `protobuf:"bytes,3,opt,name=connection,proto3" json:"connection,omitempty"`
	UplinkDelta   int64       `protobuf:"varint,4,opt,name=uplinkDelta,proto3" json:"uplinkDelta,omitempty"`
	DownlinkDelta int64       `protobuf:"varint,5,opt,name=downlinkDelta,proto3" json:"downlinkDelta,omitempty"`
	ClosedAt      int64       `protobuf:"varint,6,opt,name=closedAt,proto3" json:"closedAt,omitempty"`
}

func (m *connectionEvent) Reset()       { *m = connectionEvent{} }
func (*connectionEvent) String() string { return "ConnectionEvent" }
func (*connectionEvent) ProtoMessage()  {}

type connection struct {
	ID            string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Inbound       string `protobuf:"bytes,2,opt,name=inbound,proto3" json:"inbound,omitempty"`
	Source        string `protobuf:"bytes,6,opt,name=source,proto3" json:"source,omitempty"`
	User          string `protobuf:"bytes,10,opt,name=user,proto3" json:"user,omitempty"`
	ClosedAt      int64  `protobuf:"varint,13,opt,name=closedAt,proto3" json:"closedAt,omitempty"`
	UplinkTotal   int64  `protobuf:"varint,16,opt,name=uplinkTotal,proto3" json:"uplinkTotal,omitempty"`
	DownlinkTotal int64  `protobuf:"varint,17,opt,name=downlinkTotal,proto3" json:"downlinkTotal,omitempty"`
}

func (m *connection) Reset()       { *m = connection{} }
func (*connection) String() string { return "Connection" }
func (*connection) ProtoMessage()  {}

type connectionStream struct{ grpc.ClientStream }

func subscribeConnections(ctx context.Context, connection grpc.ClientConnInterface, interval int64) (*connectionStream, error) {
	stream, err := connection.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, subscribeConnectionsMethod)
	if err != nil {
		return nil, err
	}
	if err := stream.SendMsg(&subscribeConnectionsRequest{Interval: interval}); err != nil {
		return nil, err
	}
	if err := stream.CloseSend(); err != nil {
		return nil, err
	}
	return &connectionStream{ClientStream: stream}, nil
}

func (s *connectionStream) Recv() (*connectionEvents, error) {
	message := new(connectionEvents)
	if err := s.RecvMsg(message); err != nil {
		return nil, err
	}
	return message, nil
}

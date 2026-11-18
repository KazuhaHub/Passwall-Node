package agent

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// quicProbeDatagramSize is the smallest datagram a QUIC server must answer: RFC
// 9000 section 14.1 has a client pad its first flight to 1200 bytes, and a
// server may ignore a smaller one.
const quicProbeDatagramSize = 1200

// quicGreaseVersion is a reserved version (RFC 9000 section 15, 0x?a?a?a?a). No
// server speaks it, so a conforming one answers with Version Negotiation.
const quicGreaseVersion = 0x1a2a3a4a

// buildQUICProbe assembles a long-header packet of an unsupported version with
// random 8-byte connection ids. They are random so that an off-path sender
// cannot forge the reply, which must echo them swapped.
func buildQUICProbe() (packet, dcid, scid []byte, err error) {
	const idLength = 8
	ids := make([]byte, 2*idLength)
	if _, err := rand.Read(ids); err != nil {
		return nil, nil, nil, fmt.Errorf("generate connection ids: %w", err)
	}
	dcid, scid = ids[:idLength], ids[idLength:]
	packet = make([]byte, 0, quicProbeDatagramSize)
	packet = append(packet, 0xC0)
	packet = binary.BigEndian.AppendUint32(packet, quicGreaseVersion)
	packet = append(packet, idLength)
	packet = append(packet, dcid...)
	packet = append(packet, idLength)
	packet = append(packet, scid...)
	packet = append(packet, make([]byte, quicProbeDatagramSize-len(packet))...)
	return packet, dcid, scid, nil
}

// isVersionNegotiation reports whether reply is the Version Negotiation packet
// answering a probe sent with dcid and scid: a long header whose version is
// zero and whose connection ids are the probe's, swapped (RFC 9000 17.2.1).
func isVersionNegotiation(reply, dcid, scid []byte) bool {
	if len(reply) < 7 || reply[0]&0x80 == 0 || binary.BigEndian.Uint32(reply[1:5]) != 0 {
		return false
	}
	rest := reply[5:]
	if len(rest) < 1 || int(rest[0]) != len(scid) || len(rest) < 1+len(scid)+1 || string(rest[1:1+len(scid)]) != string(scid) {
		return false
	}
	rest = rest[1+len(scid):]
	if int(rest[0]) != len(dcid) || len(rest) < 1+len(dcid) || string(rest[1:1+len(dcid)]) != string(dcid) {
		return false
	}
	// A Version Negotiation packet lists at least one version, four bytes each.
	return len(rest[1+len(dcid):]) >= 4
}

// quic is the QUIC probe: one datagram that asks for a version nobody speaks,
// and the Version Negotiation packet back. It needs no keys, no ALPN and no
// valid connection, so it works against a proxy server that would refuse an
// unauthenticated handshake. Silence is a failure here (a timeout): unlike a
// health check there is no third answer, the line either answers or it does not.
func (p *Prober) quic(ctx context.Context, address string) (time.Duration, error) {
	packet, dcid, scid, err := buildQUICProbe()
	if err != nil {
		return 0, &probeFailure{class: protocol.ProbeErrorOther, err: err}
	}
	start := p.now()
	conn, err := p.options.Dial(ctx, "udp", address)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	deadline(ctx, conn)
	if _, err := conn.Write(packet); err != nil {
		return 0, err
	}
	buffer := make([]byte, 1500)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			return 0, err
		}
		if isVersionNegotiation(buffer[:n], dcid, scid) {
			return p.now().Sub(start), nil
		}
		// Something else on the port: keep waiting for the real answer until
		// the deadline, so a stray datagram does not decide the probe.
	}
}

// buildClientHello is a minimal TLS 1.3 ClientHello naming serverName. It
// offers what any current server accepts (TLS 1.3 and 1.2 suites, x25519) and
// nothing more; the key share is random bytes, which is a valid x25519 public
// value. The probe never completes the handshake.
func buildClientHello(serverName string) ([]byte, error) {
	random := make([]byte, 32+32+32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	u16 := func(value int) []byte { return []byte{byte(value >> 8), byte(value)} }
	extension := func(kind int, body []byte) []byte {
		return append(append(u16(kind), u16(len(body))...), body...)
	}
	name := []byte(serverName)
	serverNameList := append([]byte{0}, append(u16(len(name)), name...)...)
	extensions := []byte{}
	extensions = append(extensions, extension(0x0000, append(u16(len(serverNameList)), serverNameList...))...)
	extensions = append(extensions, extension(0x000b, []byte{1, 0})...)
	extensions = append(extensions, extension(0x000a, append(u16(4), 0x00, 0x1d, 0x00, 0x17))...)
	extensions = append(extensions, extension(0x000d, append(u16(8), 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x08, 0x07))...)
	extensions = append(extensions, extension(0x002b, []byte{4, 0x03, 0x04, 0x03, 0x03})...)
	keyShare := append(append(u16(0x001d), u16(32)...), random[64:96]...)
	extensions = append(extensions, extension(0x0033, append(u16(len(keyShare)), keyShare...))...)

	suites := []byte{0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8}
	hello := []byte{0x03, 0x03}
	hello = append(hello, random[:32]...)
	hello = append(hello, 32)
	hello = append(hello, random[32:64]...)
	hello = append(hello, u16(len(suites))...)
	hello = append(hello, suites...)
	hello = append(hello, 1, 0)
	hello = append(hello, u16(len(extensions))...)
	hello = append(hello, extensions...)

	handshake := append([]byte{0x01, 0, byte(len(hello) >> 8), byte(len(hello))}, hello...)
	record := append([]byte{0x16, 0x03, 0x01}, u16(len(handshake))...)
	return append(record, handshake...), nil
}

// tlsHello is the TLS probe of a forward behind a front: connect to the
// forward's own bind (the front's port), send a ClientHello naming serverName,
// and succeed on the first handshake record being a ServerHello. The route that
// carries that name must have reached the forward's landing for one to come
// back, which a bare connect to the front's port would not show.
func (p *Prober) tlsHello(ctx context.Context, address, serverName string) (time.Duration, error) {
	hello, err := buildClientHello(serverName)
	if err != nil {
		return 0, &probeFailure{class: protocol.ProbeErrorOther, err: err}
	}
	start := p.now()
	conn, err := p.options.Dial(ctx, "tcp", address)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	deadline(ctx, conn)
	if _, err := conn.Write(hello); err != nil {
		return 0, err
	}
	header := make([]byte, 6)
	if _, err := io.ReadFull(conn, header); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return 0, &probeFailure{class: protocol.ProbeErrorTLS, err: errors.New("connection closed before a ServerHello")}
		}
		return 0, err
	}
	if header[0] != 0x16 || header[5] != 0x02 {
		return 0, &probeFailure{class: protocol.ProbeErrorTLS, err: errors.New("the answer is not a ServerHello")}
	}
	return p.now().Sub(start), nil
}

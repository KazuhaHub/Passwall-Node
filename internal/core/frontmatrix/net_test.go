package frontmatrix

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// ---- a TLS site: serves as the REALITY decoy and as the front's default ----

type accept struct {
	at      time.Time
	first   []byte
	firstAt time.Time
	tls     bool
}

type site struct {
	name string
	addr string
	cert [32]byte // SHA-256 of the leaf
	mu   sync.Mutex
	got  []*accept
}

type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (c peekConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// newSite starts a site on host. Over TLS (1.3 only) and over plain TCP
// it answers one HTTP request with "site:<name>". It records when each
// connection was accepted and when its first byte arrived.
func newSite(t *testing.T, name, host string) *site {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13}
	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	s := &site{name: name, addr: listener.Addr().String(), cert: sha256.Sum256(der)}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go s.serve(conn, config)
		}
	}()
	return s
}

func (s *site) serve(conn net.Conn, config *tls.Config) {
	defer conn.Close()
	record := &accept{at: time.Now()}
	s.mu.Lock()
	s.got = append(s.got, record)
	s.mu.Unlock()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReaderSize(conn, 64<<10)
	first, err := reader.Peek(1)
	if err != nil {
		return
	}
	s.mu.Lock()
	record.firstAt = time.Now()
	record.first = append([]byte(nil), first...)
	record.tls = first[0] == 0x16
	s.mu.Unlock()
	var stream net.Conn = peekConn{conn, reader}
	if first[0] == 0x16 {
		secured := tls.Server(stream, config)
		if err := secured.Handshake(); err != nil {
			return
		}
		stream = secured
		reader = bufio.NewReader(secured)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" {
			break
		}
	}
	body := "site:" + s.name
	_, _ = fmt.Fprintf(stream, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	if tc, ok := stream.(*tls.Conn); ok {
		_ = tc.CloseWrite()
	}
}

func (s *site) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.got)
}

// waitAccept waits for the connection accepted after the first n and returns it.
func (s *site) waitAccept(n int, within time.Duration) *accept {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		if len(s.got) > n {
			a := s.got[n]
			s.mu.Unlock()
			return a
		}
		s.mu.Unlock()
		time.Sleep(2 * time.Millisecond)
	}
	return nil
}

// ---- byte-exact tee ----

type capture struct {
	first []byte
	all   []byte // the whole stream, for the tests' small transfers
	n     int64
	h     hash.Hash
	done  bool
}

type teeConn struct {
	c2s, s2c capture
	mu       sync.Mutex
}

// tee is a TCP proxy that records, per connection and per direction, the first
// 4 KiB, the byte count and the SHA-256 of the whole stream.
type tee struct {
	ln     net.Listener
	target string
	mu     sync.Mutex
	conns  []*teeConn
}

func newTee(t *testing.T, target string) *tee {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	x := &tee{ln: ln, target: target}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go x.handle(c)
		}
	}()
	return x
}

func (x *tee) addr() string { return x.ln.Addr().String() }

func (x *tee) handle(client net.Conn) {
	record := &teeConn{}
	record.c2s.h, record.s2c.h = sha256.New(), sha256.New()
	x.mu.Lock()
	x.conns = append(x.conns, record)
	x.mu.Unlock()
	upstream, err := net.Dial("tcp", x.target)
	if err != nil {
		_ = client.Close()
		record.c2s.done, record.s2c.done = true, true
		return
	}
	var wg sync.WaitGroup
	pump := func(dst, src net.Conn, c *capture) {
		defer wg.Done()
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				record.mu.Lock()
				if len(c.first) < 4096 {
					c.first = append(c.first, buf[:min(n, 4096-len(c.first))]...)
				}
				c.n += int64(n)
				if len(c.all) < 8<<20 {
					c.all = append(c.all, buf[:n]...)
				}
				c.h.Write(buf[:n])
				record.mu.Unlock()
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		record.mu.Lock()
		c.done = true
		record.mu.Unlock()
	}
	wg.Add(2)
	go pump(upstream, client, &record.c2s)
	go pump(client, upstream, &record.s2c)
	wg.Wait()
	_ = client.Close()
	_ = upstream.Close()
}

// settled waits until n connections exist and all are finished in both directions.
func (x *tee) settled(t *testing.T, n int) []*teeConn {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		x.mu.Lock()
		conns := append([]*teeConn(nil), x.conns...)
		x.mu.Unlock()
		if len(conns) >= n {
			ok := true
			for _, c := range conns {
				c.mu.Lock()
				ok = ok && c.c2s.done && c.s2c.done
				c.mu.Unlock()
			}
			if ok {
				return conns
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("tee %s never settled with %d connections", x.target, n)
	return nil
}

func (c *teeConn) sum(s2c bool) (string, int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cap := &c.c2s
	if s2c {
		cap = &c.s2c
	}
	return hex.EncodeToString(cap.h.Sum(nil)), cap.n
}

// ---- HTTP target and transfers through a SOCKS client ----

const megabyte = 1 << 20

var (
	bigBody = func() []byte {
		b := make([]byte, megabyte)
		_, _ = mrand.New(mrand.NewSource(7)).Read(b)
		return b
	}()
	upBody = func() []byte {
		b := make([]byte, megabyte)
		_, _ = mrand.New(mrand.NewSource(9)).Read(b)
		return b
	}()
)

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// newTarget serves what the proxied user reaches: /small, /big (1 MiB) and
// /up (returns the SHA-256 of the 1 MiB body it was sent).
func newTarget(t *testing.T) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/small", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("/big", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(bigBody) })
	mux.HandleFunc("/up", func(w http.ResponseWriter, r *http.Request) {
		h := sha256.New()
		_, _ = io.Copy(h, r.Body)
		_, _ = io.WriteString(w, hex.EncodeToString(h.Sum(nil)))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server.Listener.Addr().String()
}

func viaSOCKS(socksPort int, target string) *http.Client {
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, &net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		panic(err)
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true,
		DialContext:       func(_ context.Context, _, _ string) (net.Conn, error) { return dialer.Dial("tcp", target) },
	}}
}

func httpGetSum(c *http.Client, target, path string) (string, error) {
	response, err := c.Get("http://" + target + path)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	h := sha256.New()
	if _, err := io.Copy(h, response.Body); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func httpUpload(c *http.Client, target string) (string, error) {
	response, err := c.Post("http://"+target+"/up", "application/octet-stream", bytes.NewReader(upBody))
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	return string(body), err
}

// transfer runs a small fetch, a 1 MiB download and a 1 MiB upload, each on its
// own connection, and fails on any mismatch.
func transfer(socksPort int, target string) error {
	c := viaSOCKS(socksPort, target)
	if got, err := httpGetSum(c, target, "/small"); err != nil || got != sum([]byte("ok")) {
		return fmt.Errorf("small: %v %s", err, got)
	}
	if got, err := httpGetSum(c, target, "/big"); err != nil || got != sum(bigBody) {
		return fmt.Errorf("download: %v %s", err, got)
	}
	if got, err := httpUpload(c, target); err != nil || got != sum(upBody) {
		return fmt.Errorf("upload: %v %s", err, got)
	}
	return nil
}

// ---- TLS probes ----

// probe completes a TLS handshake with sni (none when empty) and returns the
// leaf certificate's SHA-256 and how long the handshake took.
func probe(addr, sni string) ([32]byte, time.Duration, error) {
	start := time.Now()
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return [32]byte{}, 0, err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	conn := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) //nolint:gosec // probing a decoy
	if err := conn.Handshake(); err != nil {
		return [32]byte{}, 0, err
	}
	return sha256.Sum256(conn.ConnectionState().PeerCertificates[0].Raw), time.Since(start), nil
}

func httpPlain(addr string) (string, time.Duration, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); err != nil {
		return "", 0, err
	}
	body, _ := io.ReadAll(conn)
	return string(body), time.Since(start), nil
}

// dialSOCKS opens a SOCKS5 connection to target through the client.
func dialSOCKS(socksPort int, target string) (net.Conn, error) {
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, &net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	return dialer.Dial("tcp", target)
}

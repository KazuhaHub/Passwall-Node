// Package main is an opt-in, disposable-runner installation acceptance tool.
// Its control plane is a fixed empty-stream fixture, not the PSP application.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/KazuhaHub/passwall-node/corecatalog"
	"github.com/KazuhaHub/passwall-node/protocol"
)

const fixturePath = "/acceptance-prefix/v1/node/sync"

type fixtureObservation struct {
	Reports      int
	SawFresh     bool
	Acknowledged bool
	CoreRunning  bool
	Rejected     int
}

type controlPlaneFixture struct {
	mu          sync.Mutex
	agentID     string
	credential  string
	response    protocol.SyncResponse
	observation fixtureObservation
}

func newControlPlaneFixture(agentID, credential string) (*controlPlaneFixture, error) {
	release, err := corecatalog.Recommended("xray")
	if err != nil {
		return nil, err
	}
	version := protocol.Version{Epoch: 1, Version: 1}
	config := protocol.ConfigBody{Listeners: []protocol.Listener{}, Core: protocol.CoreSelection{Engine: "xray", Version: release.Version}}
	roster := protocol.RosterBody{MinConfigVersion: version, Clients: []protocol.Client{}}
	directives := protocol.DirectivesBody{ForRosterVersion: version, Quota: []protocol.QuotaEntry{}}
	f := &controlPlaneFixture{agentID: agentID, credential: credential}
	f.response = protocol.SyncResponse{
		Config: fixtureSegment(version, config), Roster: fixtureSegment(version, roster),
		Directives: fixtureSegment(version, directives),
	}
	return f, nil
}

func fixtureSegment[T any](version protocol.Version, body T) protocol.Segment[T] {
	encoded, _ := json.Marshal(body) // All fixture bodies contain only JSON-safe protocol values.
	digest := sha256.Sum256(encoded)
	return protocol.Segment[T]{Version: version, ETag: protocol.ETag(hex.EncodeToString(digest[:])), Body: &body}
}

func conditionalFixtureSegment[T any](segment protocol.Segment[T], have protocol.StreamState) protocol.Segment[T] {
	if have.ETag == segment.ETag {
		segment.Unchanged, segment.Body = true, nil
	}
	return segment
}

func (f *controlPlaneFixture) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	reject := func(status int) {
		f.mu.Lock()
		f.observation.Rejected++
		f.mu.Unlock()
		http.Error(w, "acceptance fixture rejected request", status)
	}
	if request.Method != http.MethodPost || request.URL.Path != fixturePath {
		reject(http.StatusNotFound)
		return
	}
	if subtle.ConstantTimeCompare([]byte(request.Header.Get("Authorization")), []byte("Bearer "+f.credential)) != 1 {
		reject(http.StatusUnauthorized)
		return
	}
	defer request.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, request.Body, protocol.MaxSyncBodyBytes))
	var report protocol.NodeReport
	if err := decoder.Decode(&report); err != nil || report.AgentID != f.agentID {
		reject(http.StatusBadRequest)
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		reject(http.StatusBadRequest)
		return
	}
	if err := protocol.ValidateNodeReport(report); err != nil {
		reject(http.StatusBadRequest)
		return
	}
	response := f.response
	response.Envelope = protocol.Envelope{ComputedAtMS: time.Now().UnixMilli(), NextPollSeconds: 1, FullReportSeconds: 0}
	response.Config = conditionalFixtureSegment(response.Config, report.Have[protocol.StreamConfig])
	response.Roster = conditionalFixtureSegment(response.Roster, report.Have[protocol.StreamRoster])
	response.Directives = conditionalFixtureSegment(response.Directives, report.Have[protocol.StreamDirectives])
	f.mu.Lock()
	f.observation.Reports++
	fresh, acknowledged := true, true
	for name, expected := range map[string]protocol.StreamState{
		protocol.StreamConfig:     {Applied: f.response.Config.Version, ETag: f.response.Config.ETag},
		protocol.StreamRoster:     {Applied: f.response.Roster.Version, ETag: f.response.Roster.ETag},
		protocol.StreamDirectives: {Applied: f.response.Directives.Version, ETag: f.response.Directives.ETag},
	} {
		have := report.Have[name]
		fresh = fresh && have.Applied.Zero() && have.ETag == ""
		acknowledged = acknowledged && have == expected
	}
	f.observation.SawFresh = f.observation.SawFresh || fresh
	f.observation.Acknowledged = f.observation.Acknowledged || acknowledged
	f.observation.CoreRunning = f.observation.CoreRunning || report.CoreState == "running"
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (f *controlPlaneFixture) snapshot() fixtureObservation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.observation
}

func (f *controlPlaneFixture) beginReinstall() {
	f.mu.Lock()
	f.observation = fixtureObservation{}
	f.mu.Unlock()
}

func fixtureTLSCertificate() (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "disposable Passwall-Node acceptance fixture"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certificate, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certificate, certPEM, err
}

func startFixture(f *controlPlaneFixture) (*http.Server, string, []byte, error) {
	certificate, certPEM, err := fixtureTLSCertificate()
	if err != nil {
		return nil, "", nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", nil, err
	}
	server := &http.Server{Handler: f, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, ErrorLog: log.New(io.Discard, "", 0),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}},
	}
	go func() {
		if err := server.Serve(tls.NewListener(listener, server.TLSConfig)); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// A startup/readiness timeout is the only public failure; never log requests or headers.
			_ = listener.Close()
		}
	}()
	return server, "https://" + listener.Addr().String() + fixturePath, certPEM, nil
}

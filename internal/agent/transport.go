package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

const (
	defaultHTTPTimeout     = 30 * time.Second
	defaultMaxResponseBody = protocol.MaxSyncWireBytes
	maxErrorBody           = int64(4 << 10)
	// maxErrorWireBody bounds the compressed bytes read from an error response.
	maxErrorWireBody = int64(64 << 10)
)

// Syncer is the one network operation in the steady-state protocol.
type Syncer interface {
	Sync(context.Context, protocol.NodeReport) (protocol.SyncResponse, error)
}

// RequestSigner applies the registration credential without fixing its wire
// shape before the registration design is final.
type RequestSigner func(*http.Request) error

// NewBearerSigner constructs the production node authenticator. The
// credential is deliberately opaque: identity lives in the separately
// validated report and PSP binds the SHA-256 digest back to that identity.
func NewBearerSigner(credential string) (RequestSigner, error) {
	if len(credential) < protocol.MinNodeCredentialBytes || len(credential) > protocol.MaxNodeCredentialBytes {
		return nil, fmt.Errorf("node credential must contain %d..%d bytes", protocol.MinNodeCredentialBytes, protocol.MaxNodeCredentialBytes)
	}
	for index := 0; index < len(credential); index++ {
		if credential[index] < 0x21 || credential[index] > 0x7e {
			return nil, fmt.Errorf("node credential must use visible ASCII without whitespace")
		}
	}
	return func(request *http.Request) error {
		if request == nil {
			return errors.New("cannot sign a nil request")
		}
		request.Header.Set("Authorization", "Bearer "+credential)
		return nil
	}, nil
}

type HTTPOptions struct {
	Client *http.Client
	Signer RequestSigner
	// MaxResponseBytes bounds the bytes of a response BODY ON THE WIRE (compressed
	// when it is compressed); the decoded size has its own protocol limit. Zero
	// means protocol.MaxSyncWireBytes, and a larger value is clamped to it.
	MaxResponseBytes  int64
	AllowInsecureHTTP bool
	UserAgent         string
	// Stats observes request and response sizes and the round-trip time. It is
	// recorded HERE rather than at the caller because this is the only layer
	// that knows the encoded bytes and the instant the response completed.
	Stats *RuntimeStats
	// SyncGzip is true when the agent declares protocol.CapabilitySyncGzip. Only
	// then does the syncer send Accept-Encoding: gzip, accept a gzip response
	// and, once the panel advertises it, compress requests.
	SyncGzip bool
	// Now is the clock of the compression cooldown; time.Now when nil.
	Now func() time.Time
}

type HTTPSyncer struct {
	endpoint         *url.URL
	client           *http.Client
	signer           RequestSigner
	maxResponseBytes int64
	userAgent        string
	stats            *RuntimeStats
	gzipDeclared     bool
	mu               sync.Mutex // guards compression
	compression      *protocol.SyncCompression
}

func NewHTTPSyncer(endpoint string, options HTTPOptions) (*HTTPSyncer, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse sync endpoint: %w", err)
	}
	if u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("sync endpoint must be an absolute URL without userinfo, query, or fragment")
	}
	if !strings.HasSuffix(u.Path, "/v1/node/sync") || path.Clean(u.Path) != u.Path || u.RawPath != "" || strings.Contains(u.Path, "//") {
		return nil, fmt.Errorf("sync endpoint path must be a canonical /v1/node/sync path, optionally below a PSP panel prefix")
	}
	if u.Scheme != "https" && !(options.AllowInsecureHTTP && u.Scheme == "http") {
		return nil, fmt.Errorf("sync endpoint must use HTTPS")
	}
	client := options.Client
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	// Preserve a caller's transport/TLS setup without mutating its client. The
	// credential-bearing sync operation must never follow redirects, including
	// same-origin redirects that Go would otherwise forward Authorization to.
	privateClient := *client
	// Go's transport would otherwise add Accept-Encoding itself and inflate the
	// response with no size limit; decoding is done by protocol.DecodeSyncBody.
	// The transport is cloned, not mutated, so the caller's stays untouched.
	// A custom RoundTripper that is not an *http.Transport is used as given: it
	// is the caller's to keep from inflating (none that this module builds does).
	switch transport := privateClient.Transport.(type) {
	case nil:
		var clone *http.Transport
		if base, ok := http.DefaultTransport.(*http.Transport); ok {
			clone = base.Clone()
		} else {
			clone = &http.Transport{
				Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true,
				MaxIdleConns: 100, IdleConnTimeout: 90 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second, ExpectContinueTimeout: time.Second,
			}
		}
		clone.DisableCompression = true
		privateClient.Transport = clone
	case *http.Transport:
		clone := transport.Clone()
		clone.DisableCompression = true
		privateClient.Transport = clone
	}
	privateClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client = &privateClient
	maxResponseBytes := options.MaxResponseBytes
	if maxResponseBytes == 0 {
		maxResponseBytes = defaultMaxResponseBody
	}
	if maxResponseBytes > protocol.MaxSyncWireBytes {
		maxResponseBytes = protocol.MaxSyncWireBytes
	}
	if maxResponseBytes < 1 {
		return nil, fmt.Errorf("maximum response size must be positive")
	}
	userAgent := strings.TrimSpace(options.UserAgent)
	if userAgent == "" {
		userAgent = "passwall-node/dev"
	}
	return &HTTPSyncer{
		endpoint: u, client: client, signer: options.Signer,
		maxResponseBytes: maxResponseBytes, userAgent: userAgent,
		stats: options.Stats, gzipDeclared: options.SyncGzip,
		compression: protocol.NewSyncCompression(options.SyncGzip, options.Now),
	}, nil
}

// Sync performs one sync exchange. The agent has a single sync loop; the
// compression state is nevertheless guarded so that a stray concurrent call
// cannot corrupt it.
func (s *HTTPSyncer) Sync(ctx context.Context, report protocol.NodeReport) (protocol.SyncResponse, error) {
	body, err := json.Marshal(report)
	if err != nil {
		return protocol.SyncResponse{}, fmt.Errorf("encode node report: %w", err)
	}
	if int64(len(body)) > protocol.MaxSyncBodyBytes {
		return protocol.SyncResponse{}, fmt.Errorf("node report exceeds %d bytes", protocol.MaxSyncBodyBytes)
	}

	encoding := s.requestEncoding()
	wireBody := body
	if encoding == protocol.SyncEncodingGzip {
		compressed, encodeErr := protocol.EncodeSyncBody(body)
		if encodeErr != nil {
			// Incompressible input can grow past the wire limit; the plain body
			// is within it, so fall back rather than fail the round.
			encoding = ""
		} else {
			wireBody = compressed
		}
	}

	// The round trip is measured across the whole request/response interval, not
	// just the dial: what an operator is watching for is "how long does one sync
	// exchange take", which includes the peer's own processing time.
	requestStarted := time.Now()
	response, err := s.send(ctx, wireBody, encoding)
	if err != nil {
		return protocol.SyncResponse{}, err
	}
	if s.rejected(response.StatusCode, encoding) {
		// The path may not have taken the coding: repeat the same report once,
		// plain. Its outcome decides whether gzip goes quiet for the cooldown.
		_ = response.Body.Close()
		response, err = s.send(ctx, body, "")
		if err != nil {
			return protocol.SyncResponse{}, err
		}
		s.plainRetried(response.StatusCode)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		detail := readErrorBody(response)
		return protocol.SyncResponse{}, fmt.Errorf("sync response status %d: %s", response.StatusCode, detail)
	}

	responseEncoding, err := protocol.SyncEncodingFromHeaders(response.Header.Values(protocol.SyncContentEncodingHeader))
	if err != nil {
		return protocol.SyncResponse{}, fmt.Errorf("sync response: %w", err)
	}
	if responseEncoding == protocol.SyncEncodingGzip && !s.gzipDeclared {
		return protocol.SyncResponse{}, errors.New("sync response is gzip-encoded but the agent did not ask for compression")
	}
	counted := &countingReader{r: response.Body, limit: s.maxResponseBytes}
	responseBody, err := protocol.DecodeSyncBody(counted, responseEncoding)
	if err != nil {
		if errors.Is(err, errResponseTooLarge) || errors.Is(err, protocol.ErrSyncWireTooLarge) {
			return protocol.SyncResponse{}, fmt.Errorf("sync response exceeds %d bytes", s.maxResponseBytes)
		}
		return protocol.SyncResponse{}, fmt.Errorf("read sync response: %w", err)
	}
	// The advertisement is learned only now: a truncated or invalid 2xx body, or
	// one in a coding we refuse, says nothing reliable about the panel.
	s.observe(response.StatusCode, response.Header.Get(protocol.SyncAcceptEncodingHeader))
	// Recorded only once the body has been read IN FULL. A partial read is a
	// failure, and recording its size would describe a response that never
	// arrived. The size is what crossed the wire.
	if s.stats != nil {
		s.stats.RecordResponse(counted.n, time.Since(requestStarted))
	}
	var syncResponse protocol.SyncResponse
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	if err := decoder.Decode(&syncResponse); err != nil {
		return protocol.SyncResponse{}, fmt.Errorf("decode sync response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return protocol.SyncResponse{}, fmt.Errorf("decode sync response: trailing JSON value")
		}
		return protocol.SyncResponse{}, fmt.Errorf("decode sync response trailing data: %w", err)
	}
	return syncResponse, nil
}

// send issues one request. encoding is "" for a plain body or gzip for a body
// already compressed by the caller. A transport error is returned as such and
// never reaches the compression state: no response says nothing about what the
// panel accepts.
func (s *HTTPSyncer) send(ctx context.Context, wireBody []byte, encoding string) (*http.Response, error) {
	// Recorded after encoding, so it describes what was about to go on the wire
	// rather than what was intended.
	if s.stats != nil {
		s.stats.RecordRequestBytes(int64(len(wireBody)))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint.String(), bytes.NewReader(wireBody))
	if err != nil {
		return nil, fmt.Errorf("create sync request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", s.userAgent)
	if s.gzipDeclared {
		req.Header.Set(protocol.SyncAcceptEncodingHeader, protocol.SyncEncodingGzip)
	}
	if encoding != "" {
		req.Header.Set(protocol.SyncContentEncodingHeader, encoding)
	}
	if s.signer != nil {
		if err := s.signer(req); err != nil {
			return nil, fmt.Errorf("sign sync request: %w", err)
		}
	}
	response, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send sync request: %w", err)
	}
	return response, nil
}

// readErrorBody returns a bounded excerpt of a non-200 body. A proxy may gzip
// an error page whatever was negotiated, so a gzip body is inflated through the
// same kind of bound (maxErrorBody of output); anything else is read raw.
func readErrorBody(response *http.Response) string {
	var reader io.Reader = response.Body
	if encoding, err := protocol.SyncEncodingFromHeaders(response.Header.Values(protocol.SyncContentEncodingHeader)); err == nil && encoding == protocol.SyncEncodingGzip {
		zr, zerr := gzip.NewReader(io.LimitReader(response.Body, maxErrorWireBody))
		if zerr != nil {
			return ""
		}
		defer zr.Close()
		reader = zr
	}
	detail, _ := io.ReadAll(io.LimitReader(reader, maxErrorBody))
	return strings.TrimSpace(string(detail))
}

func (s *HTTPSyncer) requestEncoding() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.compression.RequestEncoding()
}

func (s *HTTPSyncer) rejected(status int, sent string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.compression.Rejected(status, sent)
}

func (s *HTTPSyncer) plainRetried(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.compression.PlainRetried(status)
}

func (s *HTTPSyncer) observe(status int, acceptEncoding string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.compression.ObserveResponse(status, acceptEncoding)
}

var errResponseTooLarge = errors.New("sync response exceeds the configured limit")

// countingReader counts the bytes that crossed the wire and fails once they
// exceed limit (the configured cap, which may be below the protocol wire limit
// that DecodeSyncBody enforces itself).
type countingReader struct {
	r     io.Reader
	limit int64
	n     int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.limit {
		return n, errResponseTooLarge
	}
	return n, err
}

var _ Syncer = (*HTTPSyncer)(nil)

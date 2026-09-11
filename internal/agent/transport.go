package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KazuhaHub/passwall-node/protocol"
)

const (
	defaultHTTPTimeout     = 30 * time.Second
	defaultMaxResponseBody = protocol.MaxSyncBodyBytes
	maxErrorBody           = int64(4 << 10)
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
	Client            *http.Client
	Signer            RequestSigner
	MaxResponseBytes  int64
	AllowInsecureHTTP bool
	UserAgent         string
}

type HTTPSyncer struct {
	endpoint         *url.URL
	client           *http.Client
	signer           RequestSigner
	maxResponseBytes int64
	userAgent        string
}

func NewHTTPSyncer(endpoint string, options HTTPOptions) (*HTTPSyncer, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse sync endpoint: %w", err)
	}
	if u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("sync endpoint must be an absolute URL without userinfo, query, or fragment")
	}
	if u.Path != "/v1/node/sync" {
		return nil, fmt.Errorf("sync endpoint path must be /v1/node/sync")
	}
	if u.Scheme != "https" && !(options.AllowInsecureHTTP && u.Scheme == "http") {
		return nil, fmt.Errorf("sync endpoint must use HTTPS")
	}
	client := options.Client
	if client == nil {
		client = &http.Client{
			Timeout: defaultHTTPTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	maxResponseBytes := options.MaxResponseBytes
	if maxResponseBytes == 0 {
		maxResponseBytes = defaultMaxResponseBody
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
	}, nil
}

func (s *HTTPSyncer) Sync(ctx context.Context, report protocol.NodeReport) (protocol.SyncResponse, error) {
	body, err := json.Marshal(report)
	if err != nil {
		return protocol.SyncResponse{}, fmt.Errorf("encode node report: %w", err)
	}
	if int64(len(body)) > protocol.MaxSyncBodyBytes {
		return protocol.SyncResponse{}, fmt.Errorf("node report exceeds %d bytes", protocol.MaxSyncBodyBytes)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return protocol.SyncResponse{}, fmt.Errorf("create sync request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", s.userAgent)
	if s.signer != nil {
		if err := s.signer(req); err != nil {
			return protocol.SyncResponse{}, fmt.Errorf("sign sync request: %w", err)
		}
	}

	response, err := s.client.Do(req)
	if err != nil {
		return protocol.SyncResponse{}, fmt.Errorf("send sync request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(response.Body, maxErrorBody))
		return protocol.SyncResponse{}, fmt.Errorf("sync response status %d: %s", response.StatusCode, strings.TrimSpace(string(detail)))
	}

	limited := io.LimitReader(response.Body, s.maxResponseBytes+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return protocol.SyncResponse{}, fmt.Errorf("read sync response: %w", err)
	}
	if int64(len(responseBody)) > s.maxResponseBytes {
		return protocol.SyncResponse{}, fmt.Errorf("sync response exceeds %d bytes", s.maxResponseBytes)
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

var _ Syncer = (*HTTPSyncer)(nil)

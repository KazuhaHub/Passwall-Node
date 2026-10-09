// Package auditsink receives local Xray webhook hits over a private Unix socket.
package auditsink

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/KazuhaHub/passwall-node/v4/internal/agent/audit"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"
)

type Stats struct{ Unauthorized, Malformed, Oversize uint64 }
type Sink struct {
	collector                         *audit.Collector
	token, socket                     string
	listener                          net.Listener
	server                            *http.Server
	fatal                             chan error
	unauthorized, malformed, oversize atomic.Uint64
}

// Listen completes startup before a compiler or capability receives the socket
// or token. Never fall back to TCP or an abstract socket after a setup failure.
func Listen(dataDir string, collector *audit.Collector) (*Sink, error) {
	if collector == nil || !filepath.IsAbs(dataDir) {
		return nil, errors.New("absolute data directory and audit collector are required")
	}
	if runtime.GOOS == "windows" {
		return nil, errors.New("audit sink requires Unix socket file permissions")
	}
	directory := filepath.Join(dataDir, "runtime")
	socket := filepath.Join(directory, "audit.sock")
	if len(socket) > 100 {
		return nil, errors.New("audit socket path exceeds 100 bytes")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, fmt.Errorf("create audit runtime directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("audit runtime path must be a real directory")
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return nil, fmt.Errorf("restrict audit runtime directory: %w", err)
	}
	token, err := loadToken(filepath.Join(directory, "audit.token"))
	if err != nil {
		return nil, err
	}
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("audit socket path contains a non-socket file")
		}
		if err := os.Remove(socket); err != nil {
			return nil, fmt.Errorf("remove stale audit socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect audit socket: %w", err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("listen on audit socket: %w", err)
	}
	if err := os.Chmod(socket, 0600); err != nil {
		listener.Close()
		return nil, fmt.Errorf("restrict audit socket: %w", err)
	}
	s := &Sink{collector: collector, token: token, socket: socket, listener: listener, fatal: make(chan error, 1)}
	s.server = &http.Server{Handler: s, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
	return s, nil
}

// Persist the credential used by saved core artifacts so offline restarts can
// authenticate before the next panel synchronization. Never replace a bad file.
func loadToken(path string) (string, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		var secret [32]byte
		if _, err := rand.Read(secret[:]); err != nil {
			return "", fmt.Errorf("create audit token: %w", err)
		}
		token := hex.EncodeToString(secret[:])
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if errors.Is(err, os.ErrExist) {
			return loadToken(path)
		}
		if err != nil {
			return "", fmt.Errorf("create audit token file: %w", err)
		}
		if err = file.Chmod(0600); err == nil {
			_, err = io.WriteString(file, token)
		}
		if err == nil {
			err = file.Sync()
		}
		err = errors.Join(err, file.Close())
		if err != nil {
			os.Remove(path)
			return "", fmt.Errorf("persist audit token: %w", err)
		}
		return token, nil
	}
	if err != nil {
		return "", fmt.Errorf("inspect audit token file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Size() != 64 {
		return "", errors.New("audit token file must be regular, private, and contain 64 lowercase hex characters")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open audit token file: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", errors.New("audit token file changed during startup")
	}
	body, err := io.ReadAll(io.LimitReader(file, 65))
	if err != nil {
		return "", fmt.Errorf("read audit token file: %w", err)
	}
	if len(body) != 64 {
		return "", errors.New("audit token file must contain 64 lowercase hex characters")
	}
	for _, b := range body {
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) {
			return "", errors.New("audit token file must contain 64 lowercase hex characters")
		}
	}
	return string(body), nil
}
func (s *Sink) Socket() string { return s.socket }
func (s *Sink) Token() string  { return s.token }

type webhook struct {
	Email       string `json:"email"`
	Destination string `json:"destination"`
	OutboundTag string `json:"outboundTag"`
}

func (s *Sink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if recover() != nil {
			select {
			case s.fatal <- errors.New("audit handler panicked"):
			default:
			}
			w.WriteHeader(http.StatusInternalServerError)
		}
	}()
	if r.URL.Path != "/hit" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-PSP-Audit")), []byte(s.token)) != 1 {
		s.unauthorized.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		var oversized *http.MaxBytesError
		if errors.As(err, &oversized) {
			s.oversize.Add(1)
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		s.malformed.Add(1)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	revision, err := strconv.ParseUint(r.Header.Get("X-PSP-Audit-Revision"), 10, 64)
	if err != nil {
		s.malformed.Add(1)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var event *webhook
	if err := json.Unmarshal(body, &event); err != nil || event == nil {
		s.malformed.Add(1)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.collector.AddHit(revision, event.Email, event.Destination, event.OutboundTag)
	w.WriteHeader(http.StatusNoContent)
}

// Run returns unexpected Serve errors and panics to lifecycle. Once hits are
// advertised, collector failure must terminate the agent rather than silently
// leave a process that still claims to collect. Context shutdown is graceful.
func (s *Sink) Run(ctx context.Context) error {
	if s.server == nil || s.listener == nil {
		return errors.New("audit sink was not initialized")
	}
	done := make(chan error, 1)
	go func() {
		defer func() {
			if recover() != nil {
				done <- errors.New("audit server panicked")
			}
		}()
		done <- s.server.Serve(s.listener)
	}()
	select {
	case <-ctx.Done():
		s.Close()
		<-done
		return nil
	case err := <-s.fatal:
		s.Close()
		<-done
		return err
	case err := <-done:
		s.Close()
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			return errors.New("audit server exited unexpectedly")
		}
		return fmt.Errorf("audit server stopped: %w", err)
	}
}
func (s *Sink) Close() error {
	var err error
	if s.server != nil {
		err = s.server.Close()
	}
	if s.listener != nil {
		if closeErr := s.listener.Close(); !errors.Is(closeErr, net.ErrClosed) {
			err = errors.Join(err, closeErr)
		}
	}
	return err
}
func (s *Sink) Stats() Stats {
	return Stats{s.unauthorized.Load(), s.malformed.Load(), s.oversize.Load()}
}

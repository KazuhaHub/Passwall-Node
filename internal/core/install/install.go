// Package install materializes exact, catalog-approved proxy-core binaries.
// It deliberately does not switch the running process; activation belongs to
// the lifecycle controller, after it has compiled and validated one snapshot.
package install

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/KazuhaHub/passwall-node/corecatalog"
)

const (
	defaultMaxArchiveBytes = 128 << 20
	defaultMaxBinaryBytes  = 256 << 20
	defaultCommandTimeout  = 20 * time.Second
	metadataName           = "install.json"
	maxCommandOutput       = 64 << 10
)

type Request struct {
	Engine               string
	Version              string
	AcceptRestricted     bool
	CurrentConfiguration []byte
}

type Installation struct {
	Engine       string
	Version      string
	BinaryPath   string
	MetadataPath string
	Release      corecatalog.Release
}

type Resolver func(engine, version string) (corecatalog.Release, error)

type BinaryVerifier interface {
	Verify(context.Context, string, string, []byte) error
}

type Options struct {
	RootDir         string
	GOOS            string
	GOARCH          string
	HTTPClient      *http.Client
	Resolve         Resolver
	Verifier        BinaryVerifier
	MaxArchiveBytes int64
	MaxBinaryBytes  int64
	CommandTimeout  time.Duration
}

type Installer struct {
	rootDir         string
	goos            string
	goarch          string
	client          *http.Client
	resolve         Resolver
	verifier        BinaryVerifier
	maxArchiveBytes int64
	maxBinaryBytes  int64
}

type metadata struct {
	SchemaVersion int       `json:"schema_version"`
	Engine        string    `json:"engine"`
	Version       string    `json:"version"`
	SourceURL     string    `json:"source_url"`
	ArchiveSHA256 string    `json:"archive_sha256"`
	BinarySHA256  string    `json:"binary_sha256"`
	InstalledAt   time.Time `json:"installed_at"`
}

func New(options Options) (*Installer, error) {
	if !filepath.IsAbs(options.RootDir) {
		return nil, errors.New("core installation root must be absolute")
	}
	goos := strings.TrimSpace(options.GOOS)
	if goos == "" {
		goos = runtime.GOOS
	}
	goarch := strings.TrimSpace(options.GOARCH)
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	if options.Resolve == nil {
		options.Resolve = corecatalog.Resolve
	}
	if options.MaxArchiveBytes <= 0 {
		options.MaxArchiveBytes = defaultMaxArchiveBytes
	}
	if options.MaxBinaryBytes <= 0 {
		options.MaxBinaryBytes = defaultMaxBinaryBytes
	}
	if options.CommandTimeout <= 0 {
		options.CommandTimeout = defaultCommandTimeout
	}
	if options.HTTPClient == nil {
		options.HTTPClient = &http.Client{}
	}
	options.HTTPClient = secureHTTPClient(options.HTTPClient)
	if options.Verifier == nil {
		options.Verifier = execVerifier{timeout: options.CommandTimeout}
	}
	return &Installer{
		rootDir: options.RootDir, goos: goos, goarch: goarch,
		client: options.HTTPClient, resolve: options.Resolve, verifier: options.Verifier,
		maxArchiveBytes: options.MaxArchiveBytes, maxBinaryBytes: options.MaxBinaryBytes,
	}, nil
}

func (i *Installer) Install(ctx context.Context, request Request) (Installation, error) {
	if err := ctx.Err(); err != nil {
		return Installation{}, err
	}
	engine := strings.ToLower(strings.TrimSpace(request.Engine))
	if engine != "xray" {
		return Installation{}, fmt.Errorf("core engine %q is unsupported", request.Engine)
	}
	release, err := i.resolve(engine, request.Version)
	if err != nil {
		return Installation{}, fmt.Errorf("resolve core release: %w", err)
	}
	normalized, normalizeErr := corecatalog.NormalizeVersion(request.Version)
	if release.Engine != engine || normalizeErr != nil || release.Version != normalized || !release.Selectable {
		return Installation{}, errors.New("core catalog resolver returned a non-selectable or mismatched release")
	}
	if release.RequiresConfirmation && !request.AcceptRestricted {
		return Installation{}, fmt.Errorf("%s %s is restricted and requires explicit confirmation", engine, release.Version)
	}
	asset, err := release.AssetFor(i.goos, i.goarch)
	if err != nil {
		return Installation{}, err
	}
	if err := validateAssetSource(release, asset); err != nil {
		return Installation{}, err
	}

	versionsDir := filepath.Join(i.rootDir, engine, "versions")
	if err := os.MkdirAll(versionsDir, 0o700); err != nil {
		return Installation{}, fmt.Errorf("create core versions directory: %w", err)
	}
	finalDir := filepath.Join(versionsDir, release.Version)
	result := Installation{
		Engine: engine, Version: release.Version,
		BinaryPath: filepath.Join(finalDir, asset.Binary), MetadataPath: filepath.Join(finalDir, metadataName),
		Release: release,
	}
	if _, err := os.Stat(finalDir); err == nil {
		if err := i.verifyExisting(ctx, result, asset, request.CurrentConfiguration); err != nil {
			return Installation{}, err
		}
		return result, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Installation{}, fmt.Errorf("inspect installed core: %w", err)
	}

	stagingDir, err := os.MkdirTemp(versionsDir, ".install-"+release.Version+"-")
	if err != nil {
		return Installation{}, fmt.Errorf("create core staging directory: %w", err)
	}
	defer os.RemoveAll(stagingDir)
	archivePath := filepath.Join(stagingDir, "release.zip")
	if err := i.download(ctx, asset.URL, asset.SHA256, archivePath); err != nil {
		return Installation{}, err
	}
	binaryPath := filepath.Join(stagingDir, asset.Binary)
	binaryDigest, err := extractBinary(archivePath, asset.Binary, binaryPath, i.maxBinaryBytes)
	if err != nil {
		return Installation{}, err
	}
	if err := i.verifier.Verify(ctx, binaryPath, release.Version, request.CurrentConfiguration); err != nil {
		return Installation{}, fmt.Errorf("verify downloaded %s %s: %w", engine, release.Version, err)
	}
	if err := os.Remove(archivePath); err != nil {
		return Installation{}, fmt.Errorf("remove staged core archive: %w", err)
	}
	installed := metadata{
		SchemaVersion: 1, Engine: engine, Version: release.Version, SourceURL: asset.URL,
		ArchiveSHA256: asset.SHA256, BinarySHA256: binaryDigest, InstalledAt: time.Now().UTC(),
	}
	if err := writeJSON(filepath.Join(stagingDir, metadataName), installed); err != nil {
		return Installation{}, err
	}
	if err := os.Rename(stagingDir, finalDir); err != nil {
		if _, statErr := os.Stat(finalDir); statErr == nil {
			if verifyErr := i.verifyExisting(ctx, result, asset, request.CurrentConfiguration); verifyErr == nil {
				return result, nil
			}
		}
		return Installation{}, fmt.Errorf("publish installed core: %w", err)
	}
	if err := syncDirectory(versionsDir); err != nil {
		return Installation{}, fmt.Errorf("sync core versions directory: %w", err)
	}
	return result, nil
}

func (i *Installer) verifyExisting(ctx context.Context, installation Installation, asset corecatalog.Asset, config []byte) error {
	var installed metadata
	if err := readJSON(installation.MetadataPath, &installed); err != nil {
		return fmt.Errorf("verify existing core metadata: %w", err)
	}
	if installed.SchemaVersion != 1 || installed.Engine != installation.Engine || installed.Version != installation.Version ||
		installed.SourceURL != asset.URL || installed.ArchiveSHA256 != asset.SHA256 || installed.InstalledAt.IsZero() {
		return errors.New("existing core metadata does not match the audited release")
	}
	digest, err := digestRegularFile(installation.BinaryPath, i.maxBinaryBytes)
	if err != nil {
		return fmt.Errorf("verify existing core binary: %w", err)
	}
	if digest != installed.BinarySHA256 {
		return errors.New("existing core binary digest does not match its installation metadata")
	}
	if err := i.verifier.Verify(ctx, installation.BinaryPath, installation.Version, config); err != nil {
		return fmt.Errorf("verify existing %s %s: %w", installation.Engine, installation.Version, err)
	}
	return nil
}

func (i *Installer) download(ctx context.Context, sourceURL, wantDigest, target string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return fmt.Errorf("build core download request: %w", err)
	}
	request.Header.Set("User-Agent", "Passwall-Node core installer")
	response, err := i.client.Do(request)
	if err != nil {
		return fmt.Errorf("download core archive: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download core archive: unexpected HTTP status %d", response.StatusCode)
	}
	if response.ContentLength > i.maxArchiveBytes {
		return fmt.Errorf("download core archive: declared size exceeds %d bytes", i.maxArchiveBytes)
	}
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create staged core archive: %w", err)
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, i.maxArchiveBytes+1))
	syncErr := file.Sync()
	closeErr := file.Close()
	if copyErr != nil {
		return fmt.Errorf("download core archive: %w", copyErr)
	}
	if written > i.maxArchiveBytes {
		return fmt.Errorf("download core archive: body exceeds %d bytes", i.maxArchiveBytes)
	}
	if syncErr != nil {
		return fmt.Errorf("sync staged core archive: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close staged core archive: %w", closeErr)
	}
	gotDigest := hex.EncodeToString(hash.Sum(nil))
	if gotDigest != wantDigest {
		return fmt.Errorf("core archive SHA-256 mismatch: got %s", gotDigest)
	}
	return nil
}

func extractBinary(archivePath, member, target string, maxBytes int64) (string, error) {
	archive, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", fmt.Errorf("open core archive: %w", err)
	}
	defer archive.Close()
	var selected *zip.File
	for _, entry := range archive.File {
		if entry.Name == member {
			selected = entry
			break
		}
	}
	if selected == nil {
		return "", fmt.Errorf("core archive does not contain %q", member)
	}
	if !selected.Mode().IsRegular() || selected.UncompressedSize64 > uint64(maxBytes) {
		return "", errors.New("core archive binary is not a bounded regular file")
	}
	source, err := selected.Open()
	if err != nil {
		return "", fmt.Errorf("open core archive binary: %w", err)
	}
	defer source.Close()
	targetFile, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return "", fmt.Errorf("create staged core binary: %w", err)
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(targetFile, hash), io.LimitReader(source, maxBytes+1))
	syncErr := targetFile.Sync()
	closeErr := targetFile.Close()
	if copyErr != nil {
		return "", fmt.Errorf("extract core binary: %w", copyErr)
	}
	if written > maxBytes {
		return "", fmt.Errorf("core binary exceeds %d bytes", maxBytes)
	}
	if syncErr != nil {
		return "", fmt.Errorf("sync staged core binary: %w", syncErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close staged core binary: %w", closeErr)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func writeJSON(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode core installation metadata: %w", err)
	}
	encoded = append(encoded, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create core installation metadata: %w", err)
	}
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		return fmt.Errorf("write core installation metadata: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync core installation metadata: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close core installation metadata: %w", err)
	}
	return nil
}

func readJSON(path string, value any) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func digestRegularFile(path string, maxBytes int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > maxBytes {
		return "", errors.New("not a bounded regular file")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maxBytes+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func validateAssetSource(release corecatalog.Release, asset corecatalog.Asset) error {
	if asset.Archive != "zip" || asset.Binary == "" || asset.Binary != filepath.Base(asset.Binary) || strings.ContainsAny(asset.Binary, `/\\`) {
		return errors.New("core asset must name one root-level binary in a zip archive")
	}
	location, err := url.Parse(asset.URL)
	wantPrefix := "/XTLS/Xray-core/releases/download/v" + release.Version + "/"
	if err != nil || location.Scheme != "https" || location.Host != "github.com" ||
		!strings.HasPrefix(location.Path, wantPrefix) || location.RawQuery != "" || location.Fragment != "" || location.User != nil {
		return errors.New("core asset is not an official matching Xray release URL")
	}
	digest, err := hex.DecodeString(asset.SHA256)
	if err != nil || len(digest) != sha256.Size || asset.SHA256 != strings.ToLower(asset.SHA256) {
		return errors.New("core asset has an invalid SHA-256")
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil && runtime.GOOS != "windows" {
		return err
	}
	return nil
}

func secureHTTPClient(base *http.Client) *http.Client {
	client := *base
	previousCheck := client.CheckRedirect
	if client.Timeout <= 0 {
		client.Timeout = 5 * time.Minute
	}
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		host := strings.ToLower(request.URL.Hostname())
		if request.URL.Scheme != "https" || (host != "github.com" && !strings.HasSuffix(host, ".githubusercontent.com")) {
			return errors.New("core download redirected outside GitHub HTTPS")
		}
		if previousCheck != nil {
			return previousCheck(request, via)
		}
		return nil
	}
	return &client
}

type execVerifier struct{ timeout time.Duration }

func (v execVerifier) Verify(ctx context.Context, binaryPath, wantVersion string, config []byte) error {
	versionCtx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	output, err := boundedCommand(versionCtx, binaryPath, "version")
	if err != nil {
		return fmt.Errorf("read core version: %w: %s", err, output)
	}
	if got := versionFromOutput(output); got != wantVersion {
		return fmt.Errorf("core reported version %q, want %q", got, wantVersion)
	}
	if len(config) == 0 {
		return nil
	}
	configFile, err := os.CreateTemp(filepath.Dir(binaryPath), ".verify-config-*.json")
	if err != nil {
		return fmt.Errorf("create core verification config: %w", err)
	}
	configPath := configFile.Name()
	defer os.Remove(configPath)
	if err := configFile.Chmod(0o600); err != nil {
		_ = configFile.Close()
		return fmt.Errorf("secure core verification config: %w", err)
	}
	if _, err := configFile.Write(config); err != nil {
		_ = configFile.Close()
		return fmt.Errorf("write core verification config: %w", err)
	}
	if err := configFile.Close(); err != nil {
		return fmt.Errorf("close core verification config: %w", err)
	}
	checkCtx, checkCancel := context.WithTimeout(ctx, v.timeout)
	defer checkCancel()
	output, err = boundedCommand(checkCtx, binaryPath, "run", "-test", "-config", configPath)
	if err != nil {
		return fmt.Errorf("validate current core config: %w: %s", err, output)
	}
	return nil
}

func boundedCommand(ctx context.Context, path string, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, path, arguments...)
	buffer := &boundedBuffer{remaining: maxCommandOutput}
	command.Stdout = buffer
	command.Stderr = buffer
	err := command.Run()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return strings.TrimSpace(buffer.String()), err
}

func versionFromOutput(output string) string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "Xray" {
			version, err := corecatalog.NormalizeVersion(fields[1])
			if err == nil {
				return version
			}
		}
	}
	return ""
}

type boundedBuffer struct {
	buffer    bytes.Buffer
	remaining int
}

func (b *boundedBuffer) Write(content []byte) (int, error) {
	original := len(content)
	if len(content) > b.remaining {
		content = content[:b.remaining]
	}
	_, _ = b.buffer.Write(content)
	b.remaining -= len(content)
	return original, nil
}

func (b *boundedBuffer) String() string { return b.buffer.String() }

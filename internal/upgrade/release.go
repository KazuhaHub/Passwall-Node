package upgrade

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/KazuhaHub/passwall-node/deployment"
)

const (
	releaseDownloadBase = "https://github.com/KazuhaHub/Passwall-Node/releases/download/"
	maxChecksumBytes    = 256 << 10
	maxLicenseBytes     = 1 << 20
	maxArchiveMembers   = 128
	maxVersionOutput    = 4096
	defaultArchiveLimit = 128 << 20
	defaultBinaryLimit  = 256 << 20
	defaultVerifyLimit  = 20 * time.Second
)

// ReleaseFetcherOptions deliberately has no source URL or resolver. An upgrade
// task can select only an exact release from the official PN publisher.
type ReleaseFetcherOptions struct {
	RootDir         string
	HTTPClient      *http.Client
	GOARCH          string
	MaxArchiveBytes int64
	MaxBinaryBytes  int64
	CommandTimeout  time.Duration
}

// Candidate is verified but not activated. The caller owns Dir after success;
// neither fetching nor cleanup touches the installed identity or state.
type Candidate struct {
	Dir           string
	Version       string
	GOARCH        string
	BinaryPath    string
	LicensePath   string
	NoticePath    string
	ArchiveSHA256 string
	BinarySHA256  string
}

type ReleaseFetcher struct {
	rootDir        string
	client         *http.Client
	goarch         string
	archiveLimit   int64
	binaryLimit    int64
	commandTimeout time.Duration
}

func NewReleaseFetcher(options ReleaseFetcherOptions) (*ReleaseFetcher, error) {
	if !filepath.IsAbs(options.RootDir) || filepath.Clean(options.RootDir) != options.RootDir {
		return nil, errors.New("upgrade staging root must be an absolute canonical path")
	}
	if options.GOARCH == "" {
		options.GOARCH = runtime.GOARCH
	}
	if options.GOARCH != "amd64" && options.GOARCH != "arm64" {
		return nil, errors.New("agent upgrades support only Linux amd64 and arm64 releases")
	}
	if options.MaxArchiveBytes == 0 {
		options.MaxArchiveBytes = defaultArchiveLimit
	}
	if options.MaxBinaryBytes == 0 {
		options.MaxBinaryBytes = defaultBinaryLimit
	}
	if options.MaxArchiveBytes < 1 || options.MaxArchiveBytes > defaultArchiveLimit ||
		options.MaxBinaryBytes < 1 || options.MaxBinaryBytes > defaultBinaryLimit {
		return nil, errors.New("upgrade download limits must be positive and no larger than the safe defaults")
	}
	if options.CommandTimeout == 0 {
		options.CommandTimeout = defaultVerifyLimit
	}
	if options.CommandTimeout < 0 || options.CommandTimeout > defaultVerifyLimit {
		return nil, errors.New("upgrade verification timeout must be positive and at most twenty seconds")
	}
	client := http.Client{}
	if options.HTTPClient != nil {
		client = *options.HTTPClient
	}
	if client.Timeout <= 0 || client.Timeout > 5*time.Minute {
		client.Timeout = 5 * time.Minute
	}
	previousRedirect := client.CheckRedirect
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many upgrade download redirects")
		}
		if previousRedirect != nil {
			if err := previousRedirect(request, via); err != nil {
				return err
			}
		}
		if request.URL == nil || request.URL.Scheme != "https" || request.URL.User != nil ||
			(request.URL.Port() != "" && request.URL.Port() != "443") {
			return errors.New("upgrade download redirected outside trusted GitHub HTTPS")
		}
		host := strings.ToLower(request.URL.Hostname())
		if host != "github.com" && host != "release-assets.githubusercontent.com" && host != "objects.githubusercontent.com" {
			return errors.New("upgrade download redirected outside trusted GitHub HTTPS")
		}
		return nil
	}
	return &ReleaseFetcher{
		rootDir: options.RootDir, client: &client, goarch: options.GOARCH,
		archiveLimit: options.MaxArchiveBytes, binaryLimit: options.MaxBinaryBytes,
		commandTimeout: options.CommandTimeout,
	}, nil
}

func (f *ReleaseFetcher) Fetch(ctx context.Context, version string) (candidate Candidate, resultErr error) {
	if err := ctx.Err(); err != nil {
		return Candidate{}, err
	}
	if len(version) > 128 || !deployment.ValidReleaseVersion(version) {
		return Candidate{}, errors.New("upgrade requires an exact canonical PN release version")
	}
	if err := os.MkdirAll(f.rootDir, 0o700); err != nil {
		return Candidate{}, fmt.Errorf("create upgrade staging root: %w", err)
	}
	info, err := os.Lstat(f.rootDir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return Candidate{}, errors.New("upgrade staging root must be a private non-linked directory")
	}
	dir, err := os.MkdirTemp(f.rootDir, ".candidate-")
	if err != nil {
		return Candidate{}, fmt.Errorf("create private upgrade candidate: %w", err)
	}
	defer func() {
		if resultErr != nil {
			_ = os.RemoveAll(dir)
		}
	}()
	packageName := "passwall-node_" + version + "_linux_" + f.goarch
	assetName := packageName + ".tar.gz"
	checksumsPath := filepath.Join(dir, "SHA256SUMS.txt")
	if _, err := f.download(ctx, releaseDownloadBase+version+"/SHA256SUMS.txt", checksumsPath, maxChecksumBytes); err != nil {
		return Candidate{}, err
	}
	checksums, err := os.ReadFile(checksumsPath)
	if err != nil {
		return Candidate{}, errors.New("read staged upgrade checksums failed")
	}
	wantDigest, err := releaseChecksum(checksums, assetName)
	if err != nil {
		return Candidate{}, err
	}
	archivePath := filepath.Join(dir, "release.tar.gz")
	archiveDigest, err := f.download(ctx, releaseDownloadBase+version+"/"+assetName, archivePath, f.archiveLimit)
	if err != nil {
		return Candidate{}, err
	}
	if archiveDigest != wantDigest {
		return Candidate{}, errors.New("upgrade archive SHA-256 verification failed")
	}
	candidate = Candidate{
		Dir: dir, Version: version, GOARCH: f.goarch,
		BinaryPath: filepath.Join(dir, "passwall-node"), LicensePath: filepath.Join(dir, "LICENSE"),
		NoticePath: filepath.Join(dir, "NOTICE"), ArchiveSHA256: archiveDigest,
	}
	candidate.BinarySHA256, err = extractRelease(ctx, archivePath, packageName, dir, f.binaryLimit)
	if err != nil {
		return Candidate{}, err
	}
	if err := verifyReleaseBinary(ctx, candidate.BinaryPath, version, f.commandTimeout); err != nil {
		return Candidate{}, err
	}
	for _, temporary := range []string{checksumsPath, archivePath} {
		if err := os.Remove(temporary); err != nil {
			return Candidate{}, errors.New("remove temporary upgrade download failed")
		}
	}
	return candidate, nil
}

func (f *ReleaseFetcher) download(ctx context.Context, source, target string, limit int64) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return "", errors.New("create upgrade download request failed")
	}
	request.Header.Set("User-Agent", "Passwall-Node release upgrader")
	response, err := f.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		// url.Error includes signed redirect URLs. Do not expose it or bodies.
		return "", errors.New("upgrade release HTTPS download failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("upgrade release download returned HTTP status %d", response.StatusCode)
	}
	if response.ContentLength > limit {
		return "", errors.New("upgrade release declared download size exceeds its limit")
	}
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", errors.New("create private upgrade download failed")
	}
	digest := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, digest), io.LimitReader(response.Body, limit+1))
	syncErr := file.Sync()
	closeErr := file.Close()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if copyErr != nil || written > limit || syncErr != nil || closeErr != nil {
		return "", errors.New("write bounded upgrade release download failed")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func releaseChecksum(content []byte, asset string) (string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 4096), maxChecksumBytes)
	var digest string
	count := 0
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || strings.TrimPrefix(fields[1], "*") != asset {
			continue
		}
		count++
		decoded, err := hex.DecodeString(fields[0])
		if len(fields) != 2 || err != nil || len(decoded) != sha256.Size {
			return "", errors.New("upgrade checksum entry is malformed")
		}
		digest = strings.ToLower(fields[0])
	}
	if scanner.Err() != nil || count != 1 {
		return "", errors.New("upgrade checksum entry must exist exactly once")
	}
	return digest, nil
}

func extractRelease(ctx context.Context, archivePath, packageName, dir string, binaryLimit int64) (string, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return "", errors.New("open staged upgrade archive failed")
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		return "", errors.New("open upgrade gzip archive failed")
	}
	defer compressed.Close()
	// Bound the entire expanded archive, including ignored README/config files.
	expandedLimit := binaryLimit + 8<<20
	expanded := &io.LimitedReader{R: compressed, N: expandedLimit + 1}
	reader := tar.NewReader(expanded)
	seen := make(map[string]bool)
	found := make(map[string]bool)
	required := map[string]int64{"passwall-node": binaryLimit, "LICENSE": maxLicenseBytes, "NOTICE": maxLicenseBytes}
	var binaryDigest string
	var totalSize int64
	for entries := 0; ; entries++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || entries >= maxArchiveMembers {
			return "", errors.New("upgrade archive is invalid or contains too many entries")
		}
		name := strings.TrimSuffix(header.Name, "/")
		if name == "" || path.Clean(name) != name || strings.ContainsAny(name, "\\\x00") ||
			(name != packageName && !strings.HasPrefix(name, packageName+"/")) || seen[name] ||
			header.Linkname != "" || header.Size < 0 {
			return "", errors.New("upgrade archive contains an unsafe or duplicate member")
		}
		seen[name] = true
		if header.Typeflag == tar.TypeDir {
			_, requiredDirectory := required[strings.TrimPrefix(name, packageName+"/")]
			if header.Size != 0 || requiredDirectory {
				return "", errors.New("upgrade archive directory is malformed")
			}
			continue
		}
		if (header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) || name != header.Name || name == packageName {
			return "", errors.New("upgrade archive contains a non-regular member")
		}
		if header.Size > expandedLimit-totalSize {
			return "", errors.New("upgrade expanded archive exceeds its limit")
		}
		totalSize += header.Size
		member := strings.TrimPrefix(name, packageName+"/")
		limit, wanted := required[member]
		if !wanted {
			continue
		}
		if header.Size <= 0 || header.Size > limit {
			return "", errors.New("upgrade required member must be a non-empty bounded regular file")
		}
		target := filepath.Join(dir, member)
		output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return "", errors.New("create private upgrade archive member failed")
		}
		digest := sha256.New()
		written, copyErr := io.Copy(io.MultiWriter(output, digest), reader)
		syncErr := output.Sync()
		closeErr := output.Close()
		if copyErr != nil || written != header.Size || syncErr != nil || closeErr != nil {
			return "", errors.New("write upgrade archive member failed")
		}
		if member == "passwall-node" {
			binaryDigest = hex.EncodeToString(digest.Sum(nil))
		}
		found[member] = true
	}
	for member := range required {
		if !found[member] {
			return "", errors.New("upgrade archive is missing a required member")
		}
	}
	// Reading through the gzip trailer detects corruption beyond tar's EOF.
	if _, err := io.Copy(zeroReleasePadding{}, expanded); err != nil || expanded.N <= 0 {
		return "", errors.New("upgrade gzip integrity verification failed")
	}
	if err := os.Chmod(filepath.Join(dir, "passwall-node"), 0o700); err != nil {
		return "", errors.New("mark private upgrade binary executable failed")
	}
	return binaryDigest, nil
}

type zeroReleasePadding struct{}

func (zeroReleasePadding) Write(content []byte) (int, error) {
	for _, value := range content {
		if value != 0 {
			return 0, errors.New("upgrade archive has non-padding trailing data")
		}
	}
	return len(content), nil
}

func verifyReleaseBinary(ctx context.Context, binary, version string, timeout time.Duration) error {
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(commandContext, binary, "--version")
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	command.Dir = filepath.Dir(binary)
	command.WaitDelay = 500 * time.Millisecond
	output := &releaseOutput{}
	command.Stdout = output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("downloaded upgrade binary failed bounded native version verification")
	}
	pattern := "^" + regexp.QuoteMeta(version) + `(?: \([0-9a-f]{7,64}\))?\n?$`
	if !regexp.MustCompile(pattern).Match(output.content.Bytes()) {
		return errors.New("downloaded upgrade binary did not report the exact selected release")
	}
	return nil
}

type releaseOutput struct{ content bytes.Buffer }

func (o *releaseOutput) Write(content []byte) (int, error) {
	if len(content) > maxVersionOutput-o.content.Len() {
		return 0, errors.New("upgrade binary version output exceeds its limit")
	}
	return o.content.Write(content)
}

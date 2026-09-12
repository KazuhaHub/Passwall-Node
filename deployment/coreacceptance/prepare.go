package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/KazuhaHub/passwall-node/corecatalog"
	"github.com/KazuhaHub/passwall-node/internal/core/install"
)

const (
	xrayVersion          = "26.6.27"
	singBoxVersion       = "1.14.0"
	mihomoVersion        = "1.19.30"
	maxClientArchiveSize = 64 << 20
	maxClientBinarySize  = 128 << 20
)

type clientAsset struct {
	Name   string
	SHA256 string
}

// Exact official release asset digests were read from:
// https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/v1.19.30
// Use the amd64-v1 baseline rather than assuming the runner's CPU supports v3.
// Mihomo is a test client only; server assets remain catalog-owned.
var mihomoAssets = map[string]clientAsset{
	"linux/amd64": {
		Name: "mihomo-linux-amd64-v1-v1.19.30.gz", SHA256: "cbe553d0319a414bd3a372c5976a252155b2c4882b66bce88a4d6bba9571a553",
	},
	"linux/arm64": {
		Name: "mihomo-linux-arm64-v1.19.30.gz", SHA256: "58896873736d28628f66de3677c8654fa0f180662523148e136cff4f6e890069",
	},
	// Local macOS evidence is useful, but is never reported as Linux acceptance.
	"darwin/arm64": {
		Name: "mihomo-darwin-arm64-v1.19.30.gz", SHA256: "2c7f3a7904fa1cee291e124123e630e7b1ebd13765dd9bf26c0a28432004d9f4",
	},
}

type preparedBinary struct {
	Engine        string `json:"engine"`
	Version       string `json:"version"`
	Platform      string `json:"platform"`
	SourceURL     string `json:"source_url"`
	ArchiveSHA256 string `json:"archive_sha256"`
	BinaryPath    string `json:"binary_path"`
}

func prepare(ctx context.Context, directory, environmentFile string, output io.Writer) error {
	if err := validateOutputPath(directory); err != nil {
		return fmt.Errorf("directory: %w", err)
	}
	if err := validateOutputPath(environmentFile); err != nil {
		return fmt.Errorf("env-file: %w", err)
	}
	platform := runtime.GOOS + "/" + runtime.GOARCH
	client, ok := mihomoAssets[platform]
	if !ok {
		return fmt.Errorf("unsupported acceptance fixture platform %s", platform)
	}
	for engine, expected := range map[string]string{"xray": xrayVersion, "sing-box": singBoxVersion} {
		recommended, err := corecatalog.Recommended(engine)
		if err != nil {
			return err
		}
		if recommended.Version != expected {
			return fmt.Errorf("%s recommended version %s differs from acceptance pin %s: update evidence deliberately", engine, recommended.Version, expected)
		}
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	installer, err := install.New(install.Options{RootDir: filepath.Join(directory, "cores")})
	if err != nil {
		return err
	}
	binaries := make([]preparedBinary, 0, 3)
	for _, pin := range []struct{ engine, version string }{{"xray", xrayVersion}, {"sing-box", singBoxVersion}} {
		installed, err := installer.Install(ctx, install.Request{Engine: pin.engine, Version: pin.version})
		if err != nil {
			return fmt.Errorf("install official %s %s: %w", pin.engine, pin.version, err)
		}
		asset, err := installed.Release.AssetFor(runtime.GOOS, runtime.GOARCH)
		if err != nil {
			return err
		}
		binaries = append(binaries, preparedBinary{pin.engine, pin.version, platform, asset.URL, asset.SHA256, installed.BinaryPath})
	}
	clientURL := "https://github.com/MetaCubeX/mihomo/releases/download/v" + mihomoVersion + "/" + client.Name
	clientBinary, err := prepareMihomo(ctx, directory, clientURL, client.SHA256)
	if err != nil {
		return err
	}
	binaries = append(binaries, preparedBinary{"mihomo", mihomoVersion, platform, clientURL, client.SHA256, clientBinary})
	environment := [][2]string{
		{"PSP_TEST_CORE_INSTALL", "1"},
		{"PSP_TEST_SING_BOX_INSTALL", "1"},
		{"PSP_TEST_XRAY_26627_BIN", binaries[0].BinaryPath},
		{"PSP_TEST_XRAY_CLIENT_BIN", binaries[0].BinaryPath},
		{"PSP_TEST_SING_BOX_BIN", binaries[1].BinaryPath},
		{"PSP_TEST_MIHOMO_CLIENT_BIN", clientBinary},
	}
	if err := appendEnvironment(environmentFile, environment); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(binaries)
}

func validateOutputPath(value string) error {
	if !filepath.IsAbs(value) || strings.ContainsAny(value, "\r\n\x00") {
		return errors.New("must be an absolute path without newlines or NUL")
	}
	return nil
}

func appendEnvironment(filename string, entries [][2]string) error {
	var content strings.Builder
	for _, entry := range entries {
		if strings.ContainsAny(entry[0]+entry[1], "\r\n\x00") {
			return errors.New("unsafe environment entry")
		}
		fmt.Fprintf(&content, "%s=%s\n", entry[0], entry[1])
	}
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.WriteString(file, content.String())
	return err
}

func prepareMihomo(ctx context.Context, directory, sourceURL, digest string) (string, error) {
	client := &http.Client{Timeout: 3 * time.Minute, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if len(via) >= 10 || request.URL.Scheme != "https" || request.URL.User != nil ||
			(request.URL.Hostname() != "github.com" && !strings.HasSuffix(request.URL.Hostname(), ".githubusercontent.com")) {
			return errors.New("Mihomo redirect outside official HTTPS release hosts")
		}
		return nil
	}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("download official Mihomo: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("official Mihomo download status %d", response.StatusCode)
	}
	archive, err := io.ReadAll(io.LimitReader(response.Body, maxClientArchiveSize+1))
	if err != nil || len(archive) > maxClientArchiveSize {
		return "", errors.New("Mihomo archive unreadable or larger than limit")
	}
	clientDirectory, err := os.MkdirTemp(directory, "mihomo-"+mihomoVersion+"-")
	if err != nil {
		return "", err
	}
	binary := filepath.Join(clientDirectory, "mihomo")
	if err := unpackClient(archive, digest, binary); err != nil {
		return "", err
	}
	commandContext, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	versionOutput, err := exec.CommandContext(commandContext, binary, "-v").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("execute verified Mihomo version: %w", err)
	}
	if err := verifyMihomoVersion(versionOutput); err != nil {
		return "", err
	}
	return binary, nil
}

func unpackClient(archive []byte, digest, destination string) error {
	return unpackClientBounded(archive, digest, destination, maxClientBinarySize)
}

func unpackClientBounded(archive []byte, digest, destination string, limit int64) error {
	actual := sha256.Sum256(archive)
	if hex.EncodeToString(actual[:]) != digest {
		return errors.New("Mihomo archive SHA256 mismatch")
	}
	reader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return err
	}
	defer reader.Close()
	// The gzip filename is deliberately ignored: write one verified binary only.
	binary, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil || len(binary) == 0 || int64(len(binary)) > limit {
		return errors.New("Mihomo binary unreadable, empty or larger than limit")
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return err
	}
	if _, err := file.Write(binary); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func verifyMihomoVersion(output []byte) error {
	match := regexp.MustCompile(`(?m)^Mihomo Meta (v[0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)`).FindSubmatch(output)
	if len(match) != 2 || string(match[1]) != "v"+mihomoVersion {
		return errors.New("verified Mihomo binary did not report the exact pinned version")
	}
	return nil
}

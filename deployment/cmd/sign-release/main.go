package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/KazuhaHub/passwall-node/v4/internal/releaseauth"
)

const maxSigningInput = 256 << 10

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	manifestPath := flag.String("manifest", "", "path to SHA256SUMS.txt")
	outputPath := flag.String("output", "", "path to detached signature")
	keyPath := flag.String("key", "", "path to the private PKCS#8 PEM (local signing only)")
	flag.Parse()
	if flag.NArg() != 0 || *manifestPath == "" || *outputPath == "" {
		return errors.New("sign-release requires -manifest and -output")
	}
	privateKey, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	if !bytes.Equal(privateKey.Public().(ed25519.PublicKey), releaseauth.PublicKey()) {
		return errors.New("release signing private key does not match the public key compiled into the agent")
	}
	manifest, err := readBoundedRegular(*manifestPath, maxSigningInput)
	if err != nil {
		return fmt.Errorf("read release manifest: %w", err)
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, manifest)) + "\n")
	if err := releaseauth.VerifyManifest(manifest, encoded); err != nil {
		return fmt.Errorf("self-verify release signature: %w", err)
	}
	if filepath.Clean(*outputPath) != *outputPath {
		return errors.New("signature output path must be canonical")
	}
	file, err := os.OpenFile(*outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return errors.New("create release signature output failed")
	}
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		return errors.New("write release signature output failed")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("sync release signature output failed")
	}
	if err := file.Close(); err != nil {
		return errors.New("close release signature output failed")
	}
	return nil
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	var content []byte
	if path != "" {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("release signing key file must be a private regular file")
		}
		content, err = os.ReadFile(path)
		if err != nil {
			return nil, errors.New("read release signing key failed")
		}
	} else {
		content = []byte(os.Getenv("PN_RELEASE_SIGNING_PRIVATE_KEY"))
	}
	if len(content) == 0 || len(content) > 16<<10 {
		return nil, errors.New("release signing private key is missing or too large")
	}
	block, rest := pem.Decode(content)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("release signing key must be one PKCS#8 PRIVATE KEY PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("parse release signing private key failed")
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("release signing key must be Ed25519")
	}
	return privateKey, nil
}

func readBoundedRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("input must be a non-empty bounded regular file")
	}
	return os.ReadFile(path)
}

// Package releaseauth verifies the detached signature on Passwall-Node release
// manifests. The public key is compiled into every agent so the checksum and
// archive cannot establish trust merely by agreeing with each other at the same
// mutable release origin.
package releaseauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
)

const (
	SignatureAssetName = "SHA256SUMS.txt.sig"
	publicKeyBase64    = "ugFw5h6D5JY9toC182RZZW//soFUvNjpGl+Ka7FIpMk="
)

// PublicKey returns a copy of the pinned release-signing public key.
func PublicKey() ed25519.PublicKey {
	decoded, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		panic("invalid compiled Passwall-Node release signing key")
	}
	return ed25519.PublicKey(decoded)
}

// VerifyManifest authenticates the exact SHA256SUMS.txt bytes before callers
// are allowed to trust any digest from that manifest. The detached signature is
// canonical base64 with an optional trailing newline.
func VerifyManifest(manifest, encodedSignature []byte) error {
	return verifyManifest(PublicKey(), manifest, encodedSignature)
}

func verifyManifest(publicKey ed25519.PublicKey, manifest, encodedSignature []byte) error {
	trimmed := encodedSignature
	if bytes.HasSuffix(trimmed, []byte("\n")) {
		trimmed = trimmed[:len(trimmed)-1]
	}
	if len(trimmed) == 0 || bytes.IndexAny(trimmed, " \t\r\n") >= 0 {
		return errors.New("release manifest signature has invalid framing")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(string(trimmed))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("release manifest signature is malformed")
	}
	if !ed25519.Verify(publicKey, manifest, signature) {
		return errors.New("release manifest signature verification failed")
	}
	return nil
}

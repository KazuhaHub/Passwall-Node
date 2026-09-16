package releaseauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestVerifyManifestAuthenticatesExactBytes(t *testing.T) {
	seed := sha256.Sum256([]byte("Passwall-Node releaseauth unit-test key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	manifest := []byte("abc  passwall-node_v1.2.3_linux_amd64.tar.gz\n")
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, manifest)) + "\n"
	if err := verifyManifest(publicKey, manifest, []byte(signature)); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	for name, testCase := range map[string]struct {
		manifest  []byte
		signature []byte
	}{
		"manifest":          {append(append([]byte(nil), manifest...), 'x'), []byte(signature)},
		"signature":         {manifest, []byte("A" + signature[1:])},
		"leading-space":     {manifest, []byte(" " + signature)},
		"multiple-newlines": {manifest, []byte(signature + "\n")},
	} {
		t.Run(name, func(t *testing.T) {
			if err := verifyManifest(publicKey, testCase.manifest, testCase.signature); err == nil {
				t.Fatal("tampered release authentication accepted")
			}
		})
	}
}

func TestPinnedReleasePublicKeyShape(t *testing.T) {
	if got := PublicKey(); len(got) != ed25519.PublicKeySize {
		t.Fatalf("pinned public key length = %d", len(got))
	}
}

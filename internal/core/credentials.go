package core

import (
	"encoding/hex"
	"strings"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// CredentialSet finds clients of ONE listener whose credential is one of an
// earlier client's. Two rows with one credential are one user to the core: it
// authenticates the first it finds and attributes every byte to it, so the
// second row's traffic would be counted, limited and blocked as someone else's.
//
// What counts as the same credential is what the engine compares:
//   - VLESS on Xray: the UUID with bytes 6 and 7 masked. Xray keys its VLESS
//     users by the UUID with those two bytes zeroed (where a UUID's version and
//     variant live), so two UUIDs differing only there are one user. Set
//     MaskVLESS for it.
//   - VLESS on sing-box, and VMess on both: the whole UUID.
//   - Trojan and Shadowsocks: the password.
//
// A UUID is compared as the 16 bytes it spells (dashes and case ignored); a
// string that is not one is compared as written, because the core derives its
// key from the text. A client is added only after its credential has been
// validated: an empty one is "required", not a duplicate of another empty one.
type CredentialSet struct {
	protocol  string
	maskVLESS bool
	seen      map[string]protocol.ClientKey
}

// NewCredentialSet starts an empty set for a listener of the protocol.
func NewCredentialSet(protocolName string, maskVLESS bool) *CredentialSet {
	return &CredentialSet{protocol: strings.ToLower(protocolName), maskVLESS: maskVLESS, seen: map[string]protocol.ClientKey{}}
}

// Add records the client and reports whether an earlier client has the same
// credential, and which.
func (s *CredentialSet) Add(client protocol.Client) (original protocol.ClientKey, duplicate bool) {
	identity := s.identity(client.Credentials)
	if identity == "" {
		return "", false
	}
	if other, exists := s.seen[identity]; exists {
		return other, true
	}
	s.seen[identity] = client.Key
	return "", false
}

func (s *CredentialSet) identity(credential protocol.Credential) string {
	switch s.protocol {
	case "vless":
		return "uuid:" + uuidIdentity(credential.UUID, s.maskVLESS)
	case "vmess":
		return "uuid:" + uuidIdentity(credential.UUID, false)
	case "trojan", "shadowsocks":
		if credential.Password == "" {
			return ""
		}
		return "password:" + credential.Password
	}
	return ""
}

func uuidIdentity(text string, maskVersionBytes bool) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	compact := strings.ToLower(strings.ReplaceAll(text, "-", ""))
	raw, err := hex.DecodeString(compact)
	if err != nil || len(raw) != 16 || (len(text) != 36 && len(text) != 32) {
		return "text:" + text
	}
	if maskVersionBytes {
		raw[6], raw[7] = 0, 0
	}
	return hex.EncodeToString(raw)
}

// DuplicateCredentialRejection is the rejection of a client that is left out of a listener.
func DuplicateCredentialRejection(client, original protocol.ClientKey, listener protocol.ListenerKey) *ObjectError {
	return &ObjectError{Stream: protocol.StreamRoster, Key: string(client), Code: "core_config_rejected",
		Err: errDuplicate(client, original, listener)}
}

func errDuplicate(client, original protocol.ClientKey, listener protocol.ListenerKey) error {
	return &duplicateError{client: client, original: original, listener: listener}
}

type duplicateError struct {
	client, original protocol.ClientKey
	listener         protocol.ListenerKey
}

func (e *duplicateError) Error() string {
	return "credential duplicates client " + string(e.original) + " on listener " + string(e.listener) + "; the earlier client is served and this one is not"
}

// DedupeRejected keeps one rejection per object: a client that duplicates on two
// listeners is one rejected object.
func DedupeRejected(rejected []*ObjectError) []*ObjectError {
	var out []*ObjectError
	seen := map[string]bool{}
	for _, entry := range rejected {
		if key := entry.Stream + "/" + entry.Key; !seen[key] {
			seen[key] = true
			out = append(out, entry)
		}
	}
	return out
}

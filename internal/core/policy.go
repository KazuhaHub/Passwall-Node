package core

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// PolicyEmails expands only active credentials in this immutable deployment.
// An empty result must make the compiler omit a scoped rule, never emit user:[].
func PolicyEmails(snapshot Snapshot, subjects []protocol.SubjectKey) []string {
	if len(subjects) == 0 {
		return nil
	}
	wanted := make(map[protocol.SubjectKey]bool, len(subjects))
	for _, s := range subjects {
		wanted[s] = true
	}
	seen := map[string]bool{}
	for _, client := range snapshot.Clients {
		if !wanted[client.Subject] || !client.Enabled || len(client.Listeners) == 0 || client.ExpiresAtMS > 0 && !snapshot.Now.IsZero() && snapshot.Now.UnixMilli() >= client.ExpiresAtMS {
			continue
		}
		if email := strings.TrimSpace(client.Credentials.Username); email != "" {
			seen[email] = true
		}
	}
	result := make([]string, 0, len(seen))
	for email := range seen {
		result = append(result, email)
	}
	sort.Strings(result)
	return result
}

// DestinationSniffingCheck distinguishes valid but insufficient sniffing from
// malformed listener data. The latter must remain an ObjectError, not policy.
type DestinationSniffingCheck struct {
	Sufficient bool
	Inject     bool
	Reason     string
}

func CheckDestinationSniffing(raw json.RawMessage) DestinationSniffingCheck {
	if len(raw) == 0 {
		return DestinationSniffingCheck{Sufficient: true, Inject: true}
	}
	var spec struct {
		Enabled         bool            `json:"enabled"`
		DestOverride    []string        `json:"destOverride"`
		MetadataOnly    bool            `json:"metadataOnly"`
		DomainsExcluded json.RawMessage `json:"domainsExcluded"`
	}
	if json.Unmarshal(raw, &spec) != nil {
		return DestinationSniffingCheck{Reason: "invalid_config"}
	}
	if !spec.Enabled {
		return DestinationSniffingCheck{Sufficient: true, Inject: true}
	}
	if spec.MetadataOnly {
		return DestinationSniffingCheck{Reason: "metadata_only"}
	}
	set := map[string]bool{}
	for _, value := range spec.DestOverride {
		set[value] = true
	}
	if !set["http"] || !set["tls"] || !set["quic"] {
		return DestinationSniffingCheck{Reason: "missing_dest_override"}
	}
	if len(spec.DomainsExcluded) > 0 {
		return DestinationSniffingCheck{Reason: "domains_excluded"}
	}
	return DestinationSniffingCheck{Sufficient: true}
}

// DestinationPrivateCIDRs is the exact Xray private/reserved address table.
// Return a fresh slice so callers cannot corrupt another deployment's rules.
func DestinationPrivateCIDRs() []string {
	return []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3", "::/127", "fc00::/7", "fe80::/10", "ff00::/8"}
}

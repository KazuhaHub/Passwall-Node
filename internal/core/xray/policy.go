package xray

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func (c Compiler) compileDestinationPolicy(config *xrayConfig, snapshot agentcore.Snapshot) error {
	p := snapshot.DestinationPolicy
	if p == nil {
		return nil
	}
	if err := protocol.ValidateDestinationPolicy(p); err != nil {
		return &agentcore.PolicyError{Code: protocol.IssueDestinationPolicyRejected, Err: err}
	}
	rules := []map[string]any{}
	needsSniffing, exemptAdded := false, false
	addExempt := func() {
		if emails := agentcore.PolicyEmails(snapshot, p.Exempt); len(emails) > 0 {
			rules = append(rules, map[string]any{"type": "field", "ruleTag": "psp-exempt", "user": emails, "outboundTag": "direct"})
		}
		exemptAdded = true
	}
	for _, rule := range p.Rules {
		if !exemptAdded && !(rule.Action == protocol.RuleAllow && strings.HasPrefix(rule.ID, "p")) {
			addExempt()
		}
		emails := agentcore.PolicyEmails(snapshot, rule.Subjects)
		if len(rule.Subjects) > 0 && len(emails) == 0 {
			continue
		}
		base := map[string]any{"type": "field", "ruleTag": "psp-" + rule.ID, "outboundTag": "direct"}
		if len(rule.Subjects) > 0 {
			base["user"] = emails
		}
		if rule.Ports != "" {
			base["port"] = rule.Ports
		}
		if rule.Network != "" {
			base["network"] = rule.Network
		}
		if len(rule.Protocols) > 0 {
			base["protocol"] = rule.Protocols
		}
		if rule.Action != protocol.RuleAllow {
			tag, kind := "psp-deny-"+rule.ID, "blackhole"
			if rule.Action == protocol.RuleObserve {
				tag, kind = "psp-watch-"+rule.ID, "freedom"
			}
			base["outboundTag"] = tag
			config.Outbounds = append(config.Outbounds, map[string]any{"tag": tag, "protocol": kind, "settings": map[string]any{}})
			if p.Collect != "" && (path.IsAbs(c.AuditSocket) || filepath.IsAbs(c.AuditSocket)) && len(c.AuditSocket) <= 100 && len(c.AuditToken) >= 32 {
				base["webhook"] = map[string]any{"url": c.AuditSocket + ":/hit", "headers": map[string]string{"X-PSP-Audit": c.AuditToken, "X-PSP-Audit-Revision": strconv.FormatUint(p.CollectRevision, 10)}}
			}
		}
		ips := append([]string(nil), rule.CIDRs...)
		if rule.Private {
			ips = append(ips, agentcore.DestinationPrivateCIDRs()...)
		}
		sort.Strings(ips)
		unique := ips[:0]
		for _, ip := range ips {
			if len(unique) == 0 || unique[len(unique)-1] != ip {
				unique = append(unique, ip)
			}
		}
		ips = unique
		if len(rule.Domains) > 0 && len(ips) > 0 {
			domainRule, ipRule := copyDestinationRule(base), copyDestinationRule(base)
			domainRule["domain"] = rule.Domains
			domainRule["ruleTag"] = "psp-" + rule.ID + "a"
			ipRule["ip"] = ips
			ipRule["ruleTag"] = "psp-" + rule.ID + "b"
			rules = append(rules, domainRule, ipRule)
		} else {
			if len(rule.Domains) > 0 {
				base["domain"] = rule.Domains
			}
			if len(ips) > 0 {
				base["ip"] = ips
			}
			rules = append(rules, base)
		}
		needsSniffing = needsSniffing || len(rule.Domains) > 0 || len(rule.Protocols) > 0
	}
	if !exemptAdded {
		addExempt()
	}
	if needsSniffing {
		insufficient := []protocol.ListenerKey{}
		for _, inbound := range config.Inbounds {
			var raw json.RawMessage
			if value, ok := inbound["sniffing"]; ok {
				raw, _ = json.Marshal(value)
			}
			check := agentcore.CheckDestinationSniffing(raw)
			key := protocol.ListenerKey(strings.TrimPrefix(inbound["tag"].(string), "psp-"))
			if check.Reason == "invalid_config" {
				return compileListenerError(key, errors.New("invalid sniffing object"))
			}
			if !check.Sufficient {
				insufficient = append(insufficient, key)
				continue
			}
			if check.Inject {
				inbound["sniffing"] = map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true}
			}
		}
		if len(insufficient) > 0 {
			return &agentcore.PolicyError{Code: protocol.IssueDestinationPolicySniffingInsufficient, Listeners: insufficient, Err: fmt.Errorf("enabled listener sniffing cannot support destination policy")}
		}
	}
	if len(rules) > 0 {
		config.Routing = map[string]any{"domainStrategy": "AsIs", "rules": rules}
	}
	return nil
}

func copyDestinationRule(input map[string]any) map[string]any {
	result := make(map[string]any, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

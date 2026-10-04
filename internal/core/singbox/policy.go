package singbox

import (
	"strconv"
	"strings"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func compileDestinationPolicy(result *config, snapshot agentcore.Snapshot) error {
	p := snapshot.DestinationPolicy
	if p == nil {
		return nil
	}
	if err := protocol.ValidateDestinationPolicy(p); err != nil {
		return &agentcore.PolicyError{Code: protocol.IssueDestinationPolicyRejected, Err: err}
	}
	rules := []map[string]any{}
	exemptAdded, needsSniffing := false, false
	addExempt := func() {
		if users := agentcore.PolicyEmails(snapshot, p.Exempt); len(users) > 0 {
			rules = append(rules, map[string]any{"auth_user": users, "action": "route", "outbound": "direct"})
		}
		exemptAdded = true
	}
	for _, r := range p.Rules {
		if !exemptAdded && !(r.Action == protocol.RuleAllow && strings.HasPrefix(r.ID, "p")) {
			addExempt()
		}
		users := agentcore.PolicyEmails(snapshot, r.Subjects)
		if len(r.Subjects) > 0 && len(users) == 0 {
			continue
		}
		rule := map[string]any{}
		if len(r.Subjects) > 0 {
			rule["auth_user"] = users
		}
		domains := map[string][]string{}
		for _, entry := range r.Domains {
			prefix, value, _ := strings.Cut(entry, ":")
			field := map[string]string{"domain": "domain_suffix", "full": "domain", "keyword": "domain_keyword", "regexp": "domain_regex"}[prefix]
			domains[field] = append(domains[field], value)
		}
		for field, values := range domains {
			rule[field] = values
		}
		if len(r.CIDRs) > 0 {
			rule["ip_cidr"] = r.CIDRs
		}
		if r.Private {
			rule["ip_is_private"] = true
		}
		if r.Network != "" {
			rule["network"] = []string{r.Network}
		}
		if len(r.Protocols) > 0 {
			rule["protocol"] = r.Protocols
		}
		if r.Ports != "" {
			ports := []int{}
			ranges := []string{}
			for _, part := range strings.Split(r.Ports, ",") {
				left, right, isRange := strings.Cut(part, "-")
				if isRange {
					ranges = append(ranges, left+":"+right)
				} else {
					port, _ := strconv.Atoi(left)
					ports = append(ports, port)
				}
			}
			if len(ports) > 0 {
				rule["port"] = ports
			}
			if len(ranges) > 0 {
				rule["port_range"] = ranges
			}
		}
		switch r.Action {
		case protocol.RuleBlock:
			rule["action"] = "reject"
		case protocol.RuleAllow:
			rule["action"] = "route"
			rule["outbound"] = "direct"
		case protocol.RuleObserve:
			tag := "psp-watch-" + r.ID
			rule["action"] = "route"
			rule["outbound"] = tag
			result.Outbounds = append(result.Outbounds, map[string]any{"type": "direct", "tag": tag})
		}
		rules = append(rules, rule)
		needsSniffing = needsSniffing || len(r.Domains) > 0 || len(r.Protocols) > 0
	}
	if !exemptAdded {
		addExempt()
	}
	if needsSniffing {
		rules = append([]map[string]any{{"action": "sniff"}}, rules...)
	}
	if len(rules) > 0 {
		result.Route["rules"] = rules
	}
	return nil
}

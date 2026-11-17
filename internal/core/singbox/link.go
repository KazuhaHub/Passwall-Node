package singbox

import (
	"net"
	"sort"
	"strconv"
	"strings"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// compileLinkIn is the exit's half of a link: an inbound that accepts only the
// link's credential. routeTransit sends its traffic straight out; the entry
// already applied the policy that governs it.
func compileLinkIn(link protocol.LinkIn) map[string]any {
	listen := link.Listen
	if listen == "" {
		listen = "::"
	}
	inbound := map[string]any{"tag": agentcore.LinkTag(link.Key), "listen": listen, "listen_port": link.Port}
	switch link.Protocol {
	case protocol.LinkProtocolSS2022:
		inbound["type"] = "shadowsocks"
		inbound["method"] = link.SS.Method
		inbound["password"] = link.SS.Password
	case protocol.LinkProtocolVLESSReality:
		reality := link.Reality
		host, portText, _ := net.SplitHostPort(reality.Target)
		port, _ := strconv.Atoi(portText)
		inbound["type"] = "vless"
		inbound["users"] = []any{map[string]any{"uuid": reality.UUID, "flow": "xtls-rprx-vision"}}
		inbound["tls"] = map[string]any{
			"enabled": true, "server_name": reality.ServerNames[0],
			"reality": map[string]any{
				"enabled":     true,
				"handshake":   map[string]any{"server": host, "server_port": port},
				"private_key": reality.PrivateKey, "short_id": reality.ShortIDs,
			},
		}
	}
	return inbound
}

// compileLinkOut is the entry's half of a link: an outbound that dials the
// exit with the user's destination as given.
func compileLinkOut(link protocol.LinkOut) map[string]any {
	outbound := map[string]any{"tag": agentcore.LinkTag(link.Key), "server": link.Address, "server_port": link.Port}
	switch link.Protocol {
	case protocol.LinkProtocolSS2022:
		outbound["type"] = "shadowsocks"
		outbound["method"] = link.SS.Method
		outbound["password"] = link.SS.Password
	case protocol.LinkProtocolVLESSReality:
		reality := link.Reality
		outbound["type"] = "vless"
		outbound["uuid"] = reality.UUID
		outbound["flow"] = "xtls-rprx-vision"
		outbound["tls"] = map[string]any{
			"enabled": true, "server_name": reality.ServerName,
			"utls":    map[string]any{"enabled": true, "fingerprint": reality.Fingerprint},
			"reality": map[string]any{"enabled": true, "public_key": reality.PublicKey, "short_id": reality.ShortID},
		}
	}
	return outbound
}

// applyEgress sends each bound listener's permitted traffic through its link.
// It is the Xray adapter's split (see there for why it keeps every verdict),
// in sing-box's terms: a rule that routes to direct, or to a report-only
// outbound, is copied once per group of listeners leaving the same way, each
// copy restricted to its group's inbounds; a link group's copy routes to the
// link. Rejections, sniff and resolve actions are left as they are. Each link
// group ends with a catch-all to its link, as the local group falls to
// route.final.
//
// sing-box records no hits, so a report-only copy routes to the link itself.
func applyEgress(result *config, served []protocol.ListenerKey, egress map[protocol.ListenerKey]protocol.LinkKey) {
	if len(egress) == 0 {
		return
	}
	groups := agentcore.GroupByEgress(served, egress)
	if len(groups.Order) == 0 {
		return
	}
	tagsOf := func(keys []protocol.ListenerKey) []string {
		out := make([]string, 0, len(keys))
		for _, key := range keys {
			out = append(out, "psp-"+string(key))
		}
		return out
	}
	allServed := tagsOf(served)
	localTags := tagsOf(groups.Local)
	linkTags := make(map[protocol.LinkKey][]string, len(groups.Order))
	for _, link := range groups.Order {
		linkTags[link] = tagsOf(groups.Links[link])
	}
	rules, _ := result.Route["rules"].([]map[string]any)
	out := make([]map[string]any, 0, len(rules)+len(groups.Order))
	for _, rule := range rules {
		action, _ := rule["action"].(string)
		target, _ := rule["outbound"].(string)
		scope, restricted := rule["inbound"].([]string)
		if restricted && touchesTransit(scope) {
			out = append(out, rule)
			continue
		}
		watch := strings.HasPrefix(target, "psp-watch-")
		if action != "route" || (target != "direct" && !watch) {
			out = append(out, rule)
			continue
		}
		if !restricted {
			scope = allServed
		}
		if local := intersect(scope, localTags); len(local) > 0 {
			out = append(out, restrictToInbounds(rule, local, target))
		}
		for _, link := range groups.Order {
			if members := intersect(scope, linkTags[link]); len(members) > 0 {
				out = append(out, restrictToInbounds(rule, members, agentcore.LinkTag(link)))
			}
		}
	}
	for _, link := range groups.Order {
		out = append(out, map[string]any{"inbound": linkTags[link], "action": "route", "outbound": agentcore.LinkTag(link)})
	}
	result.Route["rules"] = out
}

// restrictToInbounds returns a copy of rule that also requires one of tags and
// routes to outbound. A default rule takes the condition as a field, which
// sing-box ANDs with its other fields; a logical rule is wrapped in an "and"
// with it, because a logical rule's own fields are its children.
func restrictToInbounds(rule map[string]any, tags []string, outbound string) map[string]any {
	if rule["type"] != "logical" {
		copy := make(map[string]any, len(rule)+1)
		for key, value := range rule {
			copy[key] = value
		}
		copy["inbound"] = tags
		copy["outbound"] = outbound
		return copy
	}
	condition := make(map[string]any, len(rule))
	for key, value := range rule {
		if key != "action" && key != "outbound" {
			condition[key] = value
		}
	}
	return map[string]any{
		"type": "logical", "mode": "and",
		"rules":  []map[string]any{{"inbound": tags}, condition},
		"action": "route", "outbound": outbound,
	}
}

func touchesTransit(tags []string) bool {
	for _, tag := range tags {
		if strings.HasPrefix(tag, agentcore.TransitTagPrefix) {
			return true
		}
	}
	return false
}

func intersect(scope, group []string) []string {
	member := make(map[string]bool, len(group))
	for _, tag := range group {
		member[tag] = true
	}
	var out []string
	for _, tag := range scope {
		if member[tag] {
			out = append(out, tag)
		}
	}
	return out
}

func transitInboundTags(plan agentcore.TransitPlan) []string {
	tags := make([]string, 0, len(plan.Forwards)+len(plan.LinksIn))
	for _, forward := range plan.Forwards {
		tags = append(tags, agentcore.ForwardTag(forward.Key))
	}
	for _, link := range plan.LinksIn {
		tags = append(tags, agentcore.LinkTag(link.Key))
	}
	sort.Strings(tags)
	return tags
}

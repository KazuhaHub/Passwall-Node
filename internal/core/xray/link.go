package xray

import (
	"errors"
	"sort"
	"strings"

	"github.com/KazuhaHub/passwall-node/v4/corecatalog"
	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// compileLinkIn is the exit's half of a link: an inbound that accepts only the
// link's credential. Its traffic is routed straight out by routeTransit, never
// through the destination policy: the entry already applied the policy that
// governs it.
//
// A REALITY link passes the same client-compatibility gate as a REALITY
// listener: the entry dialing it may run either engine, and a release whose
// REALITY narrows the clients it accepts is refused (or given its minimum
// client version) exactly as it would be for users.
func (c Compiler) compileLinkIn(release corecatalog.Release, link protocol.LinkIn) (map[string]any, error) {
	inbound := map[string]any{"tag": agentcore.LinkTag(link.Key), "port": link.Port}
	if link.Listen != "" {
		inbound["listen"] = link.Listen
	}
	switch link.Protocol {
	case protocol.LinkProtocolSS2022:
		inbound["protocol"] = "shadowsocks"
		inbound["settings"] = map[string]any{
			"method": link.SS.Method, "password": link.SS.Password, "network": "tcp,udp",
		}
	case protocol.LinkProtocolVLESSReality:
		reality := link.Reality
		inbound["protocol"] = "vless"
		inbound["settings"] = map[string]any{
			"clients":    []any{map[string]any{"id": reality.UUID, "flow": "xtls-rprx-vision"}},
			"decryption": "none",
		}
		stream := map[string]any{
			"network": "raw", "security": "reality",
			"realitySettings": map[string]any{
				"target": reality.Target, "serverNames": reality.ServerNames,
				"privateKey": reality.PrivateKey, "shortIds": reality.ShortIDs,
			},
		}
		if err := c.applyRealityCompatibility(release, stream); err != nil {
			var rejected *RejectedError
			if errors.As(err, &rejected) {
				return nil, &agentcore.ObjectError{Stream: protocol.StreamConfig, Key: string(link.Key), Code: rejected.Code, Err: rejected}
			}
			return nil, agentcore.LinkError(link.Key, err)
		}
		inbound["streamSettings"] = stream
	}
	return inbound, nil
}

// compileLinkOut is the entry's half of a link: an outbound that dials the
// exit. It carries the user's destination as given, domain names included, so
// the exit resolves and connects.
func compileLinkOut(link protocol.LinkOut) map[string]any {
	outbound := map[string]any{"tag": agentcore.LinkTag(link.Key)}
	switch link.Protocol {
	case protocol.LinkProtocolSS2022:
		outbound["protocol"] = "shadowsocks"
		outbound["settings"] = map[string]any{"servers": []any{map[string]any{
			"address": link.Address, "port": link.Port, "method": link.SS.Method, "password": link.SS.Password,
		}}}
	case protocol.LinkProtocolVLESSReality:
		reality := link.Reality
		outbound["protocol"] = "vless"
		outbound["settings"] = map[string]any{"vnext": []any{map[string]any{
			"address": link.Address, "port": link.Port,
			"users": []any{map[string]any{"id": reality.UUID, "encryption": "none", "flow": "xtls-rprx-vision"}},
		}}}
		outbound["streamSettings"] = map[string]any{
			"network": "raw", "security": "reality",
			"realitySettings": map[string]any{
				"serverName": reality.ServerName, "fingerprint": reality.Fingerprint,
				"publicKey": reality.PublicKey, "shortId": reality.ShortID,
			},
		}
	}
	return outbound
}

// applyEgress sends each bound listener's permitted traffic through its link.
//
// THE POLICY SAYS "PERMITTED" BY ROUTING TO direct (or to a report-only
// outbound, which is direct with a name). With egress, permitted means "leaves
// the way this listener leaves", so every such rule is split by where its
// listeners leave from: the local group keeps the rule as it was, restricted to
// its listeners; each link group gets a copy, restricted to that link's
// listeners, routed to the link. A connection comes from exactly one listener,
// so it meets exactly one copy, at the position the original rule held:
// evaluation order and verdicts are unchanged.
//
// Blocking rules need no split: a block is a block wherever the listener
// leaves from. Rules on transit inbounds are not the policy's and are left as
// they are.
//
// A report-only copy routes to "psp-watch-<rule>~lnk_<id>", a freedom outbound
// whose dialer is the link, so the audit receiver still reads the rule from the
// outbound tag and the connection still leaves through the link. Copies take
// the rule tag with the same suffix, because Xray refuses a repeated rule tag.
//
// After the policy each link group ends with a catch-all to its link: a
// connection no rule matched leaves the way its listener leaves, as an
// unmatched local connection leaves through direct.
func applyEgress(config *xrayConfig, served []protocol.ListenerKey, egress map[protocol.ListenerKey]protocol.LinkKey) {
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
	watchOutbounds := map[string]bool{}

	var rules []map[string]any
	if config.Routing != nil {
		rules, _ = config.Routing["rules"].([]map[string]any)
	}
	out := make([]map[string]any, 0, len(rules)+len(groups.Order))
	for _, rule := range rules {
		target, _ := rule["outboundTag"].(string)
		scope, restricted := rule["inboundTag"].([]string)
		if restricted && touchesTransit(scope) {
			out = append(out, rule)
			continue
		}
		watch := strings.HasPrefix(target, "psp-watch-")
		if target != "direct" && !watch {
			out = append(out, rule)
			continue
		}
		if !restricted {
			scope = allServed
		}
		if local := intersect(scope, localTags); len(local) > 0 {
			copy := cloneRule(rule)
			copy["inboundTag"] = local
			out = append(out, copy)
		}
		for _, link := range groups.Order {
			members := intersect(scope, linkTags[link])
			if len(members) == 0 {
				continue
			}
			suffix := agentcore.EgressSuffix(link)
			copy := cloneRule(rule)
			copy["inboundTag"] = members
			if tag, ok := rule["ruleTag"].(string); ok {
				copy["ruleTag"] = tag + suffix
			}
			if watch {
				name := target + suffix
				if !watchOutbounds[name] {
					watchOutbounds[name] = true
					config.Outbounds = append(config.Outbounds, map[string]any{
						"tag": name, "protocol": "freedom", "settings": map[string]any{},
						"streamSettings": map[string]any{"sockopt": map[string]any{"dialerProxy": agentcore.LinkTag(link)}},
					})
				}
				copy["outboundTag"] = name
			} else {
				copy["outboundTag"] = agentcore.LinkTag(link)
			}
			out = append(out, copy)
		}
	}
	for _, link := range groups.Order {
		out = append(out, map[string]any{
			"type": "field", "ruleTag": "transit-egress" + agentcore.EgressSuffix(link),
			"inboundTag": linkTags[link], "outboundTag": agentcore.LinkTag(link),
		})
	}
	if config.Routing == nil {
		config.Routing = map[string]any{"domainStrategy": "AsIs"}
	}
	config.Routing["rules"] = out
}

func touchesTransit(tags []string) bool {
	for _, tag := range tags {
		if strings.HasPrefix(tag, agentcore.TransitTagPrefix) {
			return true
		}
	}
	return false
}

// intersect keeps the order of scope.
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

func cloneRule(rule map[string]any) map[string]any {
	copy := make(map[string]any, len(rule))
	for key, value := range rule {
		copy[key] = value
	}
	return copy
}

// transitInboundTags are the tags routeTransit sends straight out: forwards and
// incoming links, in key order.
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

package routebridge

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
)

var ruleTypes = map[string]string{
	"DOMAIN": "Domain", "DOMAIN-SUFFIX": "DomainSuffix", "DOMAIN-KEYWORD": "DomainKeyword",
	"DOMAIN-REGEX": "DomainRegex", "DOMAIN-WILDCARD": "DomainWildcard",
	"IP-CIDR": "IPCIDR", "IP-CIDR6": "IPCIDR", "SRC-IP-CIDR": "SrcIPCIDR",
	"GEOIP": "GeoIP", "GEOSITE": "GeoSite", "PROCESS-NAME": "ProcessName", "PROCESS-PATH": "ProcessPath",
	"RULE-SET": "RuleSet", "NETWORK": "Network", "DST-PORT": "DstPort", "SRC-PORT": "SrcPort",
}

func splitRule(s string) ([]string, error) {
	depth, start := 0, 0
	var out []string
	for i, c := range s {
		switch c {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return nil, errors.New("unsupported_rule")
			}
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	if depth != 0 {
		return nil, errors.New("unsupported_rule")
	}
	out = append(out, s[start:])
	return out, nil
}
func predicate(kind, value string) (string, string, error) {
	t, ok := ruleTypes[kind]
	if !ok {
		return "", "", errors.New("unsupported_rule")
	}
	switch kind {
	case "GEOIP", "NETWORK", "DOMAIN", "DOMAIN-SUFFIX":
		value = strings.ToLower(value)
	case "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR":
		p, e := netip.ParsePrefix(value)
		if e != nil {
			return "", "", errors.New("unsupported_rule")
		}
		value = p.Masked().String()
	}
	return t, value, nil
}
func parseCoreRules(rules []string) ([]coreRule, error) {
	out := make([]coreRule, 0, len(rules))
	for _, r := range rules {
		p, e := splitRule(r)
		if e != nil {
			return nil, e
		}
		if len(p) > 0 && p[len(p)-1] == "no-resolve" {
			p = p[:len(p)-1]
		}
		if len(p) == 2 && p[0] == "MATCH" {
			out = append(out, coreRule{Type: "Match", Proxy: p[1]})
			continue
		}
		if len(p) != 3 {
			return nil, errors.New("unsupported_rule")
		}
		if p[0] == "AND" {
			if !strings.HasPrefix(p[1], "(") || !strings.HasSuffix(p[1], ")") {
				return nil, errors.New("unsupported_rule")
			}
			children, e := splitRule(p[1][1 : len(p[1])-1])
			if e != nil {
				return nil, e
			}
			var rendered []string
			for _, child := range children {
				if !strings.HasPrefix(child, "(") || !strings.HasSuffix(child, ")") {
					return nil, errors.New("unsupported_rule")
				}
				pair, e := splitRule(child[1 : len(child)-1])
				if e != nil || len(pair) != 2 {
					return nil, errors.New("unsupported_rule")
				}
				t, v, e := predicate(pair[0], pair[1])
				if e != nil {
					return nil, e
				}
				rendered = append(rendered, "("+t+","+v+")")
			}
			out = append(out, coreRule{Type: "AND", Payload: "(" + strings.Join(rendered, " && ") + ")", Proxy: p[2]})
			continue
		}
		t, v, e := predicate(p[0], p[1])
		if e != nil {
			return nil, e
		}
		out = append(out, coreRule{Type: t, Payload: v, Proxy: p[2]})
	}
	return out, nil
}
func fileMatchesCore(rules []string, actual []coreRule) bool {
	expected, e := parseCoreRules(rules)
	return e == nil && reflect.DeepEqual(expected, actual)
}

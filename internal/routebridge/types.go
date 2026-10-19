// Package routebridge implements bounded, local-only router operations. It does
// not run a service or expose an HTTP listener of its own. Requests arrive over
// an existing SSH connection; credentials never leave the router.
package routebridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"
)

const MaxInput = 2 << 20

type Request struct {
	Operation            string   `json:"operation"`
	ID                   string   `json:"id"`
	Domain               string   `json:"domain"`
	Port                 int      `json:"port"`
	Controls             []string `json:"controls,omitempty"`
	ExpectedSnapshot     string   `json:"expectedSnapshot,omitempty"`
	ExpectedRulesHash    string   `json:"expectedRulesHash,omitempty"`
	ExpectedNonRulesHash string   `json:"expectedNonRulesHash,omitempty"`
	DesiredRulesHash     string   `json:"desiredRulesHash,omitempty"`
	Rules                []string `json:"rules,omitempty"`
	Action               string   `json:"action,omitempty"`
}

type Snapshot struct {
	ID              string              `json:"id"`
	RawRulesHash    string              `json:"rawRulesHash"`
	RawRules        []string            `json:"rawRules"`
	RawNonRulesHash string              `json:"rawNonRulesHash"`
	RuntimeRules    []string            `json:"runtimeRules"`
	LocalRules      []string            `json:"localRules"`
	Nodes           map[string]string   `json:"nodes"`
	NodeHashes      map[string]string   `json:"nodeHashes"`
	InputsHash      map[string]string   `json:"inputsHash"`
	DeviceRules     map[string][]string `json:"deviceRules"`
}

type Sample struct {
	Route      string `json:"route"`
	NodeHash   string `json:"nodeHash"`
	Domain     string `json:"domain"`
	Control    bool   `json:"control"`
	Round      int    `json:"round"`
	DNSStatus  string `json:"dnsStatus"`
	Address    string `json:"address,omitempty"`
	Stage      string `json:"stage"`
	Status     string `json:"status"` // response, failed, unknown, unsafe
	HTTPStatus int    `json:"httpStatus,omitempty"`
	Millis     int64  `json:"millis"`
	Time       int64  `json:"time"`
}

type Response struct {
	OK          bool      `json:"ok"`
	Code        string    `json:"code,omitempty"`
	Snapshot    *Snapshot `json:"snapshot,omitempty"`
	Samples     []Sample  `json:"samples,omitempty"`
	Applied     bool      `json:"applied,omitempty"`
	ID          string    `json:"id,omitempty"`
	RuntimeHash string    `json:"runtimeHash,omitempty"`
	ConfigHash  string    `json:"configHash,omitempty"`
}

func Canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}
func Hash(v any) string {
	b, err := Canonical(v)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func ValidDomain(s string) bool {
	if len(s) > 253 || s != strings.ToLower(s) || !strings.Contains(s, ".") || net.ParseIP(s) != nil {
		return false
	}
	for _, p := range strings.Split(s, ".") {
		if len(p) == 0 || len(p) > 63 || p[0] == '-' || p[len(p)-1] == '-' {
			return false
		}
		for _, c := range p {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	for _, suffix := range []string{"local", "localhost", "lan", "home.arpa", "internal", "invalid", "test", "onion"} {
		if s == suffix || strings.HasSuffix(s, "."+suffix) {
			return false
		}
	}
	return true
}
func PublicIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "198.18.0.0/15", "192.0.0.0/24", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32"} {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(ip) {
			return false
		}
	}
	return true
}
func ValidID(s string) bool {
	if len(s) < 20 || len(s) > 80 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func Validate(r Request) error {
	if r.Operation == "inspect" {
		return nil
	}
	if !ValidID(r.ID) || !ValidDomain(r.Domain) {
		return errors.New("invalid_request")
	}
	if r.Operation == "probe" {
		if r.Port != 443 || len(r.Controls) != 2 || r.Controls[0] == r.Controls[1] {
			return errors.New("unsupported_probe")
		}
		for _, d := range r.Controls {
			if !ValidDomain(d) || d == r.Domain {
				return errors.New("invalid_controls")
			}
		}
		return nil
	}
	if r.Operation == "apply" || r.Operation == "prepare" {
		if len(r.Rules) == 0 || len(r.Rules) > 20000 || r.ExpectedRulesHash == "" || r.ExpectedNonRulesHash == "" || r.DesiredRulesHash != Hash(r.Rules) {
			return errors.New("invalid_rules")
		}
		if r.Action != "DIRECT" && r.Action != "PROXY" && r.Action != "REMOVE" {
			return errors.New("invalid_action")
		}
		return nil
	}
	return errors.New("unknown_operation")
}

func nowMillis(start time.Time) int64 { return time.Since(start).Milliseconds() }

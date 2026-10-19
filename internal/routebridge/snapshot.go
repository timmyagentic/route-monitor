package routebridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

type Bridge struct {
	Root    string
	Runtime string
	Core    string
}

func ReadYAML(path string, out any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxInput+1))
	if err != nil || len(b) > MaxInput {
		return errors.New("config_too_large")
	}
	return yaml.Unmarshal(b, out)
}

func fileFingerprint(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, 128<<20))
	if e != nil || n >= 128<<20 {
		return "", errors.New("source_too_large")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func stringRules(v any) ([]string, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, errors.New("invalid_rules")
	}
	r := make([]string, len(arr))
	for i, x := range arr {
		var yes bool
		r[i], yes = x.(string)
		if !yes {
			return nil, errors.New("invalid_rule")
		}
	}
	return r, nil
}
func nonRules(c map[string]any) map[string]any {
	r := make(map[string]any, len(c))
	for k, v := range c {
		if k != "rules" {
			r[k] = v
		}
	}
	return r
}

func api(ctx context.Context, cfg map[string]any, method, path string, body io.Reader, result any) error {
	address, _ := cfg["external-controller"].(string)
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !(ip.IsPrivate() || ip.IsLoopback()) {
		return errors.New("invalid_controller")
	}
	if _, err = strconv.Atoi(port); err != nil {
		return errors.New("invalid_controller")
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+address+path, body)
	if err != nil {
		return err
	}
	secret, _ := cfg["secret"].(string)
	if secret == "" {
		return errors.New("missing_controller_secret")
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	r, err := client.Do(req)
	if err != nil {
		return errors.New("controller_unavailable")
	}
	defer r.Body.Close()
	if r.StatusCode < 200 || r.StatusCode >= 300 {
		return errors.New("controller_rejected")
	}
	if result != nil {
		if err = json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(result); err != nil {
			return errors.New("controller_invalid_json")
		}
	}
	return nil
}

func (b Bridge) load(ctx context.Context) (map[string]any, map[string]any, *Snapshot, error) {
	var runtime, raw map[string]any
	if ReadYAML(b.Runtime, &runtime) != nil || ReadYAML(filepath.Join(b.Root, "yamls/config.raw.yaml"), &raw) != nil {
		return nil, nil, nil, errors.New("config_unreadable")
	}
	rawRules, err := stringRules(raw["rules"])
	if err != nil {
		return nil, nil, nil, err
	}
	runtimeRules, err := stringRules(runtime["rules"])
	if err != nil {
		return nil, nil, nil, err
	}
	var local []string
	if ReadYAML(filepath.Join(b.Root, "yamls/rules.yaml"), &local) != nil {
		return nil, nil, nil, errors.New("local_rules_unreadable")
	}
	var proxies struct {
		Proxies map[string]struct{ Type, Now string }
	}
	if err = api(ctx, runtime, http.MethodGet, "/proxies", nil, &proxies); err != nil {
		return nil, nil, nil, err
	}
	s := &Snapshot{RawRulesHash: Hash(rawRules), RawRules: rawRules, RawNonRulesHash: Hash(nonRules(raw)), RuntimeRules: runtimeRules, LocalRules: local, Nodes: map[string]string{"DIRECT": "DIRECT"}, NodeHashes: map[string]string{"DIRECT": "DIRECT"}, DeviceRules: map[string][]string{}}
	configs := map[string]any{}
	items, _ := runtime["proxies"].([]any)
	for _, item := range items {
		if v, ok := item.(map[string]any); ok {
			name, _ := v["name"].(string)
			configs[name] = v
		}
	}
	for _, route := range []string{"JP", "HK"} {
		v, ok := proxies.Proxies[route]
		if !ok || v.Type != "Selector" || v.Now == "" {
			return nil, nil, nil, errors.New("unsupported_selector")
		}
		leaf, ok := proxies.Proxies[v.Now]
		if !ok || leaf.Now != "" || configs[v.Now] == nil || leaf.Type == "Direct" || leaf.Type == "Reject" {
			return nil, nil, nil, errors.New("unsupported_node")
		}
		cfg := configs[v.Now].(map[string]any)
		if cfg["dialer-proxy"] != nil {
			return nil, nil, nil, errors.New("nested_proxy_unsupported")
		}
		s.Nodes[route] = v.Now
		s.NodeHashes[route] = Hash(cfg)
	}
	if sub, ok := runtime["sub-rules"].(map[string]any); ok {
		for k, v := range sub {
			r, e := stringRules(v)
			if e != nil {
				return nil, nil, nil, e
			}
			s.DeviceRules[k] = r
		}
	}
	actual, settingsHash, e := getCoreState(ctx, runtime)
	if e != nil || !fileMatchesCore(runtimeRules, actual) {
		return nil, nil, nil, errors.New("runtime_file_mismatch")
	}
	var version struct {
		Version string `json:"version"`
	}
	if api(ctx, runtime, http.MethodGet, "/version", nil, &version) != nil || version.Version == "" {
		return nil, nil, nil, errors.New("core_version_unavailable")
	}
	binaryVersion, e := exec.CommandContext(ctx, b.Core, "-v").Output()
	if e != nil || !strings.Contains(string(binaryVersion), " "+version.Version+" ") {
		return nil, nil, nil, errors.New("core_version_mismatch")
	}
	files := map[string]string{}
	for name, path := range map[string]string{"core": b.Core, "device": filepath.Join(b.Root, "tools/device-selectors.sh"), "generator": filepath.Join(b.Root, "starts/clash_modify.sh"), "settings": filepath.Join(b.Root, "configs/ShellCrash.cfg"), "environment": filepath.Join(b.Root, "configs/command.env")} {
		h, e := fileFingerprint(path)
		if e != nil {
			return nil, nil, nil, errors.New("source_fingerprint_failed")
		}
		files[name] = h
	}
	for _, name := range []string{"user.yaml", "rules.yaml", "proxy-groups.yaml"} {
		h, e := fileFingerprint(filepath.Join(b.Root, "yamls", name))
		if e != nil && !os.IsNotExist(e) {
			return nil, nil, nil, errors.New("source_fingerprint_failed")
		}
		files[name] = h
	}
	s.InputsHash = files
	metadataHash, e := fileFingerprint(filepath.Join(b.Root, "yamls/config.raw.meta"))
	if e != nil && !os.IsNotExist(e) {
		return nil, nil, nil, errors.New("source_fingerprint_failed")
	}
	s.ID = Hash(map[string]any{"runtime": runtime, "raw": raw, "local": local, "nodes": s.NodeHashes, "coreRules": actual, "coreSettings": settingsHash, "coreVersion": version.Version, "files": files, "metadata": metadataHash})
	return runtime, raw, s, nil
}

func (b Bridge) Inspect(ctx context.Context) (*Snapshot, error) {
	_, _, s, e := b.load(ctx)
	return s, e
}

// AutomaticRuleActive requires the owned exact rule to remain present and
// unobstructed by local human rules. load has already checked file/core parity.
func AutomaticRuleActive(s Snapshot, domain, action string) bool {
	if protectedByLocal(s.LocalRules, domain) {
		return false
	}
	target := "Proxies"
	if action == "DIRECT" {
		target = "DIRECT"
	} else if action != "PROXY" {
		return false
	}
	for _, r := range s.RawRules {
		if r == "DOMAIN,"+domain+","+target {
			return true
		}
	}
	return false
}

func protectedByLocal(rules []string, domain string) bool {
	for _, line := range rules {
		p := strings.Split(line, ",")
		if len(p) < 2 {
			return true
		}
		kind, value := p[0], strings.ToLower(p[1])
		if kind == "DOMAIN" && value == domain || kind == "DOMAIN-SUFFIX" && (value == domain || strings.HasSuffix(domain, "."+value)) || kind == "DOMAIN-KEYWORD" && strings.Contains(domain, value) {
			return true
		}
		if kind == "DOMAIN-REGEX" || kind == "DOMAIN-WILDCARD" || kind == "RULE-SET" || kind == "GEOSITE" || kind == "MATCH" {
			return true
		}
		if (kind == "AND" || kind == "OR" || kind == "NOT") && (strings.Contains(line, "DOMAIN") || strings.Contains(line, "RULE-SET") || strings.Contains(line, "GEOSITE")) {
			// A positive AND that requires another exact domain cannot match
			// this one. Every broader/negative predicate remains protected.
			if kind == "AND" && andRequiresOtherDomain(line, domain) {
				continue
			}
			return true
		}
	}
	return false
}

func andRequiresOtherDomain(line, domain string) bool {
	parts, err := splitRule(line)
	if err != nil || len(parts) != 3 || len(parts[1]) < 2 {
		return false
	}
	children, err := splitRule(parts[1][1 : len(parts[1])-1])
	if err != nil {
		return false
	}
	for _, child := range children {
		if strings.HasPrefix(child, "(DOMAIN,") && strings.HasSuffix(child, ")") {
			value := strings.ToLower(child[len("(DOMAIN,") : len(child)-1])
			if ValidDomain(value) && value != domain {
				return true
			}
		}
	}
	return false
}

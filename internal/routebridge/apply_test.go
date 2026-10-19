package routebridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

type routerFixture struct {
	bridge       Bridge
	mu           sync.Mutex
	cfg          map[string]any
	actual       []coreRule
	puts         int
	failFirst    bool
	foreignWrite bool
	captured     *applyJournal
	backups      map[string][]byte
}

func (f *routerFixture) putFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, data, 0700); e != nil {
		t.Fatal(e)
	}
}
func (f *routerFixture) yamlFile(t *testing.T, path string, v any) {
	t.Helper()
	b, e := yaml.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	f.putFile(t, path, b)
}
func fixtureRouter(t *testing.T) *routerFixture {
	t.Helper()
	root := t.TempDir()
	f := &routerFixture{bridge: Bridge{Root: root, Runtime: filepath.Join(root, "run/config.yaml"), Core: filepath.Join(root, "core")}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer fixture-secret" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/version":
			json.NewEncoder(w).Encode(map[string]string{"version": "v1.19.32"})
		case "/proxies":
			json.NewEncoder(w).Encode(map[string]any{"proxies": map[string]any{"JP": map[string]string{"type": "Selector", "now": "jp"}, "HK": map[string]string{"type": "Selector", "now": "hk"}, "jp": map[string]string{"type": "Trojan"}, "hk": map[string]string{"type": "Trojan"}}})
		case "/rules":
			json.NewEncoder(w).Encode(map[string]any{"rules": f.actual})
		case "/configs":
			if r.Method == http.MethodGet {
				json.NewEncoder(w).Encode(map[string]any{"mode": "rule", "ipv6": false})
				return
			}
			f.puts++
			var body struct {
				Path string `json:"path"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			var loaded map[string]any
			if ReadYAML(body.Path, &loaded) != nil {
				w.WriteHeader(422)
				return
			}
			rules, _ := stringRules(loaded["rules"])
			f.actual, _ = parseCoreRules(rules)
			if strings.HasSuffix(body.Path, "generated.yaml") {
				var j applyJournal
				if readJSON(filepath.Join(root, ".route-monitor/active.json"), &j) == nil {
					f.captured = &j
					f.backups = map[string][]byte{}
					f.backups[j.Previous], _ = os.ReadFile(j.Previous)
					for _, v := range j.Files {
						f.backups[v.Backup], _ = os.ReadFile(v.Backup)
						f.backups[v.New], _ = os.ReadFile(v.New)
					}
				}
				if f.foreignWrite {
					os.WriteFile(filepath.Join(root, "yamls/config.raw.yaml"), []byte("foreign manual edit\n"), 0600)
				}
				if f.failFirst {
					f.failFirst = false
					w.WriteHeader(500)
					return
				}
			}
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	f.cfg = map[string]any{"mode": "rule", "ipv6": false, "secret": "fixture-secret", "external-controller": strings.TrimPrefix(srv.URL, "http://"), "rules": []any{"MATCH,DIRECT"}, "proxies": []any{map[string]any{"name": "jp", "type": "trojan", "server": "jp.example.com", "port": 443, "password": "fixture"}, map[string]any{"name": "hk", "type": "trojan", "server": "hk.example.com", "port": 443, "password": "fixture"}}}
	f.actual, _ = parseCoreRules([]string{"MATCH,DIRECT"})
	f.yamlFile(t, f.bridge.Runtime, f.cfg)
	f.yamlFile(t, filepath.Join(root, "yamls/config.raw.yaml"), f.cfg)
	f.yamlFile(t, filepath.Join(root, "yamls/config.yaml"), f.cfg)
	f.yamlFile(t, filepath.Join(root, "yamls/others.yaml"), map[string]any{"sub-rules": map[string]any{"device": []string{"MATCH,HK"}}})
	f.yamlFile(t, filepath.Join(root, "yamls/rules.yaml"), []string{})
	for _, p := range []string{"configs/ShellCrash.cfg", "configs/command.env", "libs/logger.sh", "libs/check_cmd.sh", "libs/compare.sh"} {
		f.putFile(t, filepath.Join(root, p), []byte("# fixture\n"))
	}
	// Sourced ShellCrash files can validly end with a false guard; nounset and
	// errexit around them used to prevent candidate generation before validation.
	f.putFile(t, filepath.Join(root, "libs/get_config.sh"), []byte("present=1\n[ -z \"$present\" ] && present=2\n"))
	f.putFile(t, filepath.Join(root, "tools/device-selectors.sh"), []byte("#!/bin/sh\ncp \"$SC_CONFIG_INPUT\" \"$CRASHDIR/yamls/config.yaml\"\n"))
	f.putFile(t, filepath.Join(root, "starts/clash_modify.sh"), []byte("modify_yaml() { cp \"$ROOT/candidate.yaml\" \"$SC_CONFIG_OUTPUT\"; }\n"))
	f.putFile(t, f.bridge.Core, []byte("#!/bin/sh\nif [ \"${1:-}\" = -v ]; then printf 'Mihomo Meta v1.19.32 linux arm64\\n'; fi\nexit 0\n"))
	f.putFile(t, filepath.Join(root, "yamls/config.raw.meta"), []byte("source=fixture\nsha256=old\n"))
	return f
}
func (f *routerFixture) request(t *testing.T) Request {
	t.Helper()
	candidate := map[string]any{}
	for k, v := range f.cfg {
		candidate[k] = v
	}
	candidate["rules"] = []string{"DOMAIN,new.example,Router-Device-Egress", "MATCH,DIRECT"}
	f.yamlFile(t, filepath.Join(f.bridge.Root, "candidate.yaml"), candidate)
	s, e := f.bridge.Inspect(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	rules := []string{"DOMAIN,new.example,Proxies", "MATCH,DIRECT"}
	return Request{Operation: "apply", ID: "fixture-rule-change-request", Domain: "new.example", Action: "PROXY", ExpectedSnapshot: s.ID, ExpectedRulesHash: s.RawRulesHash, ExpectedNonRulesHash: s.RawNonRulesHash, DesiredRulesHash: Hash(rules), Rules: rules}
}
func (f *routerFixture) files(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, p := range []string{f.bridge.Runtime, filepath.Join(f.bridge.Root, "yamls/config.raw.yaml"), filepath.Join(f.bridge.Root, "yamls/config.yaml"), filepath.Join(f.bridge.Root, "yamls/others.yaml"), filepath.Join(f.bridge.Root, "yamls/config.raw.meta"), filepath.Join(f.bridge.Root, "yamls/config.last-good.yaml")} {
		b, e := os.ReadFile(p)
		if e != nil && !os.IsNotExist(e) {
			t.Fatal(e)
		}
		out[p] = Hash(b)
	}
	return out
}

func TestPrepareAndApplyTransactionWithIdempotentReadback(t *testing.T) {
	f := fixtureRouter(t)
	r := f.request(t)
	before := f.files(t)
	r.Operation = "prepare"
	out, e := f.bridge.Apply(context.Background(), r)
	if e != nil || out.Applied || !out.OK {
		t.Fatal(out, e)
	}
	if !reflect.DeepEqual(before, f.files(t)) || f.puts != 0 {
		t.Fatal("preparation changed production state")
	}
	r.Operation = "apply"
	out, e = f.bridge.Apply(context.Background(), r)
	if e != nil || !out.Applied {
		t.Fatal(out, e)
	}
	after := f.files(t)
	out, e = f.bridge.Apply(context.Background(), r)
	if e != nil || !out.Applied || f.puts != 1 || !reflect.DeepEqual(after, f.files(t)) {
		t.Fatal("duplicate apply", out, e, f.puts)
	}
	raw, _ := os.ReadFile(filepath.Join(f.bridge.Root, "yamls/config.raw.yaml"))
	h := sha256.Sum256(raw)
	meta, _ := os.ReadFile(filepath.Join(f.bridge.Root, "yamls/config.raw.meta"))
	if !strings.Contains(string(meta), "sha256="+hex.EncodeToString(h[:])) {
		t.Fatal("stale source checksum")
	}
}
func TestFailedReloadRestoresFilesAndRuntime(t *testing.T) {
	f := fixtureRouter(t)
	r := f.request(t)
	before := f.files(t)
	f.failFirst = true
	_, e := f.bridge.Apply(context.Background(), r)
	if e == nil || e.Error() != "apply_failed_rolled_back" {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before, f.files(t)) || f.puts != 2 || !fileMatchesCore([]string{"MATCH,DIRECT"}, f.actual) {
		t.Fatal("rollback incomplete", f.puts)
	}
}
func TestConcurrentForeignEditIsNeverOverwritten(t *testing.T) {
	f := fixtureRouter(t)
	r := f.request(t)
	f.foreignWrite = true
	_, e := f.bridge.Apply(context.Background(), r)
	if e == nil || e.Error() != "recovery_conflict" {
		t.Fatal(e)
	}
	data, _ := os.ReadFile(filepath.Join(f.bridge.Root, "yamls/config.raw.yaml"))
	if string(data) != "foreign manual edit\n" {
		t.Fatal("foreign edit overwritten")
	}
}
func TestInterruptedApplyRecoversBeforeRequiringFileRuntimeAgreement(t *testing.T) {
	f := fixtureRouter(t)
	r := f.request(t)
	before := f.files(t)
	if _, e := f.bridge.Apply(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	j := *f.captured
	// Reconstruct a power loss after the core switched but before files committed.
	for path, data := range f.backups {
		f.putFile(t, path, data)
	}
	for _, file := range j.Files {
		if file.Existed {
			f.putFile(t, file.Path, f.backups[file.Backup])
		} else {
			os.Remove(file.Path)
		}
	}
	os.Remove(filepath.Join(f.bridge.Root, ".route-monitor/receipts", r.ID+".json"))
	writeJSON(filepath.Join(f.bridge.Root, ".route-monitor/active.json"), j)
	_, e := f.bridge.Apply(context.Background(), r)
	if e == nil || e.Error() != "interrupted_apply_rolled_back" {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before, f.files(t)) || !fileMatchesCore([]string{"MATCH,DIRECT"}, f.actual) {
		t.Fatal("restart recovery incomplete")
	}
}
func TestDNSOverridesAreNotSentToPublicProbeResolvers(t *testing.T) {
	c := map[string]any{"hosts": map[string]any{"internal.example": "10.0.0.1"}, "dns": map[string]any{"nameserver-policy": map[string]any{"*": "127.0.0.1", "+.lan": "127.0.0.1", "miwifi.com": "127.0.0.1"}}}
	for _, d := range []string{"internal.example", "miwifi.com", "device.lan"} {
		if !explicitDNSPolicy(c, d) {
			t.Fatal(d)
		}
	}
	if explicitDNSPolicy(c, "public.example") {
		t.Fatal("single-label wildcard matched a public domain")
	}
}

// Opt-in integration check. The core runs with no traffic listeners, no TUN,
// no providers and only synthetic node credentials, under t.TempDir().
func TestRealCoreReloadAndRollback(t *testing.T) {
	core := os.Getenv("ROUTE_MONITOR_TEST_CORE")
	if core == "" {
		t.Skip("set ROUTE_MONITOR_TEST_CORE for isolated Mihomo integration")
	}
	f := fixtureRouter(t)
	if e := os.Remove(f.bridge.Core); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(core, f.bridge.Core); e != nil {
		t.Fatal(e)
	}
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := l.Addr().String()
	l.Close()
	f.cfg["external-controller"] = address
	f.cfg["log-level"] = "silent"
	f.cfg["allow-lan"] = false
	f.cfg["mixed-port"] = 0
	f.cfg["tun"] = map[string]any{"enable": false}
	f.cfg["dns"] = map[string]any{"enable": false}
	f.cfg["profile"] = map[string]any{"store-selected": false, "store-fake-ip": false}
	f.cfg["proxy-groups"] = []any{map[string]any{"name": "JP", "type": "select", "proxies": []string{"jp"}}, map[string]any{"name": "HK", "type": "select", "proxies": []string{"hk"}}}
	f.cfg["proxies"] = append(f.cfg["proxies"].([]any), map[string]any{"name": "Router-Device-Egress", "type": "rematch", "target-sub-rule": "device"})
	f.cfg["sub-rules"] = map[string]any{"device": []string{"MATCH,HK"}}
	for _, p := range []string{f.bridge.Runtime, filepath.Join(f.bridge.Root, "yamls/config.raw.yaml"), filepath.Join(f.bridge.Root, "yamls/config.yaml")} {
		f.yamlFile(t, p, f.cfg)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, f.bridge.Core, "-d", f.bridge.Root, "-f", f.bridge.Runtime)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	hardenChild(cmd)
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cancel(); cmd.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, e = f.bridge.Inspect(ctx); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("core startup", e)
		}
		time.Sleep(25 * time.Millisecond)
	}
	r := f.request(t)
	out, e := f.bridge.Apply(ctx, r)
	if e != nil || !out.Applied {
		t.Fatal("apply", out, e)
	}
	s, e := f.bridge.Inspect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	f.yamlFile(t, filepath.Join(f.bridge.Root, "candidate.yaml"), f.cfg)
	rollback := Request{Operation: "apply", ID: "fixture-real-core-rollback", Domain: r.Domain, Action: "REMOVE", ExpectedSnapshot: s.ID, ExpectedRulesHash: s.RawRulesHash, ExpectedNonRulesHash: s.RawNonRulesHash, DesiredRulesHash: Hash([]string{"MATCH,DIRECT"}), Rules: []string{"MATCH,DIRECT"}}
	out, e = f.bridge.Apply(ctx, rollback)
	if e != nil || !out.Applied {
		t.Fatal("rollback", out, e)
	}
	if !reflect.DeepEqual(out.Snapshot.RuntimeRules, []string{"MATCH,DIRECT"}) {
		t.Fatal("rollback rules", out.Snapshot.RuntimeRules)
	}
}

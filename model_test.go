package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSnapshotDedupAndNoLatencyGuess(t *testing.T) {
	s, e := openStore(filepath.Join(t.TempDir(), "test.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.db.Close()
	data := []byte(`{"connections":[{"id":"one","metadata":{"host":"EXAMPLE.COM","sourceIP":"192.168.1.2"},"chains":["DIRECT"],"rule":"Match","rulePayload":""}]}`)
	events, e := snapshot(data, time.Now().Unix())
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 3; i++ {
		if e = s.put(events); e != nil {
			t.Fatal(e)
		}
	}
	rows, _, e := s.summary()
	if e != nil || len(rows) != 1 || rows[0].Connections != 1 || rows[0].Priority != 0 {
		t.Fatalf("bad summary: %+v %v", rows, e)
	}
}
func TestLogParsingAndSanitization(t *testing.T) {
	raw := `{"type":"warning","payload":"[TCP] dial DIRECT (match Match/) 192.168.31.95:1234 --> service.example.com:443 error: dial tcp 1.2.3.4:443: i/o timeout SECRET_IN_RAW"}`
	e, ok := parseLog([]byte(raw), "id", time.Now().Unix())
	if !ok || e.Domain != "service.example.com" || e.Route != "DIRECT" || e.Error != "连接超时" {
		t.Fatalf("%+v %v", e, ok)
	}
	b, _ := json.Marshal(e)
	if strings.Contains(string(b), "SECRET") {
		t.Fatal("raw log leaked")
	}
	_, ok = parseLog([]byte(`{"type":"warning","payload":"unrecognized"}`), "id", 1)
	if ok {
		t.Fatal("unknown log misclassified")
	}
	e, ok = parseLog([]byte(`{"type":"warning","payload":"[UDP] dial JP (match DomainSuffix/example.com) [fd00::1]:1234 --> [2001:db8::1]:443 error: timeout"}`), "id", 1)
	if !ok || e.Domain != "" || e.Source != "fd00::1" {
		t.Fatal(e)
	}
}
func TestAdviceRequiresCompleteSameBatchEvidence(t *testing.T) {
	makeP := func(status string) []Probe {
		p := []Probe{}
		for i := 0; i < 3; i++ {
			p = append(p, Probe{Batch: "a", Route: "DIRECT", Status: status, Time: 1}, Probe{Batch: "a", Route: "JP", Node: "jp1", Status: "reachable", Time: 1, Delay: 100})
		}
		return p
	}
	if _, p := advice(3, nil); p == 3 {
		t.Fatal("passive error treated as proof")
	}
	p := makeP("failed")
	if _, v := advice(0, p); v != 3 {
		t.Fatal("consistent test not recognized")
	}
	p[0].Status = "unknown"
	if _, v := advice(0, p); v == 3 {
		t.Fatal("API outage treated as direct failure")
	}
	p = makeP("failed")
	p[1].Batch = "b"
	if _, v := advice(0, p); v == 3 {
		t.Fatal("cross-batch comparison")
	}
	p = makeP("failed")
	p[1].Node = "jp2"
	if _, v := advice(0, p); v == 3 {
		t.Fatal("mixed nodes")
	}
	if _, v := advice(0, makeP("reachable")); v != 0 {
		t.Fatal("reachable should not suggest rule change")
	}
}
func TestTargetsRejectPrivateAndMalformed(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254", "198.18.0.1", "100.64.0.1", "::1", "fd00::1", "224.0.0.1"} {
		if publicIP(net.ParseIP(ip)) {
			t.Error(ip)
		}
	}
	for _, host := range []string{"x.com/path", "user@x.com", "1.2.3.4", "bad\nx.com", "-x.com", "x..com"} {
		if domainName(host) != "" {
			t.Error(host)
		}
	}
	if !publicIP(net.ParseIP("1.1.1.1")) {
		t.Fatal("public address rejected")
	}
}
func newTestApp(t *testing.T) *App {
	t.Helper()
	s, e := openStore(filepath.Join(t.TempDir(), "test.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.db.Close() })
	return &App{store: s, ctx: context.Background(), cfg: Config{Listen: "127.0.0.1:9780", Salt: "test", PasswordHash: hashPassword("test-password", "test")}, states: map[string]Health{}, lastFrame: map[string]int64{}, sessions: map[string]time.Time{}, attempts: map[string][]time.Time{}, subscribers: map[chan struct{}]bool{}}
}
func TestHTTPAuthAndOrigin(t *testing.T) {
	a := newTestApp(t)
	h := a.handler()
	request := func(method, path, host, origin, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://"+host+path, strings.NewReader(body))
		r.Header.Set("Origin", origin)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "/api/state", "localhost:9780", "", "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request("POST", "/api/login", "localhost:9780", "http://evil.com", `{"password":"test-password"}`, nil); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := request("GET", "/", "evil.com:9780", "", "", nil); w.Code != 403 {
		t.Fatal(w.Code)
	}
	w := request("POST", "/api/login", "localhost:9780", "http://localhost:9780", `{"password":"test-password"}`, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly {
		t.Fatal("cookie missing")
	}
	if w = request("GET", "/api/state", "localhost:9780", "", "", cookies[0]); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if strings.Contains(w.Body.String(), "password") || strings.Contains(w.Body.String(), "secret") {
		t.Fatal("config leaked")
	}
	if w = request("POST", "/api/probe", "localhost:9780", "http://evil.com", `{"domain":"example.com"}`, cookies[0]); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w = request("POST", "/api/rules", "localhost:9780", "http://localhost:9780", `{}`, cookies[0]); w.Code < 400 {
		t.Fatal("unexpected mutation endpoint")
	}
}
func TestRouterRequestsNeverChangeSelection(t *testing.T) {
	var mu sync.Mutex
	requests := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.Method != "GET" {
			t.Error("mutation")
		}
		if r.Header.Get("Authorization") != "Bearer unit-secret" {
			t.Error("missing auth")
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/proxies" {
			fmt.Fprint(w, `{"proxies":{"DIRECT":{"type":"Direct"},"JP":{"type":"Selector","now":"jp1"},"HK":{"type":"Selector","now":"hk1"},"jp1":{"type":"Shadowsocks"},"hk1":{"type":"Shadowsocks"}}}`)
		} else {
			fmt.Fprint(w, `{"delay":100}`)
		}
	}))
	defer srv.Close()
	a := newTestApp(t)
	a.router = newRouter(srv.URL, "unit-secret")
	nodes, e := a.nodes(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	a.runProbe(context.Background(), "example.com", nodes)
	ps, e := a.store.probes("example.com")
	if e != nil || len(ps) != 9 {
		t.Fatal(len(ps), e)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, p := range requests {
		if !strings.HasPrefix(p, "GET /proxies") {
			t.Error(p)
		}
	}
}

func TestAlreadyProxiedDomainDoesNotSuggestAddingProxyRule(t *testing.T) {
	a := newTestApp(t)
	now := time.Now().Unix()
	a.store.put([]Event{{ID: "proxy-conn", Domain: "example.com", Source: "192.168.1.2", Route: "JP", Rule: "DomainSuffix/example.com", Kind: "connection", Time: now}})
	for i := 0; i < 3; i++ {
		for _, r := range []string{"DIRECT", "JP"} {
			status := "reachable"
			if r == "DIRECT" {
				status = "failed"
			}
			_, e := a.store.db.Exec(`INSERT INTO probes VALUES(?,?,?,?,?,?,?)`, now, "same", "example.com", r, r, status, 100)
			if e != nil {
				t.Fatal(e)
			}
		}
	}
	rows, _, e := a.store.summary()
	if e != nil || len(rows) != 1 || rows[0].Priority != 0 || !strings.Contains(rows[0].Advice, "当前已走代理") {
		t.Fatal(rows, e)
	}
}

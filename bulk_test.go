package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func addBatch(t *testing.T, s *Store, domain, batch string, n int, metadata bool) {
	t.Helper()
	now := time.Now().Unix()
	if metadata {
		_, e := s.db.Exec(`INSERT INTO probe_batches VALUES(?,?,?,'completed',?,?)`, batch, domain, n, now, now)
		if e != nil {
			t.Fatal(e)
		}
	}
	for _, r := range []string{"DIRECT", "JP", "HK"} {
		for i := 0; i < n; i++ {
			_, e := s.db.Exec(`INSERT INTO probes VALUES(?,?,?,?,?,?,?)`, now, batch, domain, r, r, "reachable", 10)
			if e != nil {
				t.Fatal(e)
			}
		}
	}
}
func TestTwoSampleEvidenceAndLegacyIncomplete(t *testing.T) {
	for _, n := range []int{2, 3} {
		ps := []Probe{}
		for _, r := range []string{"DIRECT", "JP", "HK"} {
			for i := 0; i < n; i++ {
				st := "reachable"
				if r == "DIRECT" {
					st = "failed"
				}
				ps = append(ps, Probe{Batch: "b", Route: r, Node: r, Status: st, Samples: n, BatchState: "completed", Time: 1})
			}
		}
		p := proxyEvidence(ps)
		if p == nil || p.Samples != n {
			t.Fatal(p)
		}
		ps[0].BatchState = "running"
		if proxyEvidence(ps) != nil {
			t.Fatal("running batch marked")
		}
		ps[0].BatchState = "completed"
		ps = ps[:len(ps)-1]
		if proxyEvidence(ps) != nil {
			t.Fatal("incomplete batch marked")
		}
	}
	ps := []Probe{}
	for _, r := range []string{"DIRECT", "JP", "HK"} {
		for i := 0; i < 2; i++ {
			ps = append(ps, Probe{Batch: "legacy", Route: r, Node: r, Status: "failed", Time: 1})
		}
	}
	if proxyEvidence(ps) != nil {
		t.Fatal("partial legacy incorrectly treated as two")
	}
}
func TestBulkIncludesBeyondPageAndExcludesCompletedOrHandled(t *testing.T) {
	a := newTestApp(t)
	now := time.Now().Unix()
	for i := 0; i < 305; i++ {
		a.store.put([]Event{{ID: fmt.Sprint(i), Domain: fmt.Sprintf("d%d.example.com", i), Kind: "error", Time: now}})
	}
	a.store.setHandled("d0.example.com", 1, true, "handled")
	addBatch(t, a.store, "d1.example.com", "old-full", 3, false)
	addBatch(t, a.store, "d2.example.com", "new-full", 2, true)
	addBatch(t, a.store, "d3.example.com", "old-partial", 2, false)
	id, e := a.store.createBulk()
	if e != nil {
		t.Fatal(e)
	}
	status := a.store.bulkStatus()
	if status.Total != 302 {
		t.Fatal(status)
	}
	var n int
	a.store.db.QueryRow(`SELECT COUNT(*) FROM bulk_items WHERE job=? AND domain='d3.example.com'`, id).Scan(&n)
	if n != 1 {
		t.Fatal("partial omitted")
	}
	if _, e = a.store.createBulk(); e == nil {
		t.Fatal("duplicate bulk allowed")
	}
}
func TestBulkCompletesSerialDomainsAndSkipsUnsafe(t *testing.T) {
	a := newTestApp(t)
	now := time.Now().Unix()
	for _, d := range []string{"ok.example.com", "missing.example.com", "private.local"} {
		a.store.put([]Event{{ID: d, Domain: d, Route: "DIRECT", Kind: "error", Time: now}})
	}
	var mu sync.Mutex
	calls := map[string]int{}
	active, maxActive := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("mutation")
		}
		switch r.URL.Path {
		case "/dns/query":
			if r.URL.Query().Get("name") == "missing.example.com" {
				fmt.Fprint(w, `{"Status":3}`)
			} else {
				fmt.Fprint(w, `{"Answer":[{"type":1,"data":"1.1.1.1"}]}`)
			}
		case "/proxies":
			fmt.Fprint(w, `{"proxies":{"JP":{"type":"Selector","now":"jp"},"HK":{"type":"Selector","now":"hk"},"jp":{"type":"Shadowsocks"},"hk":{"type":"Shadowsocks"}}}`)
		default:
			mu.Lock()
			calls[r.URL.Path]++
			active++
			if active > maxActive {
				maxActive = active
			}
			mu.Unlock()
			time.Sleep(10 * time.Millisecond)
			mu.Lock()
			active--
			mu.Unlock()
			fmt.Fprint(w, `{"delay":50}`)
		}
	}))
	defer srv.Close()
	a.router = newRouter(srv.URL, "test")
	a.lookupIP = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
	}
	for _, k := range []string{"connections", "logs", "storage"} {
		a.states[k] = Health{Connected: true}
	}
	a.lastFrame["connections"] = now
	a.bulkRunning = true
	id, e := a.store.createBulk()
	if e != nil {
		t.Fatal(e)
	}
	a.runBulk(context.Background(), id)
	s := a.store.bulkStatus()
	if s.State != "completed" || s.Total != 3 || s.Completed != 1 || s.Skipped != 2 || s.Done != 3 {
		t.Fatal(s)
	}
	for _, r := range []string{"DIRECT", "jp", "hk"} {
		if calls["/proxies/"+r+"/delay"] != 2 {
			t.Fatal(calls)
		}
	}
	if maxActive > 3 {
		t.Fatal(maxActive)
	}
	ps, e := a.store.probes("ok.example.com")
	if e != nil || len(ps) != 6 || ps[0].Samples != 2 || ps[0].BatchState != "completed" {
		t.Fatal(ps, e)
	}
	var auto int
	a.store.db.QueryRow(`SELECT COUNT(*) FROM auto_probes`).Scan(&auto)
	if auto != 0 {
		t.Fatal("manual bulk spent auto quota")
	}
}
func TestBulkCrashRecoveryAndEligibilityRecheck(t *testing.T) {
	a := newTestApp(t)
	now := time.Now().Unix()
	a.store.put([]Event{{ID: "a", Domain: "a.example.com", Kind: "error", Time: now}})
	id, e := a.store.createBulk()
	if e != nil {
		t.Fatal(e)
	}
	a.store.db.Exec(`UPDATE bulk_items SET state='running' WHERE job=?`, id)
	a.store.db.Exec(`INSERT INTO probe_batches VALUES('interrupted','a.example.com',2,'running',?,0)`, now)
	if e = a.store.recoverBulk(); e != nil {
		t.Fatal(e)
	}
	var state string
	a.store.db.QueryRow(`SELECT state FROM bulk_items WHERE job=?`, id).Scan(&state)
	if state != "pending" {
		t.Fatal(state)
	}
	a.store.db.QueryRow(`SELECT state FROM probe_batches WHERE batch='interrupted'`).Scan(&state)
	if state != "interrupted" {
		t.Fatal(state)
	}
	a.store.setHandled("a.example.com", 1, true, "handled during queue")
	ok, e := a.bulkEligible("a.example.com")
	if e != nil || ok {
		t.Fatal(ok, e)
	}
}
func TestBulkAPIProtectedAndManualBlocked(t *testing.T) {
	a := newTestApp(t)
	a.bulkRunning = true
	a.sessions["unit"] = time.Now().Add(time.Hour)
	for _, path := range []string{"/api/probe", "/api/probe-pending"} {
		r := httptest.NewRequest("POST", "http://localhost:9780"+path, strings.NewReader(`{"domain":"example.com"}`))
		r.Header.Set("Origin", "http://localhost:9780")
		r.AddCookie(&http.Cookie{Name: "route_session", Value: "unit"})
		w := httptest.NewRecorder()
		a.handler().ServeHTTP(w, r)
		if w.Code < 400 {
			t.Fatal(path, w.Code)
		}
	}
	r := httptest.NewRequest("GET", "http://localhost:9780/api/probe-pending", nil)
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
	b, _ := json.Marshal(a.store.bulkResults())
	if !strings.Contains(string(b), "items") {
		t.Fatal(string(b))
	}
}

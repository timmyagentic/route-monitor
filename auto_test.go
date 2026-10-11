package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func putAutoErrors(t *testing.T, s *Store, domain string, ts int64, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if e := s.put([]Event{{ID: randomID(), Domain: domain, Kind: "error", Route: "DIRECT", Time: ts}}); e != nil {
			t.Fatal(e)
		}
	}
}
func claim(t *testing.T, s *Store, now time.Time, want string) time.Time {
	t.Helper()
	d, next, e := s.claimAuto(now)
	if e != nil || d != want {
		t.Fatalf("claim=%q want=%q err=%v", d, want, e)
	}
	return next
}
func TestAutoThresholdWindowDedupAndHandled(t *testing.T) {
	for _, mode := range []string{"threshold", "expired", "duplicate", "connection", "handled"} {
		t.Run(mode, func(t *testing.T) {
			a := newTestApp(t)
			s := a.store
			now := time.Now()
			putAutoErrors(t, s, "example.com", now.Unix(), 1)
			claim(t, s, now, "")
			switch mode {
			case "expired":
				putAutoErrors(t, s, "example.com", now.Unix()-601, 1)
				claim(t, s, now, "")
				return
			case "duplicate":
				var id string
				s.db.QueryRow(`SELECT id FROM events LIMIT 1`).Scan(&id)
				s.put([]Event{{ID: id, Domain: "example.com", Kind: "error", Time: now.Unix()}})
				claim(t, s, now, "")
				return
			case "connection":
				s.put([]Event{{ID: "conn", Domain: "example.com", Kind: "connection", Time: now.Unix()}})
				claim(t, s, now, "")
				return
			case "handled":
				if e := s.setHandled("example.com", 1, true); e != nil {
					t.Fatal(e)
				}
				putAutoErrors(t, s, "example.com", now.Unix(), 1)
				claim(t, s, now, "")
			}
			putAutoErrors(t, s, "example.com", now.Unix(), 1)
			claim(t, s, now, "example.com")
		})
	}
}
func TestAutoOnceSurvivesRestartFailureAndHandling(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	s, e := openStore(path)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	putAutoErrors(t, s, "example.com", now.Unix(), 2)
	claim(t, s, now, "example.com")
	s.db.Close()
	s, e = openStore(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.db.Close()
	if e = s.interruptAuto(now); e != nil {
		t.Fatal(e)
	}
	p, e := s.autoProbe("example.com")
	if e != nil || p.State != "interrupted" {
		t.Fatal(p, e)
	}
	if e = s.setHandled("example.com", 2, true); e != nil {
		t.Fatal(e)
	}
	putAutoErrors(t, s, "example.com", now.Add(4*time.Minute).Unix(), 2)
	if e = s.setHandled("example.com", 4, false); e != nil {
		t.Fatal(e)
	}
	claim(t, s, now.Add(4*time.Minute), "")
	if _, e = s.db.Exec(`DELETE FROM events;DELETE FROM auto_recent_errors;`); e != nil {
		t.Fatal(e)
	}
	putAutoErrors(t, s, "example.com", now.Add(24*time.Hour).Unix(), 2)
	claim(t, s, now.Add(24*time.Hour), "")
}
func TestAutoMigrationDoesNotUseOldHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	s, e := openStore(path)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	putAutoErrors(t, s, "example.com", now.Unix(), 2)
	if _, e = s.db.Exec(`DROP TABLE auto_recent_errors;DROP TABLE auto_probes`); e != nil {
		t.Fatal(e)
	}
	s.db.Close()
	s, e = openStore(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.db.Close()
	claim(t, s, now, "")
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n)
	if n != 2 {
		t.Fatal(n)
	}
	putAutoErrors(t, s, "example.com", now.Unix(), 1)
	claim(t, s, now, "")
	putAutoErrors(t, s, "example.com", now.Unix(), 1)
	claim(t, s, now, "example.com")
}
func TestAutoDailySpacingAndChinaMidnight(t *testing.T) {
	s := newTestApp(t).store
	now := time.Now()
	s.lastPrune = now.Unix() // keep the simulated noon fixture independent of wall-clock pruning
	day := autoDay(now)
	start := day.Add(12 * time.Hour)
	// Use recent/future timestamps so normal seven-day pruning cannot affect the fixture.
	for i := 0; i < 12; i++ {
		at := start.Add(time.Duration(i) * 3 * time.Minute)
		d := fmt.Sprintf("d%d.example.com", i)
		putAutoErrors(t, s, d, at.Unix(), 2)
		claim(t, s, at, d)
	}
	nextDomain := "next.example.com"
	end := day.AddDate(0, 0, 1)
	putAutoErrors(t, s, nextDomain, end.Add(-time.Minute).Unix(), 2)
	next := claim(t, s, end.Add(-time.Second), "")
	if !next.Equal(end) {
		t.Fatal(next, end)
	}
	claim(t, s, end, nextDomain)
	putAutoErrors(t, s, "spacing.example.com", end.Unix(), 2)
	next = claim(t, s, end.Add(179*time.Second), "")
	if next.Unix() != end.Unix()+180 {
		t.Fatal(next)
	}
	claim(t, s, end.Add(180*time.Second), "spacing.example.com")
	p, e := s.autoStatus(end.Add(180 * time.Second))
	if e != nil || p.Used != 2 {
		t.Fatal(p, e)
	}
}
func TestAutoAtomicClaim(t *testing.T) {
	s := newTestApp(t).store
	now := time.Now()
	putAutoErrors(t, s, "example.com", now.Unix(), 2)
	var wg sync.WaitGroup
	var mu sync.Mutex
	n := 0
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			d, _, e := s.claimAuto(now)
			if e != nil {
				t.Error(e)
			}
			mu.Lock()
			if d != "" {
				n++
			}
			mu.Unlock()
		})
	}
	wg.Wait()
	if n != 1 {
		t.Fatal(n)
	}
}
func TestAutoHealthAndSharedSlot(t *testing.T) {
	a := newTestApp(t)
	now := time.Now()
	if a.reserveAuto(now) {
		t.Fatal("offline")
	}
	for _, k := range []string{"logs", "connections", "storage"} {
		a.states[k] = Health{Connected: true}
	}
	a.lastFrame["connections"] = now.Unix() - 20
	if a.reserveAuto(now) {
		t.Fatal("stale")
	}
	a.lastFrame["connections"] = now.Unix()
	a.probing = true
	if a.reserveAuto(now) {
		t.Fatal("manual overlaps")
	}
	a.probing = false
	if !a.reserveAuto(now) || a.reserveAuto(now) {
		t.Fatal("slot")
	}
	a.releaseProbe()
	a.lastProbe = now
	if a.reserveAuto(now) {
		t.Fatal("manual cooldown")
	}
}
func TestProbeLogsPreserveRealClients(t *testing.T) {
	a := newTestApp(t)
	a.probing = true
	a.probeDomain = "example.com"
	for _, src := range []string{"192.168.31.95:1234", "[fd00::1]:4321", "0.0.0.0:0", "[::]:0"} {
		raw, _ := json.Marshal(map[string]string{"type": "warning", "payload": "[TCP] dial DIRECT (match Match/) " + src + " --> example.com:443 error: timeout"})
		event, ok := parseLog(raw, randomID(), time.Now().Unix())
		want := !strings.HasSuffix(src, ":0")
		if ok != want {
			t.Fatal(src, ok)
		}
		if ok {
			if e := a.store.put([]Event{event}); e != nil {
				t.Fatal(e)
			}
		}
	}
	var n int
	a.store.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n)
	if n != 2 {
		t.Fatal(n)
	}
	claim(t, a.store, time.Now(), "example.com")
}
func TestAutoPreflightAndExecution(t *testing.T) {
	for _, mode := range []string{"nxdomain", "private", "complete", "all-failed", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			a := newTestApp(t)
			now := time.Now()
			putAutoErrors(t, a.store, "example.com", now.Unix(), 2)
			claim(t, a.store, now, "example.com")
			var mu sync.Mutex
			heads := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					t.Error("mutation")
				}
				switch r.URL.Path {
				case "/dns/query":
					if mode == "nxdomain" {
						fmt.Fprint(w, `{"Status":3}`)
					} else if mode == "private" {
						fmt.Fprint(w, `{"Answer":[{"type":1,"data":"192.168.1.1"}]}`)
					} else {
						fmt.Fprint(w, `{"Answer":[{"type":1,"data":"1.1.1.1"}]}`)
					}
				case "/proxies":
					fmt.Fprint(w, `{"proxies":{"JP":{"type":"Selector","now":"jp"},"HK":{"type":"Selector","now":"hk"},"jp":{"type":"Shadowsocks"},"hk":{"type":"Shadowsocks"}}}`)
				default:
					mu.Lock()
					heads++
					mu.Unlock()
					if mode == "all-failed" {
						w.WriteHeader(503)
					} else {
						fmt.Fprint(w, `{"delay":123}`)
					}
				}
			}))
			defer srv.Close()
			a.router = newRouter(srv.URL, "test")
			a.lookupIP = func(context.Context, string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				cancel()
			}
			a.probing = true
			a.executeAuto(ctx, "example.com")
			p, e := a.store.autoProbe("example.com")
			if e != nil {
				t.Fatal(e)
			}
			want := "completed"
			count := 9
			if mode == "nxdomain" || mode == "private" {
				want = "skipped"
				count = 0
			}
			if mode == "cancel" {
				want = "interrupted"
				count = 0
			}
			mu.Lock()
			got := heads
			mu.Unlock()
			if p.State != want || got != count || a.probing {
				t.Fatal(p, got, a.probing)
			}
			putAutoErrors(t, a.store, "example.com", now.Add(4*time.Minute).Unix(), 2)
			claim(t, a.store, now.Add(4*time.Minute), "")
			if mode == "complete" { // A later manual round remains independent of the once-only ledger.
				before, _ := a.store.autoStatus(now)
				a.runProbe(context.Background(), "example.com", map[string]string{"DIRECT": "DIRECT", "JP": "jp", "HK": "hk"})
				after, _ := a.store.autoStatus(now)
				ps, _ := a.store.probes("example.com")
				if before != after || len(ps) != 18 {
					t.Fatal(before, after, len(ps))
				}
			}
		})
	}
}

func TestCollectionKeepsErrorsDuringProbe(t *testing.T) {
	a := newTestApp(t)
	a.probing = true
	a.probeDomain = "example.com"
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, e := upgrader.Upgrade(w, r, nil)
		if e != nil {
			return
		}
		defer c.Close()
		for _, src := range []string{"192.168.31.95:1234", "192.168.31.180:4321"} {
			c.WriteJSON(map[string]string{"type": "warning", "payload": "[TCP] dial DIRECT (match Match/) " + src + " --> example.com:443 error: timeout"})
		}
		for {
			if _, _, e = c.ReadMessage(); e != nil {
				return
			}
		}
	}))
	defer srv.Close()
	a.router = newRouter(srv.URL, "test")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); a.collect(ctx, "logs", "/logs") }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var n int
		if e := a.store.db.QueryRow(`SELECT COUNT(*) FROM events WHERE kind='error'`).Scan(&n); e != nil {
			t.Fatal(e)
		}
		if n == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("real errors lost during probe", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	claim(t, a.store, time.Now(), "example.com")
}
func TestAutoLoopTriggeredByEventWake(t *testing.T) {
	a := newTestApp(t)
	a.autoWake = make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"Status":3}`) }))
	defer srv.Close()
	a.router = newRouter(srv.URL, "test")
	now := time.Now()
	for _, k := range []string{"logs", "connections", "storage"} {
		a.states[k] = Health{Connected: true}
	}
	a.lastFrame["connections"] = now.Unix()
	putAutoErrors(t, a.store, "example.com", now.Unix(), 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); a.autoLoop(ctx) }()
	a.wakeAuto()
	deadline := time.Now().Add(3 * time.Second)
	for {
		p, e := a.store.autoProbe("example.com")
		if e != nil {
			t.Fatal(e)
		}
		if p != nil && p.State == "skipped" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("wake did not trigger")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

package main

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHandlingReasonRequiredAndPersisted(t *testing.T) {
	a := newTestApp(t)
	s := a.store
	now := time.Now().Unix()
	if e := s.put([]Event{{ID: "first", Domain: "example.com", Kind: "error", Route: "DIRECT", Error: "DNS 解析错误", Time: now}}); e != nil {
		t.Fatal(e)
	}
	for _, reason := range []string{"", " \n\t", strings.Repeat("字", 301)} {
		if e := s.setHandled("example.com", 1, true, reason); !errors.Is(e, errHandlingReason) {
			t.Fatal(e)
		}
	}
	reason := "已核对公开 DNS，域名不存在。 <script>文本不是代码</script>"
	if e := s.setHandled("example.com", 1, true, "  "+reason+"  "); e != nil {
		t.Fatal(e)
	}
	rows, _, e := s.summaryFor("handled")
	if e != nil || len(rows) != 1 || rows[0].HandledReason != reason {
		t.Fatal(rows, e)
	}
	if e = s.setHandled("example.com", 1, true, strings.Repeat("字", 300)); e != nil {
		t.Fatal(e)
	}
	if e = s.setHandled("example.com", 1, false, ""); e != nil {
		t.Fatal(e)
	}
	rows, _, e = s.summary()
	if e != nil || len(rows) != 1 || rows[0].HandledReason != "" {
		t.Fatal(rows, e)
	}
}
func TestSameErrorStaysHandledAcrossDevicesAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	s, e := openStore(path)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().Unix()
	event := Event{ID: "one", Domain: "example.com", Kind: "error", Route: "DIRECT", Error: "连接超时", Source: "192.168.1.2", Time: now}
	if e = s.put([]Event{event}); e != nil {
		t.Fatal(e)
	}
	if e = s.setHandled(event.Domain, 1, true, "已诊断，暂不调整"); e != nil {
		t.Fatal(e)
	}
	var handledAt int64
	s.db.QueryRow(`SELECT handled_at FROM domain_handling WHERE domain=?`, event.Domain).Scan(&handledAt)
	event.ID = "two"
	event.Source = "192.168.1.3"
	if e = s.put([]Event{event}); e != nil {
		t.Fatal(e)
	}
	s.db.Close()
	s, e = openStore(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.db.Close()
	event.ID = "three"
	event.Time = now + 1
	if e = s.put([]Event{event}); e != nil {
		t.Fatal(e)
	}
	rows, _, e := s.summaryFor("handled")
	if e != nil || len(rows) != 1 || rows[0].ErrorRevision != 3 || rows[0].NewErrors != 0 || rows[0].HandledAt != handledAt || rows[0].HandledReason != "已诊断，暂不调整" {
		t.Fatal(rows, e)
	}
	rows, _, e = s.summary()
	if e != nil || len(rows) != 0 {
		t.Fatal(rows, e)
	}
	// Retention cannot reset the signature even when no original error remains.
	if _, e = s.db.Exec(`DELETE FROM events`); e != nil {
		t.Fatal(e)
	}
	event.ID = "after-retention"
	if e = s.put([]Event{event}); e != nil {
		t.Fatal(e)
	}
	rows, _, e = s.summaryFor("handled")
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	if e = s.setHandled(event.Domain, 3, true, "旧页面"); !errors.Is(e, errHandlingConflict) {
		t.Fatal(e)
	}
}
func TestDifferentErrorOrRouteReopensAndKnownRepeatsNeverHideIt(t *testing.T) {
	for _, mode := range []string{"new-type", "new-route"} {
		t.Run(mode, func(t *testing.T) {
			s := newTestApp(t).store
			now := time.Now().Unix()
			event := Event{ID: "one", Domain: "example.com", Kind: "error", Route: "DIRECT", Error: "连接超时", Time: now}
			s.put([]Event{event})
			if e := s.setHandled(event.Domain, 1, true, "超时已检查"); e != nil {
				t.Fatal(e)
			}
			changed := event
			changed.ID = "changed"
			if mode == "new-type" {
				changed.Error = "DNS 解析错误"
			} else {
				changed.Route = "JP"
			}
			if e := s.put([]Event{changed}); e != nil {
				t.Fatal(e)
			}
			event.ID = "old-repeat"
			if e := s.put([]Event{event}); e != nil {
				t.Fatal(e)
			}
			rows, _, e := s.summary()
			if e != nil || len(rows) != 1 || rows[0].Handled || rows[0].HandledReason != "超时已检查" {
				t.Fatal(rows, e)
			}
			if e = s.setHandled(event.Domain, 3, true, "新的错误也已检查"); e != nil {
				t.Fatal(e)
			}
			changed.ID = "changed-repeat"
			if e = s.put([]Event{changed}); e != nil {
				t.Fatal(e)
			}
			rows, _, e = s.summaryFor("handled")
			if e != nil || len(rows) != 1 {
				t.Fatal(rows, e)
			}
			if e = s.setHandled(event.Domain, 4, false, ""); e != nil {
				t.Fatal(e)
			}
			var n int
			s.db.QueryRow(`SELECT COUNT(*) FROM handled_errors WHERE domain=?`, event.Domain).Scan(&n)
			if n != 0 {
				t.Fatal(n)
			}
		})
	}
}
func TestSuppressedErrorsNeverCountTowardAutoProbe(t *testing.T) {
	s := newTestApp(t).store
	now := time.Now()
	event := Event{ID: "one", Domain: "example.com", Kind: "error", Route: "DIRECT", Error: "DNS 解析错误", Time: now.Unix()}
	s.put([]Event{event})
	s.setHandled(event.Domain, 1, true, "DNS错误已核对")
	for i := 0; i < 4; i++ {
		event.ID = randomID()
		if e := s.put([]Event{event}); e != nil {
			t.Fatal(e)
		}
	}
	claim(t, s, now, "")
	changed := event
	changed.ID = randomID()
	changed.Error = "连接超时"
	s.put([]Event{changed})
	for i := 0; i < 4; i++ {
		event.ID = randomID()
		s.put([]Event{event})
	}
	claim(t, s, now, "")
	changed.ID = randomID()
	s.put([]Event{changed})
	claim(t, s, now, "example.com")
}
func TestHandlingMigrationIsAdditiveAndDoesNotReseedAfterUndo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().Unix()
	_, e = db.Exec(`CREATE TABLE events(id TEXT PRIMARY KEY,domain TEXT NOT NULL,source TEXT,route TEXT,rule TEXT,kind TEXT,error TEXT,ts INTEGER);
 CREATE TABLE domain_handling(domain TEXT PRIMARY KEY,error_revision INTEGER NOT NULL DEFAULT 0,handled_revision INTEGER,handled_at INTEGER NOT NULL DEFAULT 0);
 INSERT INTO domain_handling VALUES('handled.example.com',1,1,123),('active.example.com',1,NULL,0);`)
	if e != nil {
		t.Fatal(e)
	}
	for _, d := range []string{"handled.example.com", "active.example.com"} {
		if _, e = db.Exec(`INSERT INTO events VALUES(?,?,'device','DIRECT','rule','error','连接超时',?)`, d, d, now); e != nil {
			t.Fatal(e)
		}
	}
	db.Close()
	s, e := openStore(path)
	if e != nil {
		t.Fatal(e)
	}
	rows, _, e := s.summaryFor("handled")
	if e != nil || len(rows) != 1 || rows[0].HandledReason != "" || rows[0].HandledAt != 123 {
		t.Fatal(rows, e)
	}
	for _, d := range []string{"handled.example.com", "active.example.com"} {
		if e = s.put([]Event{{ID: "next-" + d, Domain: d, Route: "DIRECT", Kind: "error", Error: "连接超时", Time: now}}); e != nil {
			t.Fatal(e)
		}
	}
	rows, _, e = s.summary()
	if e != nil || len(rows) != 1 || rows[0].Domain != "active.example.com" {
		t.Fatal(rows, e)
	}
	if e = s.setHandled("handled.example.com", 2, false, ""); e != nil {
		t.Fatal(e)
	}
	s.db.Close()
	s, e = openStore(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.db.Close()
	var count int
	s.db.QueryRow(`SELECT COUNT(*) FROM handled_errors WHERE domain='handled.example.com'`).Scan(&count)
	if count != 0 {
		t.Fatal("migration reseeded revoked signature")
	}
}
func TestHandlingHTTPRequiresReason(t *testing.T) {
	a := newTestApp(t)
	a.store.put([]Event{{ID: "one", Domain: "example.com", Kind: "error", Route: "DIRECT", Time: time.Now().Unix()}})
	a.sessions["unit-session"] = time.Now().Add(time.Hour)
	for _, body := range []string{`{"domain":"example.com","handled":true,"expectedErrorRevision":1}`, `{"domain":"example.com","handled":true,"reason":"  ","expectedErrorRevision":1}`} {
		r := httptest.NewRequest("POST", "http://localhost:9780/api/handling", strings.NewReader(body))
		r.Header.Set("Origin", "http://localhost:9780")
		r.AddCookie(&http.Cookie{Name: "route_session", Value: "unit-session"})
		w := httptest.NewRecorder()
		a.handler().ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}

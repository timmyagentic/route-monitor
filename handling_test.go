package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHandlingPersistsAndOnlyNewErrorsReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.db")
	s, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	event := Event{ID: "error-one", Domain: "example.com", Route: "DIRECT", Kind: "error", Error: "连接超时", Time: now}
	if err = s.put([]Event{event}); err != nil {
		t.Fatal(err)
	}
	if err = s.setHandled(event.Domain, 1, true); err != nil {
		t.Fatal(err)
	}
	assertCount := func(view string, count int) []Row {
		t.Helper()
		rows, _, e := s.summaryFor(view)
		if e != nil || len(rows) != count {
			t.Fatalf("%s rows=%+v err=%v", view, rows, e)
		}
		return rows
	}
	assertCount("active", 0)
	rows := assertCount("handled", 1)
	if !rows[0].Handled || rows[0].ErrorRevision != 1 {
		t.Fatal(rows)
	}
	// Duplicate snapshots and successful observations must not reopen a handled domain.
	if err = s.put([]Event{event, {ID: "conn-one", Domain: event.Domain, Route: "DIRECT", Kind: "connection", Time: now + 1}}); err != nil {
		t.Fatal(err)
	}
	assertCount("active", 0)
	if err = s.db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	assertCount("active", 0)
	assertCount("handled", 1)
	// A distinct error in the same second must reopen it, regardless of timestamps.
	event.ID = "error-two"
	if err = s.put([]Event{event}); err != nil {
		t.Fatal(err)
	}
	rows = assertCount("active", 1)
	if rows[0].Handled || rows[0].NewErrors != 1 || rows[0].ErrorRevision != 2 {
		t.Fatal(rows)
	}
	assertCount("handled", 0)
	if err = s.setHandled(event.Domain, 1, true); !errors.Is(err, errHandlingConflict) {
		t.Fatalf("stale action swallowed new error: %v", err)
	}
	if err = s.setHandled(event.Domain, 2, true); err != nil {
		t.Fatal(err)
	}
	assertCount("active", 0)
	// Retention deletion cannot reset the watermark or unhide it after a new connection.
	if _, err = s.db.Exec("DELETE FROM events"); err != nil {
		t.Fatal(err)
	}
	if err = s.put([]Event{{ID: "conn-two", Domain: event.Domain, Route: "DIRECT", Kind: "connection", Time: now + 2}}); err != nil {
		t.Fatal(err)
	}
	assertCount("active", 0)
	if err = s.setHandled(event.Domain, 2, false); err != nil {
		t.Fatal(err)
	}
	assertCount("active", 1)
}

func TestHandlingMigratesExistingErrorsAndFiltersBeforeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.db")
	s, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	var events []Event
	for i := 0; i < 301; i++ {
		events = append(events, Event{ID: fmt.Sprint(i), Domain: fmt.Sprintf("d%d.example.com", i), Kind: "error", Route: "DIRECT", Time: now})
	}
	events = append(events, Event{ID: "unhandled", Domain: "visible.example.com", Kind: "connection", Route: "DIRECT", Time: now})
	if err = s.put(events); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("DROP TABLE domain_handling"); err != nil {
		t.Fatal(err)
	}
	s.db.Close()
	s, err = openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	for i := 0; i < 301; i++ {
		if err = s.setHandled(events[i].Domain, 1, true); err != nil {
			t.Fatal(err)
		}
	}
	rows, _, err := s.summary()
	if err != nil || len(rows) != 1 || rows[0].Domain != "visible.example.com" {
		t.Fatal(rows, err)
	}
	if err = s.setHandled("visible.example.com", 0, true); err != nil {
		t.Fatal(err)
	}
	rows, _, err = s.summary()
	if err != nil || len(rows) != 0 {
		t.Fatal(rows, err)
	}
}

func TestHandlingHTTPAuthorizationConflictAndUndo(t *testing.T) {
	a := newTestApp(t)
	h := a.handler()
	now := time.Now().Unix()
	if err := a.store.put([]Event{{ID: "one", Domain: "example.com", Kind: "error", Route: "DIRECT", Time: now}}); err != nil {
		t.Fatal(err)
	}
	call := func(method, path, body, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://localhost:9780"+path, strings.NewReader(body))
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	body := `{"domain":"example.com","handled":true,"expectedErrorRevision":1}`
	if w := call("POST", "/api/handling", body, "http://localhost:9780", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	login := call("POST", "/api/login", `{"password":"test-password"}`, "http://localhost:9780", nil)
	cookie := login.Result().Cookies()[0]
	if w := call("POST", "/api/handling", body, "http://evil.com", cookie); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := call("POST", "/api/handling", `{"domain":"example.com"}`, "http://localhost:9780", cookie); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w := call("POST", "/api/handling", body, "http://localhost:9780", cookie); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	state := func(view string) []Row {
		w := call("GET", "/api/state"+view, "", "", cookie)
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		var s struct {
			Rows []Row `json:"rows"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
			t.Fatal(err)
		}
		return s.Rows
	}
	if len(state("")) != 0 || len(state("?view=handled")) != 1 || len(state("?view=all")) != 1 {
		t.Fatal("views not filtered")
	}
	if w := call("GET", "/api/state?view=bad", "", "", cookie); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if err := a.store.put([]Event{{ID: "two", Domain: "example.com", Kind: "error", Route: "DIRECT", Time: now}}); err != nil {
		t.Fatal(err)
	}
	if w := call("POST", "/api/handling", body, "http://localhost:9780", cookie); w.Code != 409 {
		t.Fatal(w.Code)
	}
	if len(state("")) != 1 {
		t.Fatal("new error hidden")
	}
	if w := call("POST", "/api/handling", `{"domain":"example.com","handled":true,"expectedErrorRevision":2}`, "http://localhost:9780", cookie); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := call("POST", "/api/handling", `{"domain":"example.com","handled":false,"expectedErrorRevision":2}`, "http://localhost:9780", cookie); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if len(state("")) != 1 {
		t.Fatal("undo failed")
	}
	if w := call("POST", "/api/handling", `{"domain":"missing.example.com","handled":true,"expectedErrorRevision":0}`, "http://localhost:9780", cookie); w.Code != 404 {
		t.Fatal(w.Code)
	}
}

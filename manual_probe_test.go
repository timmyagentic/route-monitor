package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManualProbeImmediateRetryAndConcurrency(t *testing.T) {
	a := newTestApp(t)
	h := a.handler()
	call := func(path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://localhost:9780"+path, strings.NewReader(body))
		r.Header.Set("Origin", "http://localhost:9780")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	login := call("/api/login", `{"password":"test-password"}`, nil)
	cookie := login.Result().Cookies()[0]
	// Rejected targets release the slot; the next request must reach validation immediately.
	for i := 0; i < 2; i++ {
		w := call("/api/probe", `{"domain":"example.invalid"}`, cookie)
		if w.Code != 400 {
			t.Fatalf("attempt %d: %d %s", i, w.Code, w.Body.String())
		}
	}
	for _, bulk := range []bool{false, true} {
		a.mu.Lock()
		a.probing = !bulk
		a.bulkRunning = bulk
		a.mu.Unlock()
		w := call("/api/probe", `{"domain":"example.invalid"}`, cookie)
		if w.Code != 429 {
			t.Fatalf("busy bulk=%v: %d", bulk, w.Code)
		}
	}
}

package main

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAgentPlistEscapesPathsAndUsesBundleIdentity(t *testing.T) {
	exe := "/Users/test & person/Applications/Route Monitor.app/Contents/MacOS/route-monitor"
	dir := "/Users/test & person/a<b"
	d := xml.NewDecoder(strings.NewReader(agentPlist(exe, dir)))
	var stringsFound []string
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if start, ok := tok.(xml.StartElement); ok && (start.Name.Local == "string" || start.Name.Local == "key") {
			var value string
			if err := d.DecodeElement(&value, &start); err != nil {
				t.Fatal(err)
			}
			stringsFound = append(stringsFound, value)
		}
	}
	all := strings.Join(stringsFound, "\n")
	for _, s := range []string{exe, dir, "-service", "AssociatedBundleIdentifiers\nlocal.route-monitor", "RunAtLoad", "KeepAlive"} {
		if !strings.Contains(all, s) {
			t.Fatalf("missing %q", s)
		}
	}
}

func TestServiceLogRotatesAndRestrictsPermissions(t *testing.T) {
	l, err := openServiceLog(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.limit = 12
	for _, line := range []string{"first-line\n", "next-line\n", "last-line\n"} {
		if _, err := l.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	for name, want := range map[string]string{l.path: "last-line\n", l.path + ".1": "next-line\n"} {
		b, err := os.ReadFile(name)
		if err != nil || string(b) != want {
			t.Fatalf("%s %q %v", name, b, err)
		}
		st, err := os.Stat(name)
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatalf("log permissions: %v %v", st, err)
		}
	}
	st, err := os.Stat(filepath.Dir(l.path))
	if err != nil || st.Mode().Perm() != 0700 {
		t.Fatalf("directory permissions: %v %v", st, err)
	}
}

func TestServiceHealthRequiresLocalCallerAndFreshCollection(t *testing.T) {
	a := newTestApp(t)
	a.cfg.Secret = "test-secret-not-for-health"
	a.states = map[string]Health{"connections": {Connected: true}, "logs": {Connected: true}, "storage": {Connected: true}}
	a.lastFrame = map[string]int64{"connections": time.Now().Unix()}
	check := func(remote string, want int) {
		t.Helper()
		r := httptest.NewRequest("GET", "http://127.0.0.1:9780/healthz", nil)
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		a.handler().ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("got %d, want %d: %s", w.Code, want, w.Body.String())
		}
		if strings.Contains(w.Body.String(), a.cfg.Secret) {
			t.Fatal("secret in health response")
		}
	}
	check("127.0.0.1:40000", http.StatusOK)
	check("192.168.31.9:40000", http.StatusNotFound)
	a.lastFrame["connections"] = time.Now().Add(-time.Minute).Unix()
	check("127.0.0.1:40000", http.StatusServiceUnavailable)
	a.lastFrame["connections"] = time.Now().Unix()
	a.states["logs"] = Health{}
	check("[::1]:40000", http.StatusServiceUnavailable)
}

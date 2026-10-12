package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Only lifecycle events and pre-sanitized health messages are written here.
// Network payloads, credentials and request URLs never enter this log.
type serviceLog struct {
	mu    sync.Mutex
	path  string
	file  *os.File
	size  int64
	limit int64
}

func openServiceLog(dir string) (*serviceLog, error) {
	dir = filepath.Join(dir, "logs")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	l := &serviceLog{path: filepath.Join(dir, "service.log"), limit: 1 << 20}
	return l, l.open()
}

func (l *serviceLog) open() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.file, l.size = f, info.Size()
	return nil
}

func (l *serviceLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.size+int64(len(p)) > l.limit && l.size > 0 {
		if err := l.file.Close(); err != nil {
			return 0, err
		}
		if err := os.Rename(l.path, l.path+".1"); err != nil {
			_ = l.open()
			return 0, err
		}
		if err := l.open(); err != nil {
			return 0, err
		}
	}
	n, err := l.file.Write(p)
	l.size += int64(n)
	return n, err
}

func (l *serviceLog) Close() error { l.mu.Lock(); defer l.mu.Unlock(); return l.file.Close() }

// The installer can verify collection without knowing the user's page password.
// Only local callers receive a boolean status, never configuration or history.
func (a *App) serviceHealth(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		http.NotFound(w, r)
		return
	}
	a.mu.Lock()
	ok := a.states["connections"].Connected && a.states["logs"].Connected && a.states["storage"].Connected && time.Now().Unix()-a.lastFrame["connections"] <= 30
	a.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	fmt.Fprintf(w, "{\"ok\":%t}\n", ok)
}

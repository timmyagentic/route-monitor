package routebridge

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"
	"golang.org/x/net/dns/dnsmessage"
)

func probeConfig(runtime map[string]any, snap *Snapshot, ports map[string]int) (map[string]any, error) {
	c := map[string]any{"mode": "rule", "log-level": "info", "allow-lan": false, "bind-address": "127.0.0.1", "rules": []string{"MATCH,REJECT"}, "profile": map[string]any{"store-selected": false, "store-fake-ip": false}}
	// Copy only outbound-related options. Never copy TUN, redirection ports,
	// controller, providers, sniffing, authentication or persistent caches.
	for _, k := range []string{"ipv6", "routing-mark", "interface-name", "tcp-concurrent", "global-client-fingerprint", "hosts"} {
		if v, ok := runtime[k]; ok {
			c[k] = v
		}
	}
	dns, ok := runtime["dns"].(map[string]any)
	if !ok {
		return nil, errors.New("dns_unavailable")
	}
	d := map[string]any{}
	for k, v := range dns {
		d[k] = v
	}
	d["listen"] = ""
	d["enhanced-mode"] = "redir-host"
	d["use-system-hosts"] = false
	c["dns"] = d
	proxies := []any{}
	listeners := []any{}
	items, _ := runtime["proxies"].([]any)
	for _, route := range []string{"DIRECT", "JP", "HK"} {
		target := "DIRECT"
		if route != "DIRECT" {
			found := false
			for _, item := range items {
				v, _ := item.(map[string]any)
				if v["name"] == snap.Nodes[route] {
					clone := map[string]any{}
					for k, x := range v {
						clone[k] = x
					}
					target = "rm-node-" + route
					clone["name"] = target
					proxies = append(proxies, clone)
					found = true
					break
				}
			}
			if !found {
				return nil, errors.New("selected_node_missing")
			}
		}
		listeners = append(listeners, map[string]any{"name": "rm-" + route, "type": "mixed", "listen": "127.0.0.1", "port": ports[route], "proxy": target, "udp": false})
	}
	c["proxies"] = proxies
	c["listeners"] = listeners
	return c, nil
}

type readiness struct {
	mu     sync.Mutex
	buffer string
	seen   map[string]bool
	done   chan struct{}
	once   sync.Once
}

func (r *readiness) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buffer += string(p)
	for {
		i := strings.IndexByte(r.buffer, '\n')
		if i < 0 {
			break
		}
		line := r.buffer[:i]
		r.buffer = r.buffer[i+1:]
		if strings.Contains(line, "proxy listening at:") {
			for _, route := range []string{"DIRECT", "JP", "HK"} {
				if strings.Contains(line, "[rm-"+route+"]") {
					r.seen[route] = true
				}
			}
		}
	}
	if len(r.buffer) > 65536 {
		r.buffer = ""
	}
	if len(r.seen) == 3 {
		r.once.Do(func() { close(r.done) })
	}
	return len(p), nil
}

func dohURL(runtime map[string]any) (string, error) {
	dns, _ := runtime["dns"].(map[string]any)
	servers, _ := dns["nameserver"].([]any)
	for _, server := range servers {
		s, ok := server.(string)
		if !ok {
			continue
		}
		u, e := url.Parse(s)
		if e == nil && u.Scheme == "https" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && ValidDomain(u.Hostname()) && (u.Port() == "" || u.Port() == "443") {
			return s, nil
		}
	}
	return "", errors.New("supported_doh_required")
}

func explicitDNSPolicy(runtime map[string]any, domain string) bool {
	match := func(pattern string) bool {
		if pattern == "*" {
			return !strings.Contains(domain, ".")
		}
		if strings.HasPrefix(pattern, "+.") {
			suffix := strings.TrimPrefix(pattern, "+.")
			return domain == suffix || strings.HasSuffix(domain, "."+suffix)
		}
		if strings.HasPrefix(pattern, "*.") {
			return strings.HasSuffix(domain, strings.TrimPrefix(pattern, "*"))
		}
		if strings.ContainsAny(pattern, "*:,") {
			return true
		}
		return pattern == domain
	}
	if hosts, ok := runtime["hosts"].(map[string]any); ok {
		for pattern := range hosts {
			if match(pattern) {
				return true
			}
		}
	}
	dns, _ := runtime["dns"].(map[string]any)
	if policies, ok := dns["nameserver-policy"].(map[string]any); ok {
		for pattern := range policies {
			if match(pattern) {
				return true
			}
		}
	}
	return false
}

func resolvePublic(ctx context.Context, client *http.Client, endpoint, domain string) ([]net.IP, string) {
	name, e := dnsmessage.NewName(domain + ".")
	if e != nil {
		return nil, "invalid_domain"
	}
	var nonce [2]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return nil, "dns_internal"
	}
	id := binary.BigEndian.Uint16(nonce[:])
	msg := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	wire, e := msg.Pack()
	if e != nil {
		return nil, "dns_internal"
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(wire))
	if e != nil {
		return nil, "dns_internal"
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	r, e := client.Do(req)
	if e != nil {
		return nil, "dns_transport"
	}
	defer r.Body.Close()
	if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/dns-message") {
		return nil, "dns_response"
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, 65537))
	if e != nil || len(b) > 65536 {
		return nil, "dns_response"
	}
	var answer dnsmessage.Message
	if answer.Unpack(b) != nil || answer.ID != id || !answer.Response || len(answer.Questions) != 1 || answer.Questions[0] != msg.Questions[0] {
		return nil, "dns_response"
	}
	if answer.RCode == dnsmessage.RCodeNameError {
		return nil, "nxdomain"
	}
	if answer.RCode != dnsmessage.RCodeSuccess {
		return nil, "dns_failure"
	}
	var ips []net.IP
	for _, a := range answer.Answers {
		if v, ok := a.Body.(*dnsmessage.AResource); ok {
			ip := net.IPv4(v.A[0], v.A[1], v.A[2], v.A[3])
			if !PublicIP(ip) {
				return nil, "unsafe_address"
			}
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, "no_address"
	}
	sort.Slice(ips, func(i, j int) bool { return bytes.Compare(ips[i], ips[j]) < 0 })
	return ips, "ok"
}

func proxyClient(proxy string, serverName string) *http.Client {
	u, _ := url.Parse(proxy)
	transport := &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}}
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// Mihomo creates listeners while its tunnel is still suspended. A successful
// loopback round-trip through DIRECT proves ApplyConfig has reached OnRunning;
// a listening socket alone does not. This bounded startup check never contacts
// an external host or contributes to route-health evidence.
func awaitTunnel(ctx context.Context, proxy string) error {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return errors.New("probe_ready_failed")
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		l.Close()
		return errors.New("probe_ready_failed")
	}
	path := "/ready/" + fmt.Sprintf("%x", nonce)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}), ReadHeaderTimeout: time.Second}
	go srv.Serve(l)
	defer srv.Close()
	client := proxyClient(proxy, "")
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		attempt, stop := context.WithTimeout(ctx, 300*time.Millisecond)
		req, _ := http.NewRequestWithContext(attempt, http.MethodGet, "http://"+l.Addr().String()+path, nil)
		res, e := client.Do(req)
		if e == nil {
			res.Body.Close()
			if res.StatusCode == http.StatusNoContent {
				stop()
				return nil
			}
		}
		stop()
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	return errors.New("probe_ready_failed")
}

func probeOne(ctx context.Context, proxy, doh, domain, route, nodeHash string, port, round int, control bool) Sample {
	start := time.Now()
	s := Sample{Route: route, NodeHash: nodeHash, Domain: domain, Round: round, Control: control, Status: "unknown", Stage: "dns", Time: start.Unix()}
	dnsClient := proxyClient(proxy, "")
	defer dnsClient.CloseIdleConnections()
	resolve, cancel := context.WithTimeout(ctx, 5*time.Second)
	ips, status := resolvePublic(resolve, dnsClient, doh, domain)
	cancel()
	s.DNSStatus = status
	if status != "ok" {
		s.Millis = nowMillis(start)
		if status == "unsafe_address" {
			s.Status = "unsafe"
		} else if status == "dns_transport" || status == "dns_failure" || status == "nxdomain" || status == "no_address" {
			s.Status = "failed"
		}
		return s
	}
	s.Address = ips[0].String()
	s.Stage = "connect"
	// CONNECT uses the validated address. Host and TLS SNI retain the domain,
	// preventing a later DNS change from turning the probe into a private fetch.
	client := proxyClient(proxy, domain)
	defer client.CloseIdleConnections()
	requestCtx, stop := context.WithTimeout(ctx, 7*time.Second)
	defer stop()
	stage := "connect"
	var stageMu sync.Mutex
	trace := &httptrace.ClientTrace{TLSHandshakeStart: func() { stageMu.Lock(); stage = "tls"; stageMu.Unlock() }, TLSHandshakeDone: func(_ tls.ConnectionState, e error) {
		if e == nil {
			stageMu.Lock()
			stage = "http"
			stageMu.Unlock()
		}
	}}
	requestCtx = httptrace.WithClientTrace(requestCtx, trace)
	req, e := http.NewRequestWithContext(requestCtx, http.MethodHead, "https://"+net.JoinHostPort(s.Address, strconv.Itoa(port))+"/", nil)
	if e != nil {
		s.Millis = nowMillis(start)
		return s
	}
	req.Host = domain
	req.Header.Set("User-Agent", "RouteMonitor/0.6 connection-check")
	r, e := client.Do(req)
	if e != nil {
		stageMu.Lock()
		s.Stage = stage
		stageMu.Unlock()
		s.Status = "failed"
		var cert *tls.CertificateVerificationError
		var unknown x509.UnknownAuthorityError
		if errors.As(e, &cert) || errors.As(e, &unknown) {
			s.Stage = "tls_certificate"
			s.Status = "unsafe"
		}
	} else {
		r.Body.Close()
		s.Stage = "http"
		s.Status = "response"
		s.HTTPStatus = r.StatusCode
	}
	s.Millis = nowMillis(start)
	return s
}

func (b Bridge) Probe(ctx context.Context, req Request) (Response, error) {
	if e := Validate(req); e != nil {
		return Response{}, e
	}
	runtime, _, snap, e := b.load(ctx)
	if e != nil {
		return Response{}, e
	}
	if req.ExpectedSnapshot != "" && req.ExpectedSnapshot != snap.ID {
		return Response{}, errors.New("snapshot_changed")
	}
	for _, domain := range append(append([]string{}, req.Controls...), req.Domain) {
		if explicitDNSPolicy(runtime, domain) {
			return Response{}, errors.New("explicit_dns_policy")
		}
	}
	doh, e := dohURL(runtime)
	if e != nil {
		return Response{}, e
	}
	stage, e := os.MkdirTemp("", "route-monitor-probe-")
	if e != nil {
		return Response{}, errors.New("probe_staging_failed")
	}
	defer os.RemoveAll(stage)
	ports := map[string]int{}
	for _, route := range []string{"DIRECT", "JP", "HK"} {
		l, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			return Response{}, errors.New("probe_port_unavailable")
		}
		ports[route] = l.Addr().(*net.TCPAddr).Port
		l.Close()
	}
	cfg, e := probeConfig(runtime, snap, ports)
	if e != nil {
		return Response{}, e
	}
	y, e := yaml.Marshal(cfg)
	if e != nil {
		return Response{}, errors.New("probe_config_invalid")
	}
	file := filepath.Join(stage, "config.yaml")
	if e = os.WriteFile(file, y, 0600); e != nil {
		return Response{}, errors.New("probe_staging_failed")
	}
	coreCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(coreCtx, b.Core, "-d", stage, "-f", file)
	hardenChild(cmd)
	ready := &readiness{seen: map[string]bool{}, done: make(chan struct{})}
	cmd.Stdout = ready
	cmd.Stderr = ready
	if e = cmd.Start(); e != nil {
		return Response{}, errors.New("probe_core_failed")
	}
	exited := make(chan struct{})
	go func() { cmd.Wait(); close(exited) }()
	defer func() { cancel(); <-exited }()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-ready.done:
	case <-exited:
		return Response{}, errors.New("probe_core_failed")
	case <-timer.C:
		return Response{}, errors.New("probe_core_timeout")
	case <-ctx.Done():
		return Response{}, errors.New("probe_cancelled")
	}
	if e = awaitTunnel(coreCtx, "http://127.0.0.1:"+strconv.Itoa(ports["DIRECT"])); e != nil {
		return Response{}, e
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	out := Response{OK: true, Snapshot: snap, ID: req.ID}
	for _, route := range []string{"DIRECT", "JP", "HK"} {
		wg.Go(func() {
			proxy := "http://127.0.0.1:" + strconv.Itoa(ports[route])
			for _, domain := range append(append([]string{}, req.Controls...), req.Domain) {
				n := 1
				if domain == req.Domain {
					n = 2
				}
				for i := 0; i < n; i++ {
					if coreCtx.Err() != nil {
						return
					}
					s := probeOne(coreCtx, proxy, doh, domain, route, snap.NodeHashes[route], req.Port, i+1, domain != req.Domain)
					mu.Lock()
					out.Samples = append(out.Samples, s)
					mu.Unlock()
				}
			}
		})
	}
	wg.Wait()
	if coreCtx.Err() != nil {
		return Response{}, errors.New("probe_timeout")
	}
	after, e := b.Inspect(ctx)
	if e != nil || after.ID != snap.ID {
		return Response{}, errors.New("snapshot_changed")
	}
	sort.Slice(out.Samples, func(i, j int) bool {
		a, z := out.Samples[i], out.Samples[j]
		return a.Route+a.Domain+strconv.Itoa(a.Round) < z.Route+z.Domain+strconv.Itoa(z.Round)
	})
	return out, nil
}

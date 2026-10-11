package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/websocket"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Router struct {
	Base, Secret string
	Client       *http.Client
}

func newRouter(base, secret string) *Router {
	return &Router{base, secret, &http.Client{Timeout: 12 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (r *Router) get(ctx context.Context, path string, target any) (int, error) {
	// Every upstream request is GET. There is deliberately no generic proxy or mutation endpoint.
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, r.Base+path, nil)
	if e != nil {
		return 0, e
	}
	req.Header.Set("Authorization", "Bearer "+r.Secret)
	res, e := r.Client.Do(req)
	if e != nil {
		return 0, errors.New("路由器接口不可达")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return res.StatusCode, fmt.Errorf("路由器接口 HTTP %d", res.StatusCode)
	}
	if target != nil {
		e = json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(target)
	}
	return res.StatusCode, e
}
func (a *App) collect(ctx context.Context, kind, path string) {
	backoff := time.Second
	for ctx.Err() == nil {
		headers := http.Header{"Authorization": []string{"Bearer " + a.router.Secret}}
		dialer := websocket.Dialer{Proxy: nil, HandshakeTimeout: 8 * time.Second, NetDialContext: (&net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}).DialContext}
		endpoint := strings.Replace(a.router.Base, "http", "ws", 1) + path
		conn, resp, e := dialer.DialContext(ctx, endpoint, headers)
		if e != nil {
			message := "连接失败，正在重试"
			if resp != nil {
				message = fmt.Sprintf("HTTP %d，正在重试", resp.StatusCode)
			}
			a.health(kind, false, message)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		a.health(kind, true, "")
		conn.SetReadLimit(8 << 20)
		stop := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				conn.Close()
			case <-stop:
			}
		}()
		for ctx.Err() == nil {
			if kind == "connections" {
				conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			}
			_, data, e := conn.ReadMessage()
			if e != nil {
				break
			}
			now := time.Now().Unix()
			var events []Event
			if kind == "connections" {
				events, e = snapshot(data, now)
			} else {
				v, ok := parseLog(data, randomID(), now)
				if ok {
					events = []Event{v}
				} else {
					a.mu.Lock()
					a.unparsed++
					a.mu.Unlock()
				}
			}
			if e != nil {
				a.health(kind, true, "部分数据无法解析")
				continue
			}
			// Probe activity does not represent a user failure. The API's synthetic requests normally
			// have no client source; exclude all log events during the bounded explicit probe window.
			if kind == "logs" {
				a.mu.Lock()
				running := a.probing
				a.mu.Unlock()
				if running {
					events = nil
				}
			}
			if len(events) > 0 {
				if e = a.store.put(events); e != nil {
					a.health("storage", false, "数据库写入失败")
					continue
				}
				a.health("storage", true, "")
			}
			a.mu.Lock()
			a.lastFrame[kind] = now
			a.mu.Unlock()
			a.publish()
		}
		close(stop)
		conn.Close()
		a.health(kind, false, "连接已断开，正在重连")
	}
}
func (a *App) safeTarget(ctx context.Context, domain string) error {
	if domainName(domain) != domain {
		return errors.New("只支持已观察到的完整域名")
	}
	for _, suffix := range []string{".local", ".localhost", ".lan", ".home.arpa", ".internal", ".test", ".invalid", ".onion"} {
		if strings.HasSuffix(domain, suffix) {
			return errors.New("不探测本地域名")
		}
	}
	var count int
	if e := a.store.db.QueryRow(`SELECT COUNT(*) FROM events WHERE domain=? AND ts>?`, domain, time.Now().Unix()-86400).Scan(&count); e != nil {
		return e
	}
	if count == 0 {
		return errors.New("仅可复测最近24小时实际观察到的域名")
	}
	// Check both monitor DNS and the router's real DNS answer. Fake-IP, private and
	// mixed public/private answers are rejected. Do not use an external DNS service.
	ips, e := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if e != nil || len(ips) == 0 {
		return errors.New("无法确认公开目标地址，暂不探测")
	}
	for _, ip := range ips {
		if !publicIP(ip.IP) {
			return errors.New("解析含非公网地址，已跳过探测")
		}
	}
	var answer struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	// DNS endpoint may be unavailable; fail closed rather than probing an unknown address.
	_, e = a.router.get(ctx, "/dns/query?name="+url.QueryEscape(domain)+"&type=A", &answer)
	if e != nil {
		return errors.New("无法检查路由器 DNS 结果，暂不探测")
	}
	n := 0
	for _, rr := range answer.Answer {
		if rr.Type == 1 || rr.Type == 28 {
			n++
			if !publicIP(net.ParseIP(rr.Data)) {
				return errors.New("路由器解析含非公网地址，已跳过探测")
			}
		}
	}
	if n == 0 {
		return errors.New("路由器未返回可验证公网地址")
	}
	return nil
}
func publicIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, s := range []string{"100.64.0.0/10", "198.18.0.0/15", "192.0.0.0/24", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32"} {
		_, block, _ := net.ParseCIDR(s)
		if block.Contains(ip) {
			return false
		}
	}
	return true
}

type proxyInfo struct {
	Type string `json:"type"`
	Now  string `json:"now"`
}

func (a *App) nodes(ctx context.Context) (map[string]string, error) {
	var p struct {
		Proxies map[string]proxyInfo `json:"proxies"`
	}
	if _, e := a.router.get(ctx, "/proxies", &p); e != nil {
		return nil, e
	}
	out := map[string]string{"DIRECT": "DIRECT"}
	for _, route := range []string{"JP", "HK"} {
		v, ok := p.Proxies[route]
		if !ok || v.Type != "Selector" || v.Now == "" {
			return nil, fmt.Errorf("%s 必须是手动选择组", route)
		}
		node, ok := p.Proxies[v.Now]
		if !ok || node.Now != "" || node.Type == "Direct" || node.Type == "Reject" || node.Type == "Selector" || node.Type == "URLTest" || node.Type == "Fallback" || node.Type == "LoadBalance" {
			return nil, fmt.Errorf("%s 当前不是可独立测试的代理节点", route)
		}
		out[route] = v.Now
	}
	return out, nil
}
func (a *App) runProbe(ctx context.Context, domain string, nodes map[string]string) {
	defer func() { a.mu.Lock(); a.probing = false; a.probeDomain = ""; a.mu.Unlock(); a.publish() }()
	batch := randomID()
	for round := 0; round < 3; round++ {
		for _, route := range []string{"DIRECT", "JP", "HK"} {
			if ctx.Err() != nil {
				return
			}
			p := Probe{Time: time.Now().Unix(), Batch: batch, Domain: domain, Route: route, Node: nodes[route], Status: "failed"}
			var result struct {
				Delay int `json:"delay"`
			}
			// HEAD https://domain/; no cookies, URL paths, credentials or redirect following.
			path := "/proxies/" + url.PathEscape(p.Node) + "/delay?timeout=" + strconv.Itoa(7000) + "&url=" + url.QueryEscape("https://"+domain+"/")
			status, e := a.router.get(ctx, path, &result)
			if e == nil && result.Delay > 0 {
				p.Status = "reachable"
				p.Delay = result.Delay
			} else if status != 503 && status != 504 {
				p.Status = "unknown"
			}
			if _, e = a.store.db.Exec(`INSERT INTO probes VALUES(?,?,?,?,?,?,?)`, p.Time, p.Batch, p.Domain, p.Route, p.Node, p.Status, p.Delay); e != nil {
				a.health("storage", false, "复测记录写入失败")
				return
			}
			a.publish()
		}
	}
}

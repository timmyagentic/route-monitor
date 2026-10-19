package routebridge

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestProbeConfigNeverTakesOverTraffic(t *testing.T) {
	runtime := map[string]any{"secret": "must-not-copy", "external-controller": "0.0.0.0:9999", "mixed-port": 17890, "tun": map[string]any{"enable": true}, "dns": map[string]any{"enable": true, "listen": ":1053", "nameserver": []any{"https://resolver.example/dns-query"}}, "routing-mark": 17894, "proxies": []any{map[string]any{"name": "jp", "type": "trojan", "password": "fixture"}, map[string]any{"name": "hk", "type": "trojan", "password": "fixture"}}}
	s := &Snapshot{Nodes: map[string]string{"JP": "jp", "HK": "hk"}}
	c, e := probeConfig(runtime, s, map[string]int{"DIRECT": 10001, "JP": 10002, "HK": 10003})
	if e != nil {
		t.Fatal(e)
	}
	for _, k := range []string{"secret", "external-controller", "tun", "mixed-port", "redir-port", "tproxy-port", "proxy-providers", "rule-providers", "sniffer"} {
		if _, ok := c[k]; ok {
			t.Fatal("copied", k)
		}
	}
	if c["routing-mark"] != 17894 || c["dns"].(map[string]any)["listen"] != "" {
		t.Fatal(c)
	}
	for _, v := range c["listeners"].([]any) {
		l := v.(map[string]any)
		if l["listen"] != "127.0.0.1" || l["udp"] != false || l["proxy"] == "" {
			t.Fatal(l)
		}
	}
	if runtime["proxies"].([]any)[0].(map[string]any)["name"] != "jp" {
		t.Fatal("mutated live config")
	}
}

func TestResolverRejectsPrivateMixedAndWrongQuestion(t *testing.T) {
	for _, kind := range []string{"public", "private", "mixed", "wrong-question", "nxdomain"} {
		t.Run(kind, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				var q dnsmessage.Message
				if q.Unpack(b) != nil {
					t.Fatal("query")
				}
				q.Response = true
				if kind == "wrong-question" {
					q.Questions[0].Name, _ = dnsmessage.NewName("another.example.")
				}
				if kind == "nxdomain" {
					q.RCode = dnsmessage.RCodeNameError
				} else {
					ips := [][4]byte{{1, 1, 1, 1}}
					if kind == "private" {
						ips = [][4]byte{{127, 0, 0, 1}}
					}
					if kind == "mixed" {
						ips = append(ips, [4]byte{10, 0, 0, 1})
					}
					for _, ip := range ips {
						q.Answers = append(q.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: ip}})
					}
				}
				out, _ := q.Pack()
				w.Header().Set("Content-Type", "application/dns-message")
				w.Write(out)
			}))
			defer srv.Close()
			ips, status := resolvePublic(context.Background(), srv.Client(), srv.URL, "api.example.com")
			if kind == "public" {
				if status != "ok" || len(ips) != 1 || !ips[0].Equal(net.ParseIP("1.1.1.1")) {
					t.Fatal(status, ips)
				}
			} else if status == "ok" {
				t.Fatal("unsafe DNS accepted", kind)
			}
		})
	}
}
func TestProxyClientKeepsTargetTLSVerification(t *testing.T) {
	c := proxyClient("http://127.0.0.1:19001", "api.example.com")
	tr := c.Transport.(*http.Transport)
	if tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.ServerName != "api.example.com" {
		t.Fatal("target certificate bypass")
	}
	if c.CheckRedirect(&http.Request{}, nil) != http.ErrUseLastResponse {
		t.Fatal("redirect followed")
	}
}

func TestReadinessWaitsForUsableTunnelRatherThanOpenPort(t *testing.T) {
	var calls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		req := r.Clone(r.Context())
		req.RequestURI = ""
		res, e := (&http.Transport{Proxy: nil}).RoundTrip(req)
		if e != nil {
			t.Error(e)
			w.WriteHeader(502)
			return
		}
		defer res.Body.Close()
		w.WriteHeader(res.StatusCode)
	}))
	defer proxy.Close()
	if e := awaitTunnel(context.Background(), proxy.URL); e != nil {
		t.Fatal(e)
	}
	if calls.Load() < 3 {
		t.Fatal("tunnel readiness was not checked")
	}
}
func TestRuleDeltaOnlyTouchesOneExactDomain(t *testing.T) {
	before := []string{"DOMAIN-SUFFIX,manual.example,DIRECT", "MATCH,DIRECT"}
	valid := []string{before[0], "DOMAIN,new.example,Proxies", before[1]}
	if ruleDelta(before, valid, "new.example") != nil || ruleDelta(valid, before, "new.example") != nil {
		t.Fatal("valid delta rejected")
	}
	for _, bad := range [][]string{{"MATCH,Proxies"}, {"DOMAIN-SUFFIX,new.example,Proxies", "MATCH,DIRECT"}, {before[0], "DOMAIN,new.example,Proxies", "DOMAIN,new.example,DIRECT", before[1]}, {"MATCH,DIRECT", before[0]}} {
		if ruleDelta(before, bad, "new.example") == nil {
			t.Fatal("accepted", bad)
		}
	}
}
func TestCoreReadbackIncludesPayloadAndDisabledState(t *testing.T) {
	rules := []string{"AND,((NETWORK,UDP),(DST-PORT,3478),(IP-CIDR,1.1.1.1/32)),DIRECT", "DOMAIN,api.example.com,Router-Device-Egress", "GEOIP,CN,DIRECT,no-resolve", "MATCH,DIRECT"}
	r, e := parseCoreRules(rules)
	if e != nil {
		t.Fatal(e)
	}
	if r[0].Payload != "((Network,udp) && (DstPort,3478) && (IPCIDR,1.1.1.1/32))" || r[2].Payload != "cn" {
		t.Fatal(r)
	}
	if !fileMatchesCore(rules, r) {
		t.Fatal("own rules")
	}
	r[1].Payload = "other.example"
	if fileMatchesCore(rules, r) {
		t.Fatal("payload mismatch ignored")
	}
	r, _ = parseCoreRules(rules)
	r[1].Extra.Disabled = true
	if fileMatchesCore(rules, r) {
		t.Fatal("disabled rule ignored")
	}
}
func TestReadinessDoesNotRetainLogs(t *testing.T) {
	r := &readiness{seen: map[string]bool{}, done: make(chan struct{})}
	for _, route := range []string{"DIRECT", "JP", "HK"} {
		r.Write([]byte("ignored sensitive log\nMixed(http+socks)[rm-" + route + "] proxy listen"))
		r.Write([]byte("ing at: 127.0.0.1:123\n"))
	}
	select {
	case <-r.done:
	default:
		t.Fatal("not ready")
	}
	if strings.Contains(r.buffer, "sensitive") {
		t.Fatal("kept logs")
	}
}
func TestCanonicalRulesHashAndLocalProtection(t *testing.T) {
	a, _ := Canonical(map[string]any{"b": 2, "a": []string{"中文", "a&b"}})
	if !bytes.Equal(a, []byte(`{"a":["中文","a&b"],"b":2}`)) {
		t.Fatal(string(a))
	}
	rules := []string{"AND,((SRC-IP-CIDR,192.168.1.1/32),(DOMAIN,subscription.example)),HK", "DOMAIN-SUFFIX,manual.example,DIRECT"}
	if !protectedByLocal(rules, "api.manual.example") || !protectedByLocal(rules, "subscription.example") || protectedByLocal(rules, "new.example") {
		t.Fatal("local rule protection")
	}
	if !reflect.DeepEqual(nonRules(map[string]any{"rules": []string{}, "dns": true}), map[string]any{"dns": true}) {
		t.Fatal("nonrules")
	}
}

func TestCompoundHumanRulesRemainProtected(t *testing.T) {
	for _, rule := range []string{
		"AND,((SRC-IP-CIDR,192.168.1.2/32),(DOMAIN-KEYWORD,example)),DIRECT",
		"AND,((NETWORK,TCP),(GEOSITE,private)),DIRECT",
		"OR,((SRC-IP-CIDR,192.168.1.2/32),(DOMAIN,other.example.com)),DIRECT",
		"NOT,((DOMAIN,other.example.com)),DIRECT",
	} {
		if !protectedByLocal([]string{rule}, "api.example.com") {
			t.Fatal(rule)
		}
	}
	if protectedByLocal([]string{"AND,((SRC-IP-CIDR,192.168.1.2/32),(DOMAIN,other.example.com)),DIRECT"}, "api.example.com") {
		t.Fatal("unrelated exact-domain AND blocked")
	}
}

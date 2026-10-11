package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLogClassificationUsesOnlyErrorReason(t *testing.T) {
	cases := []struct{ host, route, rule, reason, want string }{
		{"cloudflare-dns.com", "DIRECT", "Match/", "dial tcp 104.16.248.249:443: i/o timeout", "连接超时"},
		{"a.v.smtcdns.com", "DIRECT", "DomainSuffix/smtcdns.com", "dial tcp 1.2.3.4:443: connect: connection refused", "连接被拒绝"},
		{"certificate.example.com", "DNS-policy", "DomainSuffix/resolve.example", "dial tcp 1.2.3.4:443: connection reset by peer", "连接被重置"},
		{"resolve.example.com", "DIRECT", "Match/", "unexpected EOF", "连接失败（未分类）"},
		{"ok.example.com", "DIRECT", "Domain/dns.example", "dial tcp: lookup ok.example.com: no such host", "DNS 解析错误"},
		{"cloudflare-dns.com", "DIRECT", "Match/", "dial tcp cloudflare-dns.com:443: i/o timeout", "连接超时"},
		{"certificate.example.com", "DIRECT", "Match/", "dial tcp certificate.example.com:443: connect: connection refused", "连接被拒绝"},
		{"timeout.example.com", "DIRECT", "Match/", "dial tcp timeout.example.com:443: unexpected EOF", "连接失败（未分类）"},
		{"ok.example.com", "DIRECT", "Match/", "dns resolve failed: all DNS requests failed, first error: timeout", "DNS 解析错误"},
		{"ok.example.com", "DIRECT", "Match/", "lookup ok.example.com on 1.1.1.1:53: i/o timeout", "DNS 解析错误"},
		{"ok.example.com", "DIRECT", "Match/", "tls: failed to verify certificate: x509: certificate signed by unknown authority", "TLS 证书错误"},
		{"ok.example.com", "DIRECT", "Match/", "context deadline exceeded", "连接超时"},
	}
	for _, c := range cases {
		t.Run(c.host+"/"+c.want+"/"+c.reason, func(t *testing.T) {
			raw := "2026-10-11 [TCP] dial " + c.route + " (match " + c.rule + ") 192.168.31.95:1234 --> " + c.host + ":443 error: " + c.reason
			data, _ := json.Marshal(map[string]string{"type": "warning", "payload": raw})
			e, ok := parseLog(data, "case", time.Now().Unix())
			if !ok || e.Error != c.want {
				t.Fatalf("got %+v ok=%v; want %s", e, ok, c.want)
			}
			encoded, _ := json.Marshal(e)
			if strings.Contains(string(encoded), c.reason) {
				t.Fatal("raw error persisted")
			}
		})
	}
}

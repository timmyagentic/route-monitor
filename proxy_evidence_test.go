package main

import (
	"strings"
	"testing"
	"time"
)

func evidenceBatch() []Probe {
	ps := []Probe{}
	for _, route := range []string{"DIRECT", "JP", "HK"} {
		for i := 0; i < 3; i++ {
			status := "reachable"
			if route == "DIRECT" {
				status = "failed"
			}
			ps = append(ps, Probe{Batch: "a", Route: route, Node: route + "1", Status: status, Time: 100})
		}
	}
	return ps
}
func TestProxyEvidenceBoundaries(t *testing.T) {
	for _, mode := range []string{"both", "jp", "hk", "all-failed", "unknown-direct", "partial-proxy", "mixed-node", "mixed-batch", "incomplete", "new-incomplete", "direct-ok"} {
		t.Run(mode, func(t *testing.T) {
			ps := evidenceBatch()
			want := ""
			switch mode {
			case "both":
				want = "JP,HK"
			case "jp":
				for i := 6; i < 9; i++ {
					ps[i].Status = "failed"
				}
				want = "JP"
			case "hk":
				for i := 3; i < 6; i++ {
					ps[i].Status = "failed"
				}
				want = "HK"
			case "all-failed":
				for i := 3; i < 9; i++ {
					ps[i].Status = "failed"
				}
			case "unknown-direct":
				ps[0].Status = "unknown"
			case "partial-proxy":
				ps[3].Status = "failed"
				ps[6].Status = "unknown"
			case "mixed-node":
				ps[3].Node = "other"
				ps[6].Node = "other"
			case "mixed-batch":
				ps[3].Batch = "other"
				ps[6].Batch = "other"
			case "incomplete":
				ps = ps[:8]
			case "new-incomplete":
				ps = append(ps, Probe{Batch: "b", Route: "DIRECT", Status: "failed", Time: 101})
			case "direct-ok":
				ps[0].Status = "reachable"
			}
			p := proxyEvidence(ps)
			got := ""
			if p != nil {
				got = strings.Join(p.Routes, ",")
			}
			if got != want {
				t.Fatalf("got=%s want=%s", got, want)
			}
		})
	}
}
func TestProxyMarkSummaryAndHandledState(t *testing.T) {
	for _, route := range []string{"DIRECT", "JP"} {
		t.Run(route, func(t *testing.T) {
			a := newTestApp(t)
			now := time.Now().Unix()
			if e := a.store.put([]Event{{ID: "one", Domain: "example.com", Route: route, Kind: "error", Time: now}}); e != nil {
				t.Fatal(e)
			}
			for _, p := range evidenceBatch() {
				if _, e := a.store.db.Exec(`INSERT INTO probes VALUES(?,?,?,?,?,?,?)`, now, p.Batch, "example.com", p.Route, p.Node, p.Status, p.Delay); e != nil {
					t.Fatal(e)
				}
			}
			rows, _, e := a.store.summary()
			if e != nil || len(rows) != 1 {
				t.Fatal(rows, e)
			}
			r := rows[0]
			if r.ProxyEvidence == nil || strings.Join(r.ProxyEvidence.Routes, ",") != "JP,HK" || r.RecommendProxy != (route == "DIRECT") || !strings.Contains(r.Advice, "3/3") {
				t.Fatal(r)
			}
			if route == "DIRECT" && r.Priority != 3 {
				t.Fatal(r.Priority)
			}
			if route == "JP" && !strings.Contains(r.Advice, "无需重复") {
				t.Fatal(r.Advice)
			}
			if e = a.store.setHandled("example.com", 1, true, "测试处理原因"); e != nil {
				t.Fatal(e)
			}
			rows, _, e = a.store.summaryFor("handled")
			if e != nil || len(rows) != 1 || rows[0].ProxyEvidence == nil || !rows[0].Handled {
				t.Fatal(rows, e)
			}
		})
	}
}

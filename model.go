package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	_ "modernc.org/sqlite"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Event struct {
	ID, Domain, Source, Route, Rule, Kind, Error string
	Time                                         int64
}
type Row struct {
	Domain       string `json:"domain"`
	Seen         int64  `json:"seen"`
	Connections  int    `json:"connections"`
	Errors       int    `json:"errors"`
	DirectErrors int    `json:"directErrors"`
	Sources      string `json:"sources"`
	Routes       string `json:"routes"`
	Rules        string `json:"rules"`
	Advice       string `json:"advice"`
	Priority     int    `json:"priority"`
}
type Probe struct {
	Time   int64  `json:"time"`
	Batch  string `json:"batch"`
	Domain string `json:"domain"`
	Route  string `json:"route"`
	Node   string `json:"node"`
	Status string `json:"status"`
	Delay  int    `json:"delay"`
}
type Store struct {
	db        *sql.DB
	mu        sync.Mutex
	lastPrune int64
}

func openStore(path string) (*Store, error) {
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	_, e = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
 CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, domain TEXT NOT NULL, source TEXT, route TEXT, rule TEXT, kind TEXT, error TEXT, ts INTEGER);
 CREATE INDEX IF NOT EXISTS events_time ON events(ts);
 CREATE INDEX IF NOT EXISTS events_domain ON events(domain,ts);
 CREATE TABLE IF NOT EXISTS probes (ts INTEGER, batch TEXT, domain TEXT, route TEXT, node TEXT, status TEXT, delay INTEGER);
 CREATE INDEX IF NOT EXISTS probes_domain ON probes(domain,ts);`)
	if e != nil {
		db.Close()
		return nil, e
	}
	return &Store{db: db}, nil
}
func (s *Store) put(events []Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, v := range events {
		if _, e = tx.Exec(`INSERT INTO events VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`, v.ID, v.Domain, v.Source, v.Route, v.Rule, v.Kind, v.Error, v.Time); e != nil {
			return e
		}
	}
	now := time.Now().Unix()
	if now-s.lastPrune > 3600 {
		if _, e = tx.Exec(`DELETE FROM events WHERE ts<?`, now-7*86400); e != nil {
			return e
		}
		if _, e = tx.Exec(`DELETE FROM probes WHERE ts<?`, now-7*86400); e != nil {
			return e
		}
		s.lastPrune = now
	}
	return tx.Commit()
}
func (s *Store) probes(domain string) ([]Probe, error) {
	rows, e := s.db.Query(`SELECT ts,batch,domain,route,node,status,delay FROM probes WHERE domain=? AND ts>? ORDER BY ts DESC,rowid DESC LIMIT 90`, domain, time.Now().Unix()-86400)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	result := []Probe{}
	for rows.Next() {
		var p Probe
		if e = rows.Scan(&p.Time, &p.Batch, &p.Domain, &p.Route, &p.Node, &p.Status, &p.Delay); e != nil {
			return nil, e
		}
		result = append(result, p)
	}
	return result, rows.Err()
}
func advice(directErrors int, probes []Probe) (string, int) {
	batches := map[string]map[string][]Probe{}
	// Compare only within a completed batch; never combine results from different nodes/runs.
	for _, p := range probes {
		if batches[p.Batch] == nil {
			batches[p.Batch] = map[string][]Probe{}
		}
		batches[p.Batch][p.Route] = append(batches[p.Batch][p.Route], p)
	}
	latest := ""
	var latestTime int64
	for _, p := range probes {
		if p.Time > latestTime {
			latestTime = p.Time
			latest = p.Batch
		}
	}
	b := batches[latest]
	d := b["DIRECT"]
	if len(d) == 3 {
		allFail, allOK := true, true
		sumD := 0
		for _, p := range d {
			allFail = allFail && p.Status == "failed"
			allOK = allOK && p.Status == "reachable"
			sumD += p.Delay
		}
		for _, route := range []string{"JP", "HK"} {
			ps := b[route]
			ok := len(ps) == 3
			sumP := 0
			node := ""
			for _, p := range ps {
				ok = ok && p.Status == "reachable"
				sumP += p.Delay
				if node != "" && node != p.Node {
					ok = false
				}
				node = p.Node
			}
			if ok && allFail {
				return "建议检查代理规则：直连 3 次失败，" + route + " 3 次收到响应（需业务验证）", 3
			}
			if ok && allOK && sumD > sumP*3 && sumD-sumP > 3000 {
				return "可考虑代理：直连重复明显更慢，" + route + " 更快（仅 HEAD 探测）", 2
			}
		}
		if allOK {
			return "直连可收到响应，暂不建议仅凭连接记录改规则", 0
		}
		if allFail {
			return "直连探测失败；代理尚无稳定成功证据，暂不判定", 1
		}
	}
	if directErrors >= 3 {
		return "直连多次报错，建议三路复测；尚不能认定需要代理", 2
	}
	if directErrors > 0 {
		return "出现直连错误，继续观察或手动复测", 1
	}
	return "观察中 · 尚无足够证据建议改规则", 0
}
func (s *Store) summary() ([]Row, int, error) {
	rows, e := s.db.Query(`SELECT domain,MAX(ts),SUM(kind='connection'),SUM(kind='error'),SUM(kind='error' AND route='DIRECT'),GROUP_CONCAT(DISTINCT source),GROUP_CONCAT(DISTINCT route),GROUP_CONCAT(DISTINCT rule) FROM events WHERE ts>? AND domain<>'' GROUP BY domain ORDER BY SUM(kind='error') DESC,MAX(ts) DESC LIMIT 300`, time.Now().Unix()-86400)
	if e != nil {
		return nil, 0, e
	}
	result := []Row{}
	for rows.Next() {
		var r Row
		if e = rows.Scan(&r.Domain, &r.Seen, &r.Connections, &r.Errors, &r.DirectErrors, &r.Sources, &r.Routes, &r.Rules); e != nil {
			rows.Close()
			return nil, 0, e
		}
		result = append(result, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, 0, e
	}
	for i := range result {
		ps, e := s.probes(result[i].Domain)
		if e != nil {
			return nil, 0, e
		}
		result[i].Advice, result[i].Priority = advice(result[i].DirectErrors, ps)
		if !strings.Contains(","+result[i].Routes+",", ",DIRECT,") {
			if result[i].Priority >= 2 && len(ps) > 0 {
				result[i].Advice = "当前已走代理；复测差异不意味着还需添加代理规则"
				result[i].Priority = 0
			} else if result[i].Errors > 0 {
				result[i].Advice = "代理连接出现错误，建议检查当前节点或站点状态"
				result[i].Priority = 1
			}
		}
	}
	var unknown int
	e = s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE ts>? AND domain=''`, time.Now().Unix()-86400).Scan(&unknown)
	return result, unknown, e
}
func domainName(s string) string {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if len(s) > 253 || !strings.Contains(s, ".") || net.ParseIP(s) != nil {
		return ""
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return ""
			}
		}
	}
	return s
}
func errorClass(raw string) string {
	t := strings.ToLower(raw)
	switch {
	case strings.Contains(t, "certificate") || strings.Contains(t, "x509"):
		return "TLS 证书错误"
	case strings.Contains(t, "resolve") || strings.Contains(t, "dns") || strings.Contains(t, "no such host"):
		return "DNS 解析错误"
	case strings.Contains(t, "timeout") || strings.Contains(t, "deadline"):
		return "连接超时"
	case strings.Contains(t, "refused"):
		return "连接被拒绝"
	case strings.Contains(t, "reset"):
		return "连接被重置"
	default:
		return "连接失败（未分类）"
	}
}

var logLine = regexp.MustCompile(`\[(TCP|UDP)\]\s+dial\s+(.+?)\s+\(match\s+(.+?)\)\s+(\S+)\s+-->\s+(\S+)\s+error:`)

func parseLog(data []byte, id string, now int64) (Event, bool) {
	var l struct {
		Type    string `json:"type"`
		Payload string `json:"payload"`
	}
	if json.Unmarshal(data, &l) != nil || !(l.Type == "warning" || l.Type == "error") {
		return Event{}, false
	}
	m := logLine.FindStringSubmatch(l.Payload)
	if m == nil {
		return Event{}, false
	}
	host, _, e := net.SplitHostPort(m[5])
	if e != nil {
		return Event{}, false
	}
	source, _, _ := net.SplitHostPort(m[4])
	route := strings.TrimSpace(m[2])
	if route != "DIRECT" && route != "JP" && route != "HK" {
		route = "OTHER"
	}
	return Event{ID: id, Domain: domainName(host), Source: source, Route: route, Rule: m[3], Kind: "error", Error: errorClass(l.Payload), Time: now}, true
}
func snapshot(data []byte, now int64) ([]Event, error) {
	var snap struct {
		Connections []struct {
			ID       string `json:"id"`
			Metadata struct {
				Host      string `json:"host"`
				SourceIP  string `json:"sourceIP"`
				SniffHost string `json:"sniffHost"`
			} `json:"metadata"`
			Chains      []string `json:"chains"`
			Rule        string   `json:"rule"`
			RulePayload string   `json:"rulePayload"`
		} `json:"connections"`
	}
	if e := json.Unmarshal(data, &snap); e != nil {
		return nil, e
	}
	out := []Event{}
	for _, c := range snap.Connections {
		if c.ID == "" {
			continue
		}
		route := "OTHER"
		for _, v := range c.Chains {
			if v == "DIRECT" || v == "JP" || v == "HK" {
				route = v
			}
		}
		host := c.Metadata.Host
		if host == "" {
			host = c.Metadata.SniffHost
		}
		out = append(out, Event{ID: "conn:" + c.ID, Domain: domainName(host), Source: c.Metadata.SourceIP, Route: route, Rule: fmt.Sprintf("%s/%s", c.Rule, c.RulePayload), Kind: "connection", Time: now})
	}
	return out, nil
}

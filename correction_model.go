package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"route-monitor/internal/routebridge"
)

type CorrectionConfig struct {
	Mode       string   `json:"mode"` // off, observe, auto; no browser endpoint enables auto
	SSHConfig  string   `json:"sshConfig"`
	SSHHost    string   `json:"sshHost"`
	BridgePath string   `json:"bridgePath"`
	RulesURL   string   `json:"rulesURL,omitempty"`
	Profile    string   `json:"profile,omitempty"`
	TokenFile  string   `json:"tokenFile,omitempty"`
	HTTPProxy  string   `json:"httpProxy,omitempty"`
	Controls   []string `json:"controls"`
}

func (c CorrectionConfig) validate() error {
	if c.Mode == "" || c.Mode == "off" {
		return nil
	}
	if c.Mode != "observe" && c.Mode != "auto" {
		return errors.New("纠偏模式无效")
	}
	if !filepath.IsAbs(c.SSHConfig) || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`).MatchString(c.SSHHost) || !regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`).MatchString(c.BridgePath) || strings.Contains(c.BridgePath, "..") {
		return errors.New("纠偏需要现有 SSH 配置及绝对路径的路由器桥接程序")
	}
	if len(c.Controls) != 2 || c.Controls[0] == c.Controls[1] {
		return errors.New("需要两个不同的公网对照域名")
	}
	for _, d := range c.Controls {
		if !routebridge.ValidDomain(d) {
			return errors.New("对照域名格式错误")
		}
	}
	if c.RulesURL != "" {
		u, e := url.Parse(c.RulesURL)
		if e != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return errors.New("规则服务需要无凭据的 HTTPS 根地址")
		}
		if !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`).MatchString(c.Profile) || !filepath.IsAbs(c.TokenFile) {
			return errors.New("规则服务配置不完整")
		}
	}
	if c.HTTPProxy != "" {
		u, e := url.Parse(c.HTTPProxy)
		if e != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return errors.New("代理地址格式错误")
		}
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !(ip.IsPrivate() || ip.IsLoopback()) {
			return errors.New("纠偏管理请求代理必须是本机或局域网地址")
		}
	}
	if c.Mode == "auto" && c.RulesURL == "" {
		return errors.New("自动纠偏需要配置规则服务")
	}
	return nil
}

type Fault struct {
	Domain  string `json:"domain"`
	Source  string `json:"source"`
	Network string `json:"network"`
	Port    int    `json:"port"`
	Route   string `json:"route"`
	Error   string `json:"error"`
	Last    int64  `json:"last"`
	Count   int    `json:"count"`
}
type Evidence struct {
	Started  int64                `json:"started"`
	Finished int64                `json:"finished"`
	Snapshot routebridge.Snapshot `json:"snapshot"`
	Samples  []routebridge.Sample `json:"samples"`
}
type Decision struct {
	Action    string `json:"action,omitempty"`
	Code      string `json:"code"`
	Confirmed bool   `json:"confirmed"`
}

type AutomaticRule struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
	Action string `json:"action"`
	Reason string `json:"reason"`
	Active *bool  `json:"active,omitempty"`
}
type RuleState struct {
	Revision        int64           `json:"revision"`
	Release         string          `json:"release"`
	Automatic       []AutomaticRule `json:"automatic"`
	ManualRulesYAML string          `json:"manualRulesYaml"`
	Rules           []string        `json:"rules"`
	RulesHash       string          `json:"rulesHash"`
	NonRulesHash    string          `json:"nonRulesHash"`
}
type RuleRequest struct {
	Domain           string  `json:"domain"`
	Action           string  `json:"action"`
	RequestID        string  `json:"requestId"`
	ExpectedRuleID   *string `json:"expectedRuleId"`
	ExpectedRevision int64   `json:"expectedRevision"`
	ExpectedRelease  string  `json:"expectedRelease"`
	Reason           string  `json:"reason"`
	PreviewHash      string  `json:"previewHash,omitempty"`
}
type RulePreview struct {
	PreviewHash     string   `json:"previewHash"`
	BeforeRulesHash string   `json:"beforeRulesHash"`
	RulesHash       string   `json:"rulesHash"`
	NonRulesHash    string   `json:"nonRulesHash"`
	Rules           []string `json:"rules"`
}
type RuleReceipt struct {
	RequestID       string         `json:"requestId"`
	Domain          string         `json:"domain"`
	Action          string         `json:"action"`
	Release         string         `json:"release"`
	PreviousRelease string         `json:"previousRelease"`
	Revision        int64          `json:"revision"`
	Created         string         `json:"created"`
	Before          *AutomaticRule `json:"before"`
	After           *AutomaticRule `json:"after"`
	BeforeRulesHash string         `json:"beforeRulesHash"`
	RulesHash       string         `json:"rulesHash"`
	NonRulesHash    string         `json:"nonRulesHash"`
}
type Correction struct {
	ID                   string               `json:"id"`
	Fault                Fault                `json:"fault"`
	State                string               `json:"state"`
	Reason               string               `json:"reason"`
	Created              int64                `json:"created"`
	Updated              int64                `json:"updated"`
	Next                 int64                `json:"next"`
	Attempts             int                  `json:"attempts"`
	Evidence             []Evidence           `json:"evidence,omitempty"`
	Decision             Decision             `json:"decision"`
	Verification         []Evidence           `json:"verification,omitempty"`
	VerificationAttempts int                  `json:"verificationAttempts,omitempty"`
	Request              *RuleRequest         `json:"request,omitempty"`
	Preview              *RulePreview         `json:"-"`
	Receipt              *RuleReceipt         `json:"receipt,omitempty"`
	ApplyRequest         *routebridge.Request `json:"-"`
	AppliedAt            int64                `json:"appliedAt,omitempty"`
	ObservedAt           int64                `json:"observedAt,omitempty"`
	RollbackReceipt      *RuleReceipt         `json:"rollbackReceipt,omitempty"`
	Failures             int                  `json:"failures"`
	SentAt               int64                `json:"sentAt,omitempty"`
	Rollback             bool                 `json:"rollback"`
	LastError            int64                `json:"lastError"`
	RetryAfter           int64                `json:"retryAfter"`
}

// Private durable fields are stored explicitly but are not returned to the UI.
type savedCorrection struct {
	Correction
	Preview      *RulePreview         `json:"preview"`
	ApplyRequest *routebridge.Request `json:"applyRequest"`
}

type BridgeClient interface {
	Call(context.Context, routebridge.Request) (routebridge.Response, error)
}
type RuleClient interface {
	State(context.Context) (RuleState, error)
	Check(context.Context, RuleRequest) (RulePreview, error)
	Publish(context.Context, RuleRequest) (RuleReceipt, error)
	Receipt(context.Context, string) (*RuleReceipt, error)
}

func (s *Store) initCorrection() error {
	_, e := s.db.Exec(`CREATE TABLE IF NOT EXISTS event_transport(id TEXT PRIMARY KEY,network TEXT NOT NULL,port INTEGER NOT NULL,node TEXT NOT NULL,download INTEGER NOT NULL,seen INTEGER NOT NULL,started INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS correction_cases(domain TEXT PRIMARY KEY,id TEXT NOT NULL,state TEXT NOT NULL,next_at INTEGER NOT NULL,updated INTEGER NOT NULL,body TEXT NOT NULL);
 CREATE INDEX IF NOT EXISTS correction_due ON correction_cases(next_at);
 CREATE TABLE IF NOT EXISTS correction_history(id INTEGER PRIMARY KEY,case_id TEXT NOT NULL,ts INTEGER NOT NULL,state TEXT NOT NULL,reason TEXT NOT NULL,body TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS correction_operations(id TEXT PRIMARY KEY,domain TEXT NOT NULL,created INTEGER NOT NULL,rollback INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS correction_probes(id TEXT PRIMARY KEY,domain TEXT NOT NULL,started INTEGER NOT NULL,finished INTEGER NOT NULL DEFAULT 0,status TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS correction_settings(id INTEGER PRIMARY KEY,paused INTEGER NOT NULL);
 INSERT OR IGNORE INTO correction_settings VALUES(1,0);`)
	return e
}

// Only old budget waits on already-applied changes are resumed. Receipts,
// attempts and ordinary queues stay intact; the new reason makes this one-shot.
func (s *Store) resumeLegacyVerification(now int64) error {
	items, err := s.correctionRows(`SELECT body FROM correction_cases WHERE state='verifying'
 AND json_extract(body,'$.reason')='daily_limit'`)
	if err != nil {
		return err
	}
	for _, c := range items {
		if c.Receipt == nil || c.AppliedAt == 0 {
			continue
		}
		c.Next, c.Updated, c.Reason = now, now, "verification_resumed"
		// Retain known legacy attempts rather than granting a fresh budget.
		c.VerificationAttempts = max(c.VerificationAttempts, c.Failures, len(c.Verification))
		if err := s.saveCorrection(c); err != nil {
			return err
		}
	}
	return nil
}

func decodeCorrection(body string) (Correction, error) {
	var v savedCorrection
	e := json.Unmarshal([]byte(body), &v)
	v.Correction.Preview = v.Preview
	v.Correction.ApplyRequest = v.ApplyRequest
	return v.Correction, e
}
func (s *Store) correction(domain string) (Correction, error) {
	var body string
	e := s.db.QueryRow(`SELECT body FROM correction_cases WHERE domain=?`, domain).Scan(&body)
	if e != nil {
		return Correction{}, e
	}
	return decodeCorrection(body)
}
func (s *Store) corrections() ([]Correction, error) {
	return s.correctionRows(`SELECT body FROM correction_cases ORDER BY updated DESC LIMIT 100`)
}
func (s *Store) watchedCorrections() ([]Correction, error) {
	return s.correctionRows(`SELECT body FROM correction_cases WHERE state IN ('watching','confirmed')`)
}
func (s *Store) correctionRows(query string) ([]Correction, error) {
	rows, e := s.db.Query(query)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	result := []Correction{}
	for rows.Next() {
		var body string
		if e = rows.Scan(&body); e != nil {
			return nil, e
		}
		v, e := decodeCorrection(body)
		if e != nil {
			return nil, e
		}
		result = append(result, v)
	}
	return result, rows.Err()
}
func (s *Store) saveCorrection(c Correction) error {
	body, e := json.Marshal(savedCorrection{Correction: c, Preview: c.Preview, ApplyRequest: c.ApplyRequest})
	if e != nil {
		return e
	}
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	_, e = tx.Exec(`INSERT INTO correction_cases VALUES(?,?,?,?,?,?) ON CONFLICT(domain) DO UPDATE SET id=excluded.id,state=excluded.state,next_at=excluded.next_at,updated=excluded.updated,body=excluded.body`, c.Fault.Domain, c.ID, c.State, c.Next, c.Updated, string(body))
	if e != nil {
		return e
	}
	public, _ := json.Marshal(c)
	_, e = tx.Exec(`INSERT INTO correction_history(case_id,ts,state,reason,body) VALUES(?,?,?,?,?)`, c.ID, c.Updated, c.State, c.Reason, string(public))
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) correctionPaused() bool {
	var p bool
	if s.db.QueryRow(`SELECT paused FROM correction_settings WHERE id=1`).Scan(&p) != nil {
		return true
	}
	return p
}
func (s *Store) setCorrectionPaused(p bool) error {
	_, e := s.db.Exec(`UPDATE correction_settings SET paused=? WHERE id=1`, p)
	return e
}

func (s *Store) freshFaults(now time.Time, includeHandled bool) ([]Fault, error) {
	// Only transport metadata captured by this version participates. Old errors
	// are not retroactively promoted into automatic work after an upgrade.
	predicate := " AND (h.handled_revision IS NULL OR h.handled_revision<>h.error_revision)"
	if includeHandled {
		predicate = ""
	}
	rows, e := s.db.Query(`SELECT e.domain,e.source,t.network,t.port,e.route,e.error,MAX(e.ts),COUNT(*)
 FROM events e JOIN event_transport t ON t.id=e.id LEFT JOIN domain_handling h ON h.domain=e.domain
 WHERE e.kind='error' AND e.domain<>'' AND e.ts>? AND e.ts<=?`+predicate+`
 GROUP BY e.domain,e.source,t.network,t.port,e.route,e.error HAVING COUNT(*)>=2 ORDER BY CASE WHEN e.error='DNS 解析错误' THEN 1 ELSE 0 END,MAX(e.ts) DESC LIMIT 100`, now.Unix()-600, now.Unix())
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []Fault
	for rows.Next() {
		var f Fault
		if e = rows.Scan(&f.Domain, &f.Source, &f.Network, &f.Port, &f.Route, &f.Error, &f.Last, &f.Count); e != nil {
			return nil, e
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
func (s *Store) correctionDue(now int64) (Correction, error) {
	var body string
	e := s.db.QueryRow(`SELECT body FROM correction_cases WHERE next_at>0 AND next_at<=?`+s.correctionPauseFilter()+` ORDER BY CASE WHEN state IN ('publishing','applying','verifying','rollback') THEN 0 WHEN state IN ('confirming','probing','planning') THEN 1 ELSE 2 END,CASE WHEN json_extract(body,'$.fault.error')='DNS 解析错误' THEN 1 ELSE 0 END,next_at,updated LIMIT 1`, now).Scan(&body)
	if e != nil {
		return Correction{}, e
	}
	return decodeCorrection(body)
}
func (s *Store) nextCorrection() int64 {
	var next sql.NullInt64
	s.db.QueryRow(`SELECT MIN(next_at) FROM correction_cases WHERE next_at>0` + s.correctionPauseFilter()).Scan(&next)
	return next.Int64
}

func (s *Store) correctionPauseFilter() string {
	if s.correctionPaused() {
		return ` AND (json_extract(body,'$.receipt') IS NOT NULL OR COALESCE(json_extract(body,'$.sentAt'),0)>0)`
	}
	return ""
}

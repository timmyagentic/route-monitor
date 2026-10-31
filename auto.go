package main

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const autoWindow = 600
const autoSpacing = 180
const autoDaily = 12

var errNXDOMAIN = errors.New("域名不存在（NXDOMAIN），已跳过三路探测")
var autoZone = time.FixedZone("CST", 8*3600)

type AutoProbe struct {
	Domain   string `json:"domain"`
	Started  int64  `json:"started"`
	Finished int64  `json:"finished"`
	State    string `json:"state"`
	Reason   string `json:"reason"`
}
type AutoStatus struct {
	Used      int   `json:"used"`
	Limit     int   `json:"limit"`
	Threshold int   `json:"threshold"`
	Window    int   `json:"windowSeconds"`
	Spacing   int   `json:"spacingSeconds"`
	Next      int64 `json:"nextAllowed"`
}

func autoDay(now time.Time) time.Time {
	t := now.In(autoZone)
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, autoZone)
}
func (s *Store) autoProbe(domain string) (*AutoProbe, error) {
	p := &AutoProbe{Domain: domain}
	e := s.db.QueryRow(`SELECT started,finished,state,reason FROM auto_probes WHERE domain=?`, domain).Scan(&p.Started, &p.Finished, &p.State, &p.Reason)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	return p, e
}
func (s *Store) autoStatus(now time.Time) (AutoStatus, error) {
	p := AutoStatus{Limit: autoDaily, Threshold: 2, Window: autoWindow, Spacing: autoSpacing}
	var last int64
	e := s.db.QueryRow(`SELECT COALESCE(MAX(started),0),COUNT(CASE WHEN started>=? THEN 1 END) FROM auto_probes`, autoDay(now).Unix()).Scan(&last, &p.Used)
	if last > 0 {
		p.Next = last + autoSpacing
	}
	if p.Used >= autoDaily {
		p.Next = max(p.Next, autoDay(now).AddDate(0, 0, 1).Unix())
	}
	return p, e
}

// Claim before DNS or HEAD requests. The domain primary key survives all outcomes and pruning.
func (s *Store) claimAuto(now time.Time) (string, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.db.Begin()
	if e != nil {
		return "", time.Time{}, e
	}
	defer tx.Rollback()
	var last int64
	var used int
	e = tx.QueryRow(`SELECT COALESCE(MAX(started),0),COUNT(CASE WHEN started>=? THEN 1 END) FROM auto_probes`, autoDay(now).Unix()).Scan(&last, &used)
	if e != nil {
		return "", time.Time{}, e
	}
	next := last + autoSpacing
	if used >= autoDaily {
		next = max(next, autoDay(now).AddDate(0, 0, 1).Unix())
	}
	if next > now.Unix() {
		return "", time.Unix(next, 0), nil
	}
	var domain string
	e = tx.QueryRow(`SELECT r.domain FROM auto_recent_errors r
 JOIN domain_handling h ON h.domain=r.domain
 LEFT JOIN auto_probes p ON p.domain=r.domain
 WHERE p.domain IS NULL AND r.ts>? AND r.ts<=? AND r.revision>COALESCE(h.handled_revision,-1)
 GROUP BY r.domain HAVING COUNT(*)>=2 ORDER BY MIN(r.ts),r.domain LIMIT 1`, now.Unix()-autoWindow, now.Unix()).Scan(&domain)
	if errors.Is(e, sql.ErrNoRows) {
		return "", time.Time{}, nil
	}
	if e != nil {
		return "", time.Time{}, e
	}
	_, e = tx.Exec(`INSERT INTO auto_probes(domain,started,state) VALUES(?,?,'running')`, domain, now.Unix())
	if e != nil {
		return "", time.Time{}, e
	}
	if e = tx.Commit(); e != nil {
		return "", time.Time{}, e
	}
	return domain, time.Time{}, nil
}
func (s *Store) finishAuto(domain, state, reason string, now time.Time) error {
	_, e := s.db.Exec(`UPDATE auto_probes SET state=?,reason=?,finished=? WHERE domain=? AND state='running'`, state, reason, now.Unix(), domain)
	return e
}
func (s *Store) interruptAuto(now time.Time) error {
	_, e := s.db.Exec(`UPDATE auto_probes SET state='interrupted',reason='服务重启前未完成；不自动重试，可手动复测',finished=? WHERE state='running'`, now.Unix())
	return e
}
func (a *App) wakeAuto() {
	select {
	case a.autoWake <- struct{}{}:
	default:
	}
}
func (a *App) releaseProbe() {
	a.mu.Lock()
	a.probing = false
	a.probeDomain = ""
	a.mu.Unlock()
	a.publish()
	a.wakeAuto()
}

// Reserve the same slot as manual probes. Stream health gates all automatic network work.
func (a *App) reserveProbe(now time.Time, manualCooldown time.Duration) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.bulkRunning || a.probing || now.Sub(a.lastProbe) < manualCooldown || !a.states["connections"].Connected || !a.states["logs"].Connected || !a.states["storage"].Connected || now.Unix()-a.lastFrame["connections"] > 15 {
		return false
	}
	a.probing = true
	return true
}
func (a *App) autoLoop(ctx context.Context) {
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
			return
		case <-a.autoWake:
		}
		now := time.Now()
		if !a.reserveProbe(now, time.Minute) {
			continue
		}
		domain, next, e := a.store.claimAuto(now)
		if domain == "" {
			// Do not wake ourselves when there is no candidate.
			a.mu.Lock()
			a.probing = false
			a.mu.Unlock()
			if e != nil {
				a.health("storage", false, "自动复测状态写入失败")
				continue
			}
			if !next.IsZero() {
				timer := time.NewTimer(time.Until(next))
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
					a.wakeAuto()
				}
			}
			continue
		}
		a.mu.Lock()
		a.probeDomain = domain
		a.mu.Unlock()
		a.publish()
		a.executeAuto(ctx, domain)
	}
}
func (a *App) executeAuto(ctx context.Context, domain string) {
	state, reason := "completed", "三路复测已完成；不会自动重复"
	pre, cancel := context.WithTimeout(ctx, 10*time.Second)
	e := a.safeTarget(pre, domain)
	var nodes map[string]string
	if e == nil {
		nodes, e = a.nodes(pre)
	}
	cancel()
	if e != nil {
		state = "skipped"
		reason = e.Error()
		a.releaseProbe()
	} else if e = a.runProbe(ctx, domain, nodes); e != nil {
		state = "failed"
		reason = e.Error()
	}
	if ctx.Err() != nil {
		state = "interrupted"
		reason = "服务停止，复测未完成；不自动重试"
	}
	if e = a.store.finishAuto(domain, state, reason, time.Now()); e != nil {
		a.health("storage", false, "自动复测结果写入失败")
	}
	a.publish()
}

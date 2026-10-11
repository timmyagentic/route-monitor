package main

import (
	"context"
	"database/sql"
	"time"
)

type BulkStatus struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	Total     int    `json:"total"`
	Done      int    `json:"done"`
	Completed int    `json:"completed"`
	Skipped   int    `json:"skipped"`
	Failed    int    `json:"failed"`
	Current   string `json:"current"`
}
type BulkItem struct {
	Domain string `json:"domain"`
	State  string `json:"state"`
	Reason string `json:"reason"`
}

func (s *Store) initBulk() error {
	_, e := s.db.Exec(`CREATE TABLE IF NOT EXISTS bulk_jobs(id TEXT PRIMARY KEY,started INTEGER,finished INTEGER NOT NULL DEFAULT 0,state TEXT);
 CREATE UNIQUE INDEX IF NOT EXISTS one_bulk_running ON bulk_jobs(state) WHERE state='running';
 CREATE TABLE IF NOT EXISTS bulk_items(job TEXT,domain TEXT,position INTEGER,state TEXT,reason TEXT NOT NULL DEFAULT '',PRIMARY KEY(job,domain));`)
	return e
}

const completedProbeSQL = `EXISTS(SELECT 1 FROM probe_batches b WHERE b.domain=e.domain AND b.state='completed') OR EXISTS(SELECT 1 FROM probes p LEFT JOIN probe_batches b ON b.batch=p.batch WHERE p.domain=e.domain GROUP BY p.batch HAVING COUNT(*)=3*COALESCE(MAX(b.samples),3) AND SUM(p.route='DIRECT')=COALESCE(MAX(b.samples),3) AND SUM(p.route='JP')=COALESCE(MAX(b.samples),3) AND SUM(p.route='HK')=COALESCE(MAX(b.samples),3) AND (MAX(b.state) IS NULL OR MAX(b.state)='completed'))`

func (s *Store) recoverBulk() error {
	_, e := s.db.Exec(`UPDATE probe_batches SET state='interrupted' WHERE state='running';UPDATE bulk_items SET state='pending' WHERE state='running'`)
	return e
}
func (s *Store) createBulk() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.db.Begin()
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	id := randomID()
	_, e = tx.Exec(`INSERT INTO bulk_jobs(id,started,state) VALUES(?,?,'running')`, id, time.Now().Unix())
	if e != nil {
		return "", e
	}
	_, e = tx.Exec(`INSERT INTO bulk_items(job,domain,position,state) SELECT ?,e.domain,ROW_NUMBER() OVER(ORDER BY SUM(e.kind='error') DESC,MAX(e.ts) DESC,e.domain),'pending' FROM events e LEFT JOIN domain_handling h ON h.domain=e.domain WHERE e.ts>? AND e.domain<>'' AND (h.handled_revision IS NULL OR h.handled_revision<>h.error_revision) AND NOT (`+completedProbeSQL+`) GROUP BY e.domain HAVING SUM(e.kind='error')>0`, id, time.Now().Unix()-86400)
	if e != nil {
		return "", e
	}
	return id, tx.Commit()
}
func (s *Store) bulkStatus() *BulkStatus {
	b := &BulkStatus{}
	if e := s.db.QueryRow(`SELECT id,state FROM bulk_jobs ORDER BY started DESC,rowid DESC LIMIT 1`).Scan(&b.ID, &b.State); e != nil {
		return nil
	}
	s.db.QueryRow(`SELECT COUNT(*),COALESCE(SUM(state IN('completed','skipped','failed')),0),COALESCE(SUM(state='completed'),0),COALESCE(SUM(state='skipped'),0),COALESCE(SUM(state='failed'),0),COALESCE(MAX(CASE WHEN state='running' THEN domain END),'') FROM bulk_items WHERE job=?`, b.ID).Scan(&b.Total, &b.Done, &b.Completed, &b.Skipped, &b.Failed, &b.Current)
	return b
}
func (s *Store) bulkResults() any {
	status := s.bulkStatus()
	items := []BulkItem{}
	if status != nil {
		rows, e := s.db.Query(`SELECT domain,state,reason FROM bulk_items WHERE job=? ORDER BY position`, status.ID)
		if e == nil {
			defer rows.Close()
			for rows.Next() {
				var x BulkItem
				if rows.Scan(&x.Domain, &x.State, &x.Reason) == nil {
					items = append(items, x)
				}
			}
		}
	}
	return map[string]any{"status": status, "items": items}
}
func (a *App) resumeBulk(ctx context.Context) {
	var id string
	if a.store.db.QueryRow(`SELECT id FROM bulk_jobs WHERE state='running'`).Scan(&id) == nil {
		a.bulkRunning = true
		go a.runBulk(ctx, id)
	}
}
func (a *App) bulkEligible(domain string) (bool, error) {
	var ok bool
	e := a.store.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM events e LEFT JOIN domain_handling h ON h.domain=e.domain WHERE e.domain=? AND e.ts>? AND e.kind='error' AND (h.handled_revision IS NULL OR h.handled_revision<>h.error_revision) AND NOT (`+completedProbeSQL+`))`, domain, time.Now().Unix()-86400).Scan(&ok)
	return ok, e
}
func (a *App) runBulk(ctx context.Context, id string) {
	defer func() { a.mu.Lock(); a.bulkRunning = false; a.mu.Unlock(); a.publish(); a.wakeAuto() }()
	for ctx.Err() == nil {
		var domain string
		e := a.store.db.QueryRow(`SELECT domain FROM bulk_items WHERE job=? AND state='pending' ORDER BY position LIMIT 1`, id).Scan(&domain)
		if e == sql.ErrNoRows {
			a.store.db.Exec(`UPDATE bulk_jobs SET state='completed',finished=? WHERE id=?`, time.Now().Unix(), id)
			return
		}
		if e != nil {
			a.health("storage", false, "批量复测读取失败")
			return
		}
		a.mu.Lock()
		healthy := a.states["connections"].Connected && a.states["logs"].Connected && a.states["storage"].Connected && time.Now().Unix()-a.lastFrame["connections"] <= 15
		a.mu.Unlock()
		if !healthy {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
				continue
			}
		}
		ok, e := a.bulkEligible(domain)
		state, reason := "completed", "每路两次复测已完成"
		if e != nil {
			a.health("storage", false, "批量资格读取失败")
			return
		}
		if !ok {
			state = "skipped"
			reason = "已无最近24小时真实错误、已处理或已有完整复测"
		} else {
			if _, e = a.store.db.Exec(`UPDATE bulk_items SET state='running' WHERE job=? AND domain=?`, id, domain); e != nil {
				a.health("storage", false, "批量状态保存失败")
				return
			}
			a.mu.Lock()
			a.probing = true
			a.probeDomain = domain
			a.mu.Unlock()
			a.publish()
			pre, cancel := context.WithTimeout(ctx, 10*time.Second)
			e = a.safeTarget(pre, domain)
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
		}
		if ctx.Err() != nil {
			return
		}
		if _, e = a.store.db.Exec(`UPDATE bulk_items SET state=?,reason=? WHERE job=? AND domain=?`, state, reason, id, domain); e != nil {
			a.health("storage", false, "批量结果保存失败")
			return
		}
		a.publish()
	}
}

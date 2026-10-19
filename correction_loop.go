package main

import (
	"context"
	"time"
)

func (a *App) correctionState() map[string]any {
	mode := a.cfg.Correction.Mode
	if mode == "" {
		mode = "off"
	}
	rows, err := a.store.corrections()
	if err != nil {
		return map[string]any{"mode": mode, "error": "读取纠偏记录失败"}
	}
	views := make([]map[string]any, 0, len(rows))
	for _, c := range rows {
		views = append(views, map[string]any{"id": c.ID, "domain": c.Fault.Domain, "source": c.Fault.Source, "network": c.Fault.Network, "port": c.Fault.Port, "route": c.Fault.Route, "state": c.State, "reason": correctionReason(c.Reason), "reasonCode": c.Reason, "decision": c.Decision, "updated": c.Updated, "next": c.Next, "appliedAt": c.AppliedAt, "observedAt": c.ObservedAt, "receipt": c.Receipt, "rollbackReceipt": c.RollbackReceipt, "evidence": c.Evidence, "verification": c.Verification})
	}
	return map[string]any{"mode": mode, "paused": a.store.correctionPaused(), "cases": views, "dailyProbeLimit": correctionDailyProbes, "dailyChangeLimit": correctionDailyChanges, "rulesConfigured": a.cfg.Correction.RulesURL != ""}
}

func (a *App) correctionLoop(ctx context.Context) {
	var timer *time.Timer
	var due <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
			return
		case <-a.autoWake:
		case <-due:
		}
		if timer != nil {
			timer.Stop()
			timer = nil
			due = nil
		}
		if !a.reserveAuto(time.Now()) {
			continue
		}
		_, err := a.correction.Step(ctx)
		a.mu.Lock()
		a.probing = false
		a.probeDomain = ""
		a.mu.Unlock()
		// Do not wake this loop from its own status update.
		a.mu.Lock()
		if err != nil {
			a.states["correction"] = Health{false, "纠偏状态保存失败，未继续发布"}
		} else {
			a.states["correction"] = Health{true, ""}
		}
		a.mu.Unlock()
		a.publish()
		// A single timer serves persisted due work. There is no new router or
		// cloud polling loop; new faults arrive through the existing streams.
		next := a.store.nextCorrection()
		if next > 0 {
			delay := time.Until(time.Unix(next, 0))
			if delay < time.Second {
				delay = time.Second
			}
			timer = time.NewTimer(delay)
			due = timer.C
		}
	}
}

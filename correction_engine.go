package main

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"

	"route-monitor/internal/routebridge"
)

type correctionEngine struct {
	mu     sync.Mutex
	store  *Store
	config CorrectionConfig
	bridge BridgeClient
	rules  RuleClient
	now    func() time.Time
}

func (e *correctionEngine) save(c *Correction, state, reason string, next int64) error {
	c.State, c.Reason, c.Next, c.Updated = state, reason, next, e.now().Unix()
	return e.store.saveCorrection(*c)
}
func (e *correctionEngine) deferError(c *Correction, reason string) error {
	c.Failures++
	if c.Failures >= 3 {
		return e.save(c, "attention", reason, 0)
	}
	return e.save(c, c.State, reason, e.now().Unix()+int64(c.Failures)*60)
}
func (e *correctionEngine) closeCase(c *Correction, state, reason string, seconds int64) error {
	c.RetryAfter = e.now().Unix() + seconds
	return e.save(c, state, reason, 0)
}

func (e *correctionEngine) discover() error {
	now := e.now()
	faults, err := e.store.freshFaults(now, false)
	if err != nil {
		return err
	}
	for _, f := range faults {
		c, err := e.store.correction(f.Domain)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil {
			// Owned changes are rechecked below; another device cannot launch a
			// competing rule transaction for this same domain.
			if (c.Receipt != nil && c.State != "rolled_back") || c.Next > 0 || c.RetryAfter > now.Unix() || f.Last <= c.LastError || c.State == "attention" {
				continue
			}
		}
		c = Correction{ID: randomID(), Fault: f, Created: now.Unix(), LastError: f.Last}
		if reason := eligibleFault(f); reason != "" {
			if err = e.closeCase(&c, "blocked", reason, 6*3600); err != nil {
				return err
			}
			continue
		}
		if err = e.save(&c, "queued", "awaiting_evidence", now.Unix()); err != nil {
			return err
		}
	}
	return nil
}

func (e *correctionEngine) watch() error {
	items, err := e.store.watchedCorrections()
	if err != nil {
		return err
	}
	faults, err := e.store.freshFaults(e.now(), true)
	if err != nil {
		return err
	}
	for _, c := range items {
		if c.State != "watching" && c.State != "confirmed" {
			continue
		}
		var seen sql.NullInt64
		want := c.Decision.Action
		if err = e.store.db.QueryRow(`SELECT MAX(t.seen) FROM events v JOIN event_transport t ON t.id=v.id
 WHERE v.domain=? AND v.source=? AND v.kind='connection' AND t.started>? AND t.started<=t.seen AND t.network='tcp' AND t.port=443 AND t.download>0
 AND ((?='DIRECT' AND v.route='DIRECT') OR (?='PROXY' AND v.route IN ('JP','HK')))`, c.Fault.Domain, c.Fault.Source, c.AppliedAt, want, want).Scan(&seen); err != nil {
			return err
		}
		if seen.Valid && c.ObservedAt == 0 {
			c.ObservedAt = seen.Int64
			if err = e.save(&c, "confirmed", "confirmed", 0); err != nil {
				return err
			}
		}
		for _, f := range faults {
			if f.Domain != c.Fault.Domain || f.Last <= c.AppliedAt || f.Last <= c.LastError || eligibleFault(f) != "" {
				continue
			}
			if want == "PROXY" && f.Route == "DIRECT" || want == "DIRECT" && f.Route != "DIRECT" {
				continue
			}
			c.LastError = f.Last
			c.Verification = nil
			c.Failures = 0
			if err = e.save(&c, "verifying", "verification_failed", e.now().Unix()); err != nil {
				return err
			}
			break
		}
	}
	return nil
}

func (e *correctionEngine) probeBudget() (bool, int64, error) {
	var count int
	var last int64
	err := e.store.db.QueryRow(`SELECT COUNT(CASE WHEN started>=? THEN 1 END),COALESCE(MAX(started),0) FROM correction_probes`, autoDay(e.now()).Unix()).Scan(&count, &last)
	if err != nil {
		return false, 0, err
	}
	if count >= correctionDailyProbes {
		return false, autoDay(e.now()).AddDate(0, 0, 1).Unix(), nil
	}
	if last+autoSpacing > e.now().Unix() {
		return false, last + autoSpacing, nil
	}
	return true, 0, nil
}
func (e *correctionEngine) runProbe(ctx context.Context, c *Correction) (*Evidence, error) {
	id := randomID()
	started := e.now().Unix()
	if _, err := e.store.db.Exec(`INSERT INTO correction_probes VALUES(?,?,?,0,'running')`, id, c.Fault.Domain, started); err != nil {
		return nil, err
	}
	snapshot, err := e.bridge.Call(ctx, routebridge.Request{Operation: "inspect"})
	if err != nil || snapshot.Snapshot == nil {
		e.store.db.Exec(`UPDATE correction_probes SET finished=?,status='failed' WHERE id=?`, e.now().Unix(), id)
		return nil, correctionError{errorCode(err, "bridge_unavailable")}
	}
	result, err := e.bridge.Call(ctx, routebridge.Request{Operation: "probe", ID: id, Domain: c.Fault.Domain, Port: 443, Controls: e.config.Controls, ExpectedSnapshot: snapshot.Snapshot.ID})
	status := "completed"
	if err != nil {
		status = "failed"
	}
	if _, dbErr := e.store.db.Exec(`UPDATE correction_probes SET finished=?,status=? WHERE id=?`, e.now().Unix(), status, id); dbErr != nil {
		return nil, dbErr
	}
	if err != nil {
		return nil, err
	}
	if result.Snapshot == nil || result.Snapshot.ID != snapshot.Snapshot.ID {
		return nil, correctionError{"snapshot_changed"}
	}
	if c.Receipt != nil && !c.Rollback && !routebridge.AutomaticRuleActive(*result.Snapshot, c.Fault.Domain, c.Decision.Action) {
		return nil, correctionError{"local_rule_protected"}
	}
	compact := *result.Snapshot
	compact.RuntimeRules = nil
	compact.RawRules = nil
	compact.LocalRules = nil
	compact.DeviceRules = nil
	return &Evidence{Started: started, Finished: e.now().Unix(), Snapshot: compact, Samples: result.Samples}, nil
}

func (e *correctionEngine) testCase(ctx context.Context, c *Correction) error {
	faults, err := e.store.freshFaults(e.now(), false)
	if err != nil {
		return err
	}
	fresh := false
	for _, f := range faults {
		if f.Domain == c.Fault.Domain && f.Source == c.Fault.Source && f.Network == c.Fault.Network && f.Port == c.Fault.Port && f.Route == c.Fault.Route && f.Error == c.Fault.Error {
			c.Fault, c.LastError, fresh = f, f.Last, true
			break
		}
	}
	if !fresh {
		return e.closeCase(c, "resolved", "no_recent_fault", 600)
	}
	ok, next, err := e.probeBudget()
	if err != nil {
		return err
	}
	if !ok {
		return e.save(c, c.State, "daily_limit", next)
	}
	if err = e.save(c, "probing", "awaiting_evidence", e.now().Unix()+90); err != nil {
		return err
	}
	ev, err := e.runProbe(ctx, c)
	c.Attempts++
	if err != nil {
		c.State = "queued"
		return e.deferError(c, errorCode(err, "bridge_unavailable"))
	}
	c.Failures = 0
	if len(c.Evidence) > 0 && (c.Evidence[len(c.Evidence)-1].Snapshot.ID != ev.Snapshot.ID || e.now().Unix()-c.Evidence[len(c.Evidence)-1].Finished > correctionEvidenceAge) {
		c.Evidence = nil
	}
	c.Evidence = append(c.Evidence, *ev)
	if len(c.Evidence) > 2 {
		c.Evidence = c.Evidence[len(c.Evidence)-2:]
	}
	c.Decision = assessEvidence(c.Fault, c.Evidence, e.config.Controls, e.now().Unix())
	if c.Decision.Action == "" {
		cooldown := int64(1800)
		if c.Decision.Code == "no_public_resolution" {
			cooldown = correctionCooldown
		} else if c.Decision.Code == "all_paths_failed" {
			cooldown = 6 * 3600
		}
		return e.closeCase(c, "inconclusive", c.Decision.Code, cooldown)
	}
	if !c.Decision.Confirmed {
		return e.save(c, "confirming", "awaiting_confirmation", ev.Finished+correctionConfirmDelay)
	}
	if err = e.save(c, "planning", "checking_change", e.now().Unix()); err != nil {
		return err
	}
	return e.prepareChange(ctx, c)
}

func (e *correctionEngine) prepareChange(ctx context.Context, c *Correction) error {
	if !c.Rollback {
		var pending int
		if err := e.store.db.QueryRow(`SELECT COUNT(*) FROM correction_cases WHERE domain<>? AND
 (state IN ('publishing','applying','verifying','rollback') OR (state='attention' AND
 (json_extract(body,'$.receipt') IS NOT NULL OR json_extract(body,'$.reason')='publish_unknown')))`, c.Fault.Domain).Scan(&pending); err != nil {
			return err
		}
		if pending > 0 {
			return e.save(c, "planning", "another_change_pending", e.now().Unix()+autoSpacing)
		}
	}
	if e.rules == nil {
		return e.closeCase(c, "suggested", "rules_not_configured", 3600)
	}
	s, err := e.rules.State(ctx)
	if err != nil {
		return e.deferError(c, errorCode(err, "cloud_unavailable"))
	}
	snap, err := e.bridge.Call(ctx, routebridge.Request{Operation: "inspect"})
	if err != nil || snap.Snapshot == nil {
		return e.deferError(c, errorCode(err, "bridge_unavailable"))
	}
	if !c.Rollback && (len(c.Evidence) == 0 || snap.Snapshot.ID != c.Evidence[len(c.Evidence)-1].Snapshot.ID || e.now().Unix()-c.Evidence[0].Finished > correctionEvidenceAge) {
		c.Evidence = nil
		return e.save(c, "queued", "configuration_changed", e.now().Unix()+autoSpacing)
	}
	routerAtBase := snap.Snapshot.RawRulesHash == s.RulesHash
	if c.Rollback && c.Receipt != nil && snap.Snapshot.RawRulesHash == c.Receipt.BeforeRulesHash {
		routerAtBase = true
	}
	if !routerAtBase || snap.Snapshot.RawNonRulesHash != s.NonRulesHash {
		return e.closeCase(c, "attention", "subscription_drift", 0)
	}
	action := c.Decision.Action
	var expected *string
	var owned *AutomaticRule
	for _, r := range s.Automatic {
		if r.Domain == c.Fault.Domain {
			copy := r
			owned = &copy
			break
		}
	}
	if c.Rollback {
		if c.Receipt == nil || c.Receipt.After == nil || owned == nil || owned.ID != c.Receipt.After.ID {
			return e.save(c, "attention", "manual_intervention", 0)
		}
		action = "REMOVE"
		expected = &owned.ID
	} else if owned != nil {
		return e.save(c, "attention", "manual_intervention", 0)
	}
	if !c.Rollback && e.config.Mode == "auto" {
		var n int
		if err = e.store.db.QueryRow(`SELECT COUNT(*) FROM correction_operations WHERE rollback=0 AND created>=?`, autoDay(e.now()).Unix()).Scan(&n); err != nil {
			return err
		}
		if n >= correctionDailyChanges {
			c.Evidence = nil
			return e.save(c, "queued", "daily_limit", autoDay(e.now()).AddDate(0, 0, 1).Unix())
		}
	}
	r := RuleRequest{Domain: c.Fault.Domain, Action: action, RequestID: randomID(), ExpectedRuleID: expected, ExpectedRevision: s.Revision, ExpectedRelease: s.Release, Reason: "network-difference"}
	if c.Rollback {
		r.Reason = "regression"
	}
	p, err := e.rules.Check(ctx, r)
	if err != nil {
		return e.closeCase(c, "blocked", errorCode(err, "cloud_unavailable"), 3600)
	}
	if p.BeforeRulesHash != s.RulesHash || p.NonRulesHash != s.NonRulesHash || p.RulesHash != routebridge.Hash(p.Rules) {
		return e.save(c, "attention", "cloud_invalid_response", 0)
	}
	r.PreviewHash = p.PreviewHash
	apply := routebridge.Request{Operation: "prepare", ID: r.RequestID, Domain: r.Domain, Action: r.Action, ExpectedSnapshot: snap.Snapshot.ID, ExpectedRulesHash: snap.Snapshot.RawRulesHash, ExpectedNonRulesHash: s.NonRulesHash, DesiredRulesHash: p.RulesHash, Rules: p.Rules}
	if _, err = e.bridge.Call(ctx, apply); err != nil {
		return e.closeCase(c, "blocked", errorCode(err, "apply_failed"), 3600)
	}
	apply.Operation = "apply"
	c.Request = &r
	c.Preview = &p
	c.ApplyRequest = &apply
	c.Failures = 0
	c.SentAt = 0
	if e.config.Mode != "auto" {
		return e.closeCase(c, "suggested", "observe_only", 3600)
	}
	return e.save(c, "publishing", "ready_to_publish", e.now().Unix())
}

func receiptMatches(r RuleRequest, p RulePreview, receipt RuleReceipt) bool {
	return receipt.RequestID == r.RequestID && receipt.Domain == r.Domain && receipt.Action == r.Action && receipt.PreviousRelease == r.ExpectedRelease && receipt.BeforeRulesHash == p.BeforeRulesHash && receipt.RulesHash == p.RulesHash && receipt.NonRulesHash == p.NonRulesHash && receipt.Release != ""
}
func (e *correctionEngine) publishChange(ctx context.Context, c *Correction) error {
	if e.config.Mode != "auto" {
		return e.save(c, "attention", "publish_unknown", 0)
	}
	if c.Request == nil || c.Preview == nil || c.ApplyRequest == nil {
		return e.save(c, "attention", "invalid_operation", 0)
	}
	if e.store.correctionPaused() && c.SentAt == 0 && !c.Rollback {
		return nil
	}
	receipt, err := e.rules.Receipt(ctx, c.Request.RequestID)
	if err != nil {
		return e.deferError(c, "publish_unknown")
	}
	if receipt == nil {
		state, err := e.rules.State(ctx)
		if err != nil {
			return e.deferError(c, "publish_unknown")
		}
		if state.Revision != c.Request.ExpectedRevision || state.Release != c.Request.ExpectedRelease {
			return e.save(c, "attention", "cloud_conflict", 0)
		}
		if !c.Rollback && (len(c.Evidence) == 0 || e.now().Unix()-c.Evidence[0].Finished > correctionEvidenceAge) {
			return e.save(c, "attention", "stale_evidence", 0)
		}
		if c.SentAt == 0 {
			if e.store.correctionPaused() && !c.Rollback {
				return nil
			}
			// Persist intent before the external request. A restart retries the
			// same request ID, including if its first response was lost.
			c.SentAt = e.now().Unix()
			if err = e.save(c, "publishing", "publish_unknown", e.now().Unix()); err != nil {
				return err
			}
		}
		if _, err = e.store.db.Exec(`INSERT OR IGNORE INTO correction_operations VALUES(?,?,?,?)`, c.Request.RequestID, c.Fault.Domain, c.SentAt, c.Rollback); err != nil {
			return err
		}
		value, err := e.rules.Publish(ctx, *c.Request)
		if err != nil {
			return e.deferError(c, "publish_unknown")
		}
		receipt = &value
	}
	if !receiptMatches(*c.Request, *c.Preview, *receipt) {
		return e.save(c, "attention", "cloud_invalid_response", 0)
	}
	if c.Rollback {
		c.RollbackReceipt = receipt
	} else {
		c.Receipt = receipt
	}
	c.Failures = 0
	return e.save(c, "applying", "published", e.now().Unix())
}

func (e *correctionEngine) applyChange(ctx context.Context, c *Correction) error {
	if e.config.Mode != "auto" {
		return e.save(c, "attention", "manual_intervention", 0)
	}
	receipt := c.Receipt
	if c.Rollback {
		receipt = c.RollbackReceipt
	}
	if receipt == nil || c.ApplyRequest == nil {
		return e.save(c, "attention", "invalid_operation", 0)
	}
	current, err := e.rules.State(ctx)
	if err != nil {
		return e.deferError(c, "cloud_unavailable")
	}
	if current.Release != receipt.Release || current.RulesHash != receipt.RulesHash {
		return e.save(c, "attention", "manual_intervention", 0)
	}
	result, err := e.bridge.Call(ctx, *c.ApplyRequest)
	if err != nil {
		// A lost SSH response is not proof that apply failed. Repeat the same
		// request ID; the bridge recovers its journal or returns its receipt.
		code := errorCode(err, "bridge_unavailable")
		if code == "bridge_unavailable" || code == "configuration_busy" {
			return e.deferError(c, code)
		}
		if !c.Rollback && (code == "snapshot_changed" || code == "subscription_drift" || code == "local_rule_protected" || code == "non_rules_changed" || code == "generation_failed" || code == "core_validation_failed" || code == "interrupted_apply_rolled_back" || code == "apply_failed_rolled_back" || code == "readback_failed_rolled_back" || code == "commit_failed_rolled_back" || code == "verification_failed_rolled_back" || code == "receipt_failed_rolled_back") {
			// Known failed/no-op applies leave the previous runtime intact. The
			// owned cloud rule can be withdrawn without restoring other rules.
			c.Rollback = true
			c.Request = nil
			c.Preview = nil
			c.ApplyRequest = nil
			c.Failures = 0
			return e.save(c, "rollback", "apply_failed", e.now().Unix())
		}
		return e.save(c, "attention", code, 0)
	}
	if !result.Applied || result.Snapshot == nil || result.Snapshot.RawRulesHash != receipt.RulesHash {
		return e.save(c, "attention", "apply_failed", 0)
	}
	c.AppliedAt = e.now().Unix()
	c.Verification = nil
	c.Failures = 0
	c.ApplyRequest = nil
	c.Preview = nil
	if c.Rollback {
		return e.closeCase(c, "rolled_back", "rolled_back", correctionCooldown)
	}
	return e.save(c, "verifying", "applied", e.now().Unix()+autoSpacing)
}

func usableFor(action string, ev Evidence) bool {
	routes := map[string]bool{"DIRECT": action == "DIRECT", "JP": action == "PROXY", "HK": action == "PROXY"}
	counts := map[string]int{}
	for _, s := range ev.Samples {
		if s.Control || !routes[s.Route] {
			continue
		}
		if s.Status != "response" || s.HTTPStatus < 200 || s.HTTPStatus >= 400 {
			return false
		}
		counts[s.Route]++
	}
	for route, want := range routes {
		if want && counts[route] != 2 {
			return false
		}
	}
	return true
}
func (e *correctionEngine) verifyChange(ctx context.Context, c *Correction) error {
	ok, next, err := e.probeBudget()
	if err != nil {
		return err
	}
	if !ok {
		return e.save(c, "verifying", "daily_limit", next)
	}
	ev, err := e.runProbe(ctx, c)
	if err != nil {
		return e.deferError(c, errorCode(err, "bridge_unavailable"))
	}
	state, err := e.rules.State(ctx)
	if err != nil {
		return e.deferError(c, "cloud_unavailable")
	}
	want := c.Decision.Action
	receipt := c.Receipt
	if c.Rollback {
		receipt = c.RollbackReceipt
		want = "PROXY"
		if c.Fault.Route == "DIRECT" {
			want = "DIRECT"
		}
	}
	ownership := false
	if receipt != nil && receipt.After != nil {
		for _, r := range state.Automatic {
			if r.ID == receipt.After.ID && r.Domain == c.Fault.Domain && r.Action == c.Decision.Action && r.Active != nil && *r.Active {
				ownership = true
			}
		}
	}
	if c.Rollback {
		ownership = receipt != nil && state.Release == receipt.Release
	}
	if receipt == nil || ev.Snapshot.RawRulesHash != state.RulesHash || !ownership {
		return e.save(c, "attention", "manual_intervention", 0)
	}
	if usableFor(want, *ev) {
		c.Verification = append(c.Verification, *ev)
		if c.Rollback {
			return e.closeCase(c, "rolled_back", "rolled_back", correctionCooldown)
		}
		return e.save(c, "watching", "watching", 0)
	}
	if c.Rollback {
		return e.save(c, "attention", "verification_failed", 0)
	}
	if len(c.Verification) > 0 && (c.Verification[len(c.Verification)-1].Snapshot.ID != ev.Snapshot.ID || e.now().Unix()-c.Verification[len(c.Verification)-1].Finished > correctionEvidenceAge) {
		c.Verification = nil
	}
	c.Verification = append(c.Verification, *ev)
	if len(c.Verification) > 2 {
		c.Verification = c.Verification[len(c.Verification)-2:]
	}
	f := c.Fault
	if want == "PROXY" {
		f.Route = "HK"
	} else {
		f.Route = "DIRECT"
	}
	d := assessEvidence(f, c.Verification, e.config.Controls, e.now().Unix())
	if d.Confirmed && d.Action != "" && d.Action != want {
		c.Rollback = true
		c.Request = nil
		c.Preview = nil
		c.ApplyRequest = nil
		c.Failures = 0
		return e.save(c, "rollback", "rollback", e.now().Unix())
	}
	c.Failures++
	if c.Failures >= 3 {
		return e.save(c, "attention", "verification_failed", 0)
	}
	return e.save(c, "verifying", "verification_failed", ev.Finished+correctionConfirmDelay)
}

func (e *correctionEngine) Step(ctx context.Context) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.config.Mode == "off" || e.config.Mode == "" {
		return false, nil
	}
	paused := e.store.correctionPaused()
	if !paused {
		if err := e.watch(); err != nil {
			return false, err
		}
		if err := e.discover(); err != nil {
			return false, err
		}
	}
	c, err := e.store.correctionDue(e.now().Unix())
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if paused && c.Receipt == nil && c.SentAt == 0 {
		return false, nil
	}
	switch c.State {
	case "queued", "confirming":
		return true, e.testCase(ctx, &c)
	case "probing":
		return true, e.save(&c, "queued", "interrupted", e.now().Unix()+autoSpacing)
	case "publishing":
		return true, e.publishChange(ctx, &c)
	case "applying":
		return true, e.applyChange(ctx, &c)
	case "verifying":
		return true, e.verifyChange(ctx, &c)
	case "rollback":
		return true, e.prepareChange(ctx, &c)
	case "planning":
		return true, e.prepareChange(ctx, &c)
	default:
		return true, e.save(&c, "attention", "invalid_operation", 0)
	}
}

func (e *correctionEngine) Retry(domain, id string) error {
	if !e.mu.TryLock() {
		return correctionError{"correction_busy"}
	}
	defer e.mu.Unlock()
	c, err := e.store.correction(domain)
	if err != nil {
		return err
	}
	if c.ID != id {
		return correctionError{"case_changed"}
	}
	if c.State != "attention" && c.State != "blocked" && c.State != "inconclusive" && c.State != "suggested" {
		return correctionError{"case_not_retryable"}
	}
	c.Failures = 0
	if c.Request != nil && c.SentAt > 0 && ((!c.Rollback && c.Receipt == nil) || (c.Rollback && c.RollbackReceipt == nil)) {
		return e.save(&c, "publishing", "publish_unknown", e.now().Unix())
	}
	if c.Receipt != nil {
		if c.Rollback && c.RollbackReceipt == nil {
			return e.save(&c, "rollback", "rollback", e.now().Unix())
		}
		if c.ApplyRequest != nil {
			return e.save(&c, "applying", "applying", e.now().Unix())
		}
		if c.AppliedAt > 0 {
			return e.save(&c, "verifying", "verification_failed", e.now().Unix())
		}
	}
	if c.Request != nil && c.Reason == "publish_unknown" {
		return e.save(&c, "publishing", "publish_unknown", e.now().Unix())
	}
	c.Request = nil
	c.Preview = nil
	c.ApplyRequest = nil
	c.Evidence = nil
	c.SentAt = 0
	if faults, err := e.store.freshFaults(e.now(), true); err == nil {
		for _, f := range faults {
			if f.Domain == domain && f.Source == c.Fault.Source && eligibleFault(f) == "" {
				c.Fault = f
				c.LastError = f.Last
				break
			}
		}
	}
	return e.save(&c, "queued", "awaiting_evidence", e.now().Unix())
}

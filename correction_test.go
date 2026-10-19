package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"route-monitor/internal/routebridge"
)

var testControls = []string{"control-a.example", "control-b.example"}

func sampleEvidence(at int64, domain string, direct, proxy string) Evidence {
	e := Evidence{Started: at, Finished: at, Snapshot: routebridge.Snapshot{ID: "same-config", Nodes: map[string]string{"DIRECT": "DIRECT", "JP": "jp", "HK": "hk"}, NodeHashes: map[string]string{"DIRECT": "DIRECT", "JP": "jp-hash", "HK": "hk-hash"}}}
	for _, route := range []string{"DIRECT", "JP", "HK"} {
		for _, d := range testControls {
			e.Samples = append(e.Samples, routebridge.Sample{Route: route, NodeHash: e.Snapshot.NodeHashes[route], Domain: d, Control: true, Round: 1, Stage: "http", Status: "response", HTTPStatus: 200, Time: at})
		}
		for i := 1; i <= 2; i++ {
			status := proxy
			if route == "DIRECT" {
				status = direct
			}
			s := routebridge.Sample{Route: route, NodeHash: e.Snapshot.NodeHashes[route], Domain: domain, Round: i, Status: status, Time: at, Stage: "connect", DNSStatus: "ok"}
			if status == "response" {
				s.Stage = "http"
				s.HTTPStatus = 200
			}
			e.Samples = append(e.Samples, s)
		}
	}
	return e
}
func testFault(at int64, route string) Fault {
	return Fault{Domain: "api.example.com", Source: "192.168.1.2", Network: "tcp", Port: 443, Route: route, Error: "连接超时", Last: at, Count: 2}
}

func TestBidirectionalEvidenceNeedsSeparateStableHealthyRounds(t *testing.T) {
	for _, direction := range []string{"PROXY", "DIRECT"} {
		t.Run(direction, func(t *testing.T) {
			at := time.Now().Unix()
			route, d, p := "DIRECT", "failed", "response"
			if direction == "DIRECT" {
				route, d, p = "JP", "response", "failed"
			}
			f := testFault(at, route)
			a := sampleEvidence(at, f.Domain, d, p)
			b := sampleEvidence(at+181, f.Domain, d, p)
			got := assessEvidence(f, []Evidence{a, b}, testControls, at+181)
			if !got.Confirmed || got.Action != direction {
				t.Fatal(got)
			}
			if assessEvidence(f, []Evidence{a}, testControls, at).Confirmed {
				t.Fatal("one round promoted")
			}
			for _, bad := range []string{"too-close", "stale", "changed", "unhealthy-control", "403", "unknown", "wrong-port", "wrong-protocol", "wrong-node", "wrong-domain", "duplicate-round", "mixed-exits"} {
				t.Run(bad, func(t *testing.T) {
					fa := f
					ea := sampleEvidence(at, f.Domain, d, p)
					eb := sampleEvidence(at+181, f.Domain, d, p)
					now := at + 181
					switch bad {
					case "too-close":
						eb.Started = at + 10
					case "stale":
						now += 901
					case "changed":
						eb.Snapshot.ID = "new-config"
					case "unhealthy-control":
						eb.Samples[0].Status = "failed"
					case "403":
						for i := range eb.Samples {
							if !eb.Samples[i].Control && eb.Samples[i].Status == "response" {
								eb.Samples[i].HTTPStatus = 403
							}
						}
					case "unknown":
						eb.Samples[2].Status = "unknown"
					case "wrong-port":
						fa.Port = 5223
					case "wrong-protocol":
						fa.Network = "udp"
					case "wrong-node":
						eb.Samples[6].NodeHash = "changed-node"
					case "wrong-domain":
						eb.Samples[2].Domain = "other.example"
					case "duplicate-round":
						eb.Samples[3].Round = 1
					case "mixed-exits":
						for i := range eb.Samples {
							if eb.Samples[i].Route == "HK" && !eb.Samples[i].Control {
								if p == "failed" {
									eb.Samples[i].Status = "response"
									eb.Samples[i].HTTPStatus = 200
									eb.Samples[i].Stage = "http"
								} else {
									eb.Samples[i].Status = "failed"
									eb.Samples[i].HTTPStatus = 0
									eb.Samples[i].Stage = "connect"
								}
							}
						}
					}
					if got := assessEvidence(fa, []Evidence{ea, eb}, testControls, now); got.Confirmed {
						t.Fatal("unsafe promotion", bad, got)
					}
				})
			}
		})
	}
}

type fakeCorrectionBridge struct {
	clock         *time.Time
	rules         []string
	direct, proxy string
	applied       map[string]routebridge.Response
	applyCalls    int
	lostApply     bool
	failApply     string
	prepareFail   bool
	localRules    []string
}

func (b *fakeCorrectionBridge) snapshot() *routebridge.Snapshot {
	h := routebridge.Hash(b.rules)
	return &routebridge.Snapshot{ID: h, RawRulesHash: h, RawRules: b.rules, RawNonRulesHash: "non-rules", RuntimeRules: b.rules, LocalRules: b.localRules, Nodes: map[string]string{"DIRECT": "DIRECT", "JP": "jp", "HK": "hk"}, NodeHashes: map[string]string{"DIRECT": "DIRECT", "JP": "jp-hash", "HK": "hk-hash"}}
}
func (b *fakeCorrectionBridge) Call(_ context.Context, r routebridge.Request) (routebridge.Response, error) {
	s := b.snapshot()
	switch r.Operation {
	case "inspect":
		return routebridge.Response{OK: true, Snapshot: s}, nil
	case "probe":
		ev := sampleEvidence(b.clock.Unix(), r.Domain, b.direct, b.proxy)
		ev.Snapshot = *s
		return routebridge.Response{OK: true, Snapshot: s, Samples: ev.Samples}, nil
	case "prepare":
		if b.prepareFail {
			return routebridge.Response{}, correctionError{"local_rule_protected"}
		}
		if r.ExpectedRulesHash != s.RawRulesHash {
			return routebridge.Response{}, correctionError{"subscription_drift"}
		}
		return routebridge.Response{OK: true, Snapshot: s}, nil
	case "apply":
		if old, ok := b.applied[r.ID]; ok {
			return old, nil
		}
		if b.failApply != "" {
			code := b.failApply
			b.failApply = ""
			return routebridge.Response{}, correctionError{code}
		}
		if r.ExpectedRulesHash != s.RawRulesHash {
			return routebridge.Response{}, correctionError{"subscription_drift"}
		}
		b.rules = append([]string{}, r.Rules...)
		b.applyCalls++
		out := routebridge.Response{OK: true, Applied: true, ID: r.ID, Snapshot: b.snapshot()}
		b.applied[r.ID] = out
		if b.lostApply {
			b.lostApply = false
			return routebridge.Response{}, correctionError{"bridge_unavailable"}
		}
		return out, nil
	}
	return routebridge.Response{}, errors.New("unexpected bridge operation")
}

type fakeCorrectionRules struct {
	s           RuleState
	receipts    map[string]RuleReceipt
	publishes   int
	losePublish bool
	conflict    bool
	stateError  bool
}

func (r *fakeCorrectionRules) State(context.Context) (RuleState, error) {
	if r.stateError {
		return RuleState{}, correctionError{"cloud_unavailable"}
	}
	return r.s, nil
}
func (r *fakeCorrectionRules) Check(_ context.Context, q RuleRequest) (RulePreview, error) {
	if r.conflict || q.ExpectedRevision != r.s.Revision || q.ExpectedRelease != r.s.Release {
		return RulePreview{}, correctionError{"cloud_conflict"}
	}
	rules := []string{}
	for _, rule := range r.s.Rules {
		if !strings.HasPrefix(rule, "DOMAIN,"+q.Domain+",") {
			rules = append(rules, rule)
		}
	}
	if q.Action != "REMOVE" {
		target := "Proxies"
		if q.Action == "DIRECT" {
			target = "DIRECT"
		}
		rules = append([]string{"DOMAIN," + q.Domain + "," + target}, rules...)
	}
	return RulePreview{PreviewHash: "preview", BeforeRulesHash: r.s.RulesHash, RulesHash: routebridge.Hash(rules), NonRulesHash: r.s.NonRulesHash, Rules: rules}, nil
}
func (r *fakeCorrectionRules) Publish(ctx context.Context, q RuleRequest) (RuleReceipt, error) {
	if old, ok := r.receipts[q.RequestID]; ok {
		return old, nil
	}
	p, e := r.Check(ctx, q)
	if e != nil {
		return RuleReceipt{}, e
	}
	receipt := RuleReceipt{RequestID: q.RequestID, Domain: q.Domain, Action: q.Action, Release: "release-" + q.RequestID, PreviousRelease: r.s.Release, Revision: r.s.Revision + 1, BeforeRulesHash: p.BeforeRulesHash, RulesHash: p.RulesHash, NonRulesHash: p.NonRulesHash}
	var next []AutomaticRule
	for _, v := range r.s.Automatic {
		if v.Domain != q.Domain {
			next = append(next, v)
		} else {
			copy := v
			receipt.Before = &copy
		}
	}
	if q.Action != "REMOVE" {
		active := true
		v := AutomaticRule{ID: q.RequestID, Domain: q.Domain, Action: q.Action, Active: &active}
		receipt.After = &v
		next = append(next, v)
	}
	r.s.Revision++
	r.s.Release = receipt.Release
	r.s.Rules = p.Rules
	r.s.RulesHash = p.RulesHash
	r.s.Automatic = next
	r.receipts[q.RequestID] = receipt
	r.publishes++
	if r.losePublish {
		r.losePublish = false
		return RuleReceipt{}, correctionError{"cloud_unavailable"}
	}
	return receipt, nil
}
func (r *fakeCorrectionRules) Receipt(_ context.Context, id string) (*RuleReceipt, error) {
	if v, ok := r.receipts[id]; ok {
		return &v, nil
	}
	return nil, nil
}

func correctionFixture(t *testing.T, mode string) (*correctionEngine, *fakeCorrectionBridge, *fakeCorrectionRules, *time.Time) {
	t.Helper()
	s := newTestApp(t).store
	clock := time.Now().Add(-time.Minute)
	rules := []string{"MATCH,DIRECT"}
	b := &fakeCorrectionBridge{clock: &clock, rules: rules, direct: "failed", proxy: "response", applied: map[string]routebridge.Response{}}
	r := &fakeCorrectionRules{s: RuleState{Revision: 1, Release: "base", Rules: rules, RulesHash: routebridge.Hash(rules), NonRulesHash: "non-rules"}, receipts: map[string]RuleReceipt{}}
	e := &correctionEngine{store: s, config: CorrectionConfig{Mode: mode, Controls: testControls}, bridge: b, rules: r, now: func() time.Time { return clock }}
	putCorrectionFault(t, s, clock, "DIRECT")
	return e, b, r, &clock
}
func putCorrectionFault(t *testing.T, s *Store, at time.Time, route string) {
	t.Helper()
	for i := 0; i < 2; i++ {
		if e := s.put([]Event{{ID: randomID(), Domain: "api.example.com", Source: "192.168.1.2", Route: route, Network: "tcp", Port: 443, Error: "连接超时", Kind: "error", Time: at.Unix()}}); e != nil {
			t.Fatal(e)
		}
	}
}
func correctionStep(t *testing.T, e *correctionEngine) Correction {
	t.Helper()
	if _, err := e.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	c, err := e.store.correction("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func advance(t *testing.T, e *correctionEngine, clock *time.Time, seconds int) Correction {
	t.Helper()
	*clock = clock.Add(time.Duration(seconds) * time.Second)
	return correctionStep(t, e)
}

func TestCorrectionObservationNeverPublishesAndKeepsEvidenceAcrossRestart(t *testing.T) {
	e, b, r, clock := correctionFixture(t, "observe")
	if c := correctionStep(t, e); c.State != "confirming" {
		t.Fatal(c.State, c.Reason)
	}
	c := advance(t, e, clock, 181)
	if c.State != "suggested" || c.Reason != "observe_only" || !c.Decision.Confirmed || r.publishes != 0 || b.applyCalls != 0 {
		t.Fatal(c.State, c.Reason, r.publishes, b.applyCalls)
	}
	if c.Preview == nil || c.ApplyRequest == nil || len(c.Evidence) != 2 {
		t.Fatal("durable prepared state lost")
	}
	encoded, _ := json.Marshal(c)
	if strings.Contains(string(encoded), "applyRequest") || strings.Contains(string(encoded), "\"rules\":[") {
		t.Fatal("private payload in view")
	}
}

func TestCorrectionPublishApplyRecoveryAndRegressionRollback(t *testing.T) {
	e, b, r, clock := correctionFixture(t, "auto")
	correctionStep(t, e)
	c := advance(t, e, clock, 181)
	if c.State != "publishing" {
		t.Fatal(c.State, c.Reason)
	}
	r.losePublish = true
	c = correctionStep(t, e)
	if c.State != "publishing" || r.publishes != 1 {
		t.Fatal(c.State, r.publishes)
	}
	c = advance(t, e, clock, 61)
	if c.State != "applying" || r.publishes != 1 {
		t.Fatal(c.State, r.publishes)
	}
	b.lostApply = true
	c = correctionStep(t, e)
	if c.State != "applying" || b.applyCalls != 1 {
		t.Fatal(c.State)
	}
	c = advance(t, e, clock, 61)
	if c.State != "verifying" || b.applyCalls != 1 {
		t.Fatal(c.State)
	}
	c = advance(t, e, clock, 181)
	if c.State != "watching" {
		t.Fatal(c.State, c.Reason)
	}
	if err := e.store.put([]Event{{ID: "conn:after", Domain: c.Fault.Domain, Source: c.Fault.Source, Network: "tcp", Port: 443, Route: "JP", Download: 100, Kind: "connection", Time: clock.Unix(), StartedAt: clock.Unix()}}); err != nil {
		t.Fatal(err)
	}
	c = correctionStep(t, e)
	if c.State != "confirmed" || c.ObservedAt == 0 {
		t.Fatal(c.State)
	}
	*clock = clock.Add(181 * time.Second)
	b.direct, b.proxy = "response", "failed"
	putCorrectionFault(t, e.store, *clock, "JP")
	c = correctionStep(t, e)
	if c.State != "verifying" {
		t.Fatal(c.State, c.Reason)
	}
	c = advance(t, e, clock, 181)
	if c.State != "rollback" {
		t.Fatal(c.State, c.Reason)
	}
	for range 3 {
		c = correctionStep(t, e)
	}
	if c.State != "rolled_back" || r.publishes != 2 || b.applyCalls != 2 || len(r.s.Automatic) != 0 || len(b.rules) != 1 {
		t.Fatal(c.State, c.Reason, r.publishes, b.applyCalls, r.s.Automatic, b.rules)
	}
	putCorrectionFault(t, e.store, *clock, "DIRECT")
	c = correctionStep(t, e)
	if c.State != "rolled_back" {
		t.Fatal("cooldown ignored")
	}
}

func TestCorrectionKnownApplyFailureWithdrawsOnlyOwnedCloudRule(t *testing.T) {
	e, b, r, clock := correctionFixture(t, "auto")
	correctionStep(t, e)
	advance(t, e, clock, 181)
	correctionStep(t, e)
	b.failApply = "generation_failed"
	c := correctionStep(t, e)
	if c.State != "rollback" {
		t.Fatal(c.State, c.Reason)
	}
	for range 3 {
		c = correctionStep(t, e)
	}
	if c.State != "rolled_back" || len(r.s.Automatic) != 0 || len(b.rules) != 1 {
		t.Fatal(c.State, c.Reason, r.s)
	}
}

func TestCorrectionConflictPreparationAndPausePreventNewWrites(t *testing.T) {
	for _, mode := range []string{"manual", "local", "pause"} {
		t.Run(mode, func(t *testing.T) {
			e, b, r, clock := correctionFixture(t, "auto")
			correctionStep(t, e)
			if mode == "manual" {
				r.conflict = true
			}
			if mode == "local" {
				b.prepareFail = true
			}
			if mode == "pause" {
				e.store.setCorrectionPaused(true)
			}
			c := advance(t, e, clock, 181)
			if r.publishes != 0 || b.applyCalls != 0 {
				t.Fatal("unexpected write")
			}
			if mode != "pause" && c.State != "blocked" {
				t.Fatal(c.State)
			}
		})
	}
}

func TestFaultTriggerDoesNotCombineDevicesPortsOrOldHistory(t *testing.T) {
	s := newTestApp(t).store
	now := time.Now()
	for i, v := range []Event{{Source: "192.168.1.2", Network: "tcp", Port: 443}, {Source: "192.168.1.3", Network: "tcp", Port: 443}, {Source: "192.168.1.2", Network: "udp", Port: 443}, {Source: "192.168.1.2", Network: "tcp", Port: 5223}, {Source: "192.168.1.2"}} {
		v.ID = fmt.Sprint(i)
		v.Domain = "api.example.com"
		v.Route = "DIRECT"
		v.Kind = "error"
		v.Time = now.Unix()
		if err := s.put([]Event{v}); err != nil {
			t.Fatal(err)
		}
	}
	f, e := s.freshFaults(now, false)
	if e != nil || len(f) != 0 {
		t.Fatal(f, e)
	}
}

func TestBridgeConfigurationRejectsShellAndCredentialURLs(t *testing.T) {
	base := CorrectionConfig{Mode: "auto", SSHConfig: filepath.Join(t.TempDir(), "ssh"), SSHHost: "router", BridgePath: "/tmp/route-bridge", RulesURL: "https://rules.example", Profile: "home", TokenFile: filepath.Join(t.TempDir(), "token"), Controls: testControls}
	if e := base.validate(); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*CorrectionConfig){func(c *CorrectionConfig) { c.SSHHost = "-oProxyCommand=evil" }, func(c *CorrectionConfig) { c.BridgePath = "/tmp/bridge; echo bad" }, func(c *CorrectionConfig) { c.RulesURL = "https://name:password@rules.example" }, func(c *CorrectionConfig) { c.HTTPProxy = "http://public.example:80" }, func(c *CorrectionConfig) { c.Controls[0] = "private.lan" }} {
		c := base
		c.Controls = append([]string{}, base.Controls...)
		change(&c)
		if c.validate() == nil {
			t.Fatal(c)
		}
	}
}

func TestCorrectionPauseAPIRequiresAuthenticationAndOrigin(t *testing.T) {
	a := newTestApp(t)
	a.correction = &correctionEngine{}
	for _, origin := range []string{"", "http://evil.example"} {
		req := httptest.NewRequest(http.MethodPost, "http://localhost:9780/api/correction/pause", strings.NewReader(`{"paused":true}`))
		req.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		a.handler().ServeHTTP(w, req)
		if w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
}

func TestCorrectionPauseBeforeSendAndAfterUncertainSend(t *testing.T) {
	e, b, r, clock := correctionFixture(t, "auto")
	correctionStep(t, e)
	c := advance(t, e, clock, 181)
	if c.State != "publishing" || c.SentAt != 0 {
		t.Fatal(c.State, c.SentAt)
	}
	e.store.setCorrectionPaused(true)
	correctionStep(t, e)
	if r.publishes != 0 || e.store.nextCorrection() != 0 {
		t.Fatal("paused prepared request was sent or busy-looped")
	}
	e.store.setCorrectionPaused(false)
	r.losePublish = true
	c = correctionStep(t, e)
	if c.SentAt == 0 || r.publishes != 1 {
		t.Fatal("missing durable intent")
	}
	e.store.setCorrectionPaused(true)
	c = advance(t, e, clock, 61)
	if c.State != "applying" {
		t.Fatal(c.State)
	}
	correctionStep(t, e)
	c = advance(t, e, clock, 181)
	if c.State != "watching" || r.publishes != 1 || b.applyCalls != 1 {
		t.Fatal(c.State, r.publishes, b.applyCalls)
	}
}

func TestCorrectionQueueRefreshAndExpiredEvidence(t *testing.T) {
	for _, scenario := range []string{"fresh-queue", "expired-queue", "expired-confirmation"} {
		t.Run(scenario, func(t *testing.T) {
			e, _, _, clock := correctionFixture(t, "auto")
			if scenario == "expired-confirmation" {
				correctionStep(t, e)
			} else if err := e.discover(); err != nil {
				t.Fatal(err)
			}
			*clock = clock.Add(901 * time.Second)
			if scenario != "expired-queue" {
				putCorrectionFault(t, e.store, *clock, "DIRECT")
			}
			c := correctionStep(t, e)
			if scenario == "expired-queue" {
				if c.State != "resolved" {
					t.Fatal(c.State)
				}
				return
			}
			if c.State != "confirming" || len(c.Evidence) != 1 || c.Fault.Last != clock.Unix() {
				t.Fatal(c.State, len(c.Evidence), c.Fault.Last)
			}
		})
	}
}

func TestCorrectionPlanningRetryDoesNotRepeatProbe(t *testing.T) {
	e, _, r, clock := correctionFixture(t, "auto")
	correctionStep(t, e)
	r.stateError = true
	c := advance(t, e, clock, 181)
	if c.State != "planning" {
		t.Fatal(c.State)
	}
	r.stateError = false
	c = advance(t, e, clock, 61)
	if c.State != "publishing" || c.Attempts != 2 {
		t.Fatal(c.State, c.Attempts)
	}
}

func TestCorrectionVerificationOwnershipAndLocalOverrides(t *testing.T) {
	for _, scenario := range []string{"unrelated-release", "manual-mask", "local-mask"} {
		t.Run(scenario, func(t *testing.T) {
			e, b, r, clock := correctionFixture(t, "auto")
			correctionStep(t, e)
			advance(t, e, clock, 181)
			correctionStep(t, e)
			correctionStep(t, e)
			r.s.Release = "later-unrelated-release"
			r.s.Revision++
			if scenario == "manual-mask" {
				active := false
				r.s.Automatic[0].Active = &active
			}
			if scenario == "local-mask" {
				b.localRules = []string{"DOMAIN-SUFFIX,example.com,DIRECT"}
			}
			c := advance(t, e, clock, 181)
			if scenario == "unrelated-release" {
				if c.State != "watching" {
					t.Fatal(c.State, c.Reason)
				}
			} else if c.State == "watching" || c.State == "confirmed" {
				t.Fatal("masked rule reported active")
			}
		})
	}
}

func TestConfirmationQueueHasPriorityAndOldOwnedRulesStayWatched(t *testing.T) {
	e, _, _, clock := correctionFixture(t, "auto")
	if err := e.discover(); err != nil {
		t.Fatal(err)
	}
	c, _ := e.store.correction("api.example.com")
	confirmed := c
	confirmed.Fault.Domain = "confirm.example.com"
	confirmed.ID = randomID()
	confirmed.State = "confirming"
	if err := e.store.saveCorrection(confirmed); err != nil {
		t.Fatal(err)
	}
	due, err := e.store.correctionDue(clock.Unix())
	if err != nil || due.ID != confirmed.ID {
		t.Fatal(due.ID, err)
	}
	for i := 0; i < 101; i++ {
		other := c
		other.ID = randomID()
		other.Fault.Domain = fmt.Sprintf("other-%d.example.com", i)
		other.Next = 0
		other.Updated = clock.Unix() + 1
		other.State = "inconclusive"
		if err := e.store.saveCorrection(other); err != nil {
			t.Fatal(err)
		}
	}
	c.Receipt = &RuleReceipt{RequestID: "owned"}
	c.Next = 0
	c.State = "watching"
	c.Decision.Action = "PROXY"
	c.AppliedAt = clock.Unix() - 10
	if err := e.store.saveCorrection(c); err != nil {
		t.Fatal(err)
	}
	if err := e.store.put([]Event{{ID: randomID(), Domain: c.Fault.Domain, Source: c.Fault.Source, Network: "tcp", Port: 443, Route: "JP", Download: 1, Kind: "connection", Time: clock.Unix(), StartedAt: clock.Unix()}}); err != nil {
		t.Fatal(err)
	}
	if err := e.watch(); err != nil {
		t.Fatal(err)
	}
	c, _ = e.store.correction(c.Fault.Domain)
	if c.State != "confirmed" {
		t.Fatal("old owned rule fell out of observation", c.State)
	}
}

func TestRollbackRetryResolvesLostCloudReceiptBeforeApplying(t *testing.T) {
	e, b, r, clock := correctionFixture(t, "auto")
	correctionStep(t, e)
	advance(t, e, clock, 181)
	correctionStep(t, e)
	b.failApply = "generation_failed"
	correctionStep(t, e)
	correctionStep(t, e)
	r.losePublish = true
	c := correctionStep(t, e)
	if c.State != "publishing" || !c.Rollback || c.SentAt == 0 {
		t.Fatal(c.State, c.Rollback)
	}
	if err := e.save(&c, "attention", "publish_unknown", 0); err != nil {
		t.Fatal(err)
	}
	if err := e.Retry(c.Fault.Domain, c.ID); err != nil {
		t.Fatal(err)
	}
	c = correctionStep(t, e)
	if c.State != "applying" || c.RollbackReceipt == nil {
		t.Fatal(c.State, c.Reason)
	}
	c = correctionStep(t, e)
	if c.State != "rolled_back" || r.publishes != 2 {
		t.Fatal(c.State, r.publishes)
	}
}

func TestConnectionConfirmationUsesRealStartNotFirstSnapshot(t *testing.T) {
	e, _, _, clock := correctionFixture(t, "auto")
	correctionStep(t, e)
	advance(t, e, clock, 181)
	correctionStep(t, e)
	c := correctionStep(t, e)
	c = advance(t, e, clock, 181)
	for i, start := range []int64{0, c.AppliedAt - 10, c.AppliedAt, clock.Unix() + 3600} {
		err := e.store.put([]Event{{ID: fmt.Sprintf("conn:old-%d", i), Domain: c.Fault.Domain, Source: c.Fault.Source, Network: "tcp", Port: 443, Route: "JP", Download: 100, Kind: "connection", Time: clock.Unix(), StartedAt: start}})
		if err != nil {
			t.Fatal(err)
		}
	}
	c = correctionStep(t, e)
	if c.State != "watching" || c.ObservedAt != 0 {
		t.Fatal("old, unknown or future connection confirmed a correction")
	}
	events, err := snapshot([]byte(fmt.Sprintf(`{"connections":[{"id":"real-new","start":%q,"metadata":{"host":"api.example.com","sourceIP":"192.168.1.2","network":"tcp","destinationPort":"443"},"download":100,"chains":["jp","JP"],"rule":"Domain"}]}`, clock.UTC().Format(time.RFC3339))), clock.Unix())
	if err != nil || len(events) != 1 || events[0].StartedAt != clock.Unix() {
		t.Fatal(events, err)
	}
	if err = e.store.put(events); err != nil {
		t.Fatal(err)
	}
	c = correctionStep(t, e)
	if c.State != "confirmed" {
		t.Fatal(c.State)
	}
}

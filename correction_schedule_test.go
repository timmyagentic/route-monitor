package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"route-monitor/internal/routebridge"
)

func fillDiscoveryBudget(t *testing.T, e *correctionEngine, at time.Time, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		if _, err := e.store.db.Exec(`INSERT INTO correction_probes VALUES(?,?,?,?,'completed')`, randomID(), fmt.Sprintf("old-%d.example.com", i), at.Unix(), at.Unix()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCorrectionLastDailyProbeStillVerifies(t *testing.T) {
	e, _, r, clock := correctionFixture(t, "auto")
	*clock = autoDay(*clock).Add(12 * time.Hour)
	putCorrectionFault(t, e.store, *clock, "DIRECT")
	fillDiscoveryBudget(t, e, clock.Add(-time.Hour), 22)
	correctionStep(t, e)
	advance(t, e, clock, 181)
	correctionStep(t, e)
	correctionStep(t, e)
	c := advance(t, e, clock, 181)
	if c.State != "watching" || r.publishes != 1 {
		t.Fatalf("verification blocked after final discovery slot: %s / %s", c.State, c.Reason)
	}
	var n int
	if err := e.store.db.QueryRow(`SELECT COUNT(*) FROM correction_probes`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 24 {
		t.Fatalf("verification consumed discovery budget: %d", n)
	}
}

func TestCorrectionConfirmationIsThirtySecondsAndVerificationImmediate(t *testing.T) {
	e, _, _, clock := correctionFixture(t, "auto")
	c := correctionStep(t, e)
	if c.Next != clock.Unix()+30 {
		t.Fatalf("confirmation scheduled for %d seconds", c.Next-clock.Unix())
	}
	c = advance(t, e, clock, 29)
	if c.State != "confirming" {
		t.Fatal("confirmed too early", c.State)
	}
	c = advance(t, e, clock, 1)
	if c.State != "publishing" {
		t.Fatal(c.State, c.Reason)
	}
	correctionStep(t, e)
	c = correctionStep(t, e)
	if c.State != "verifying" || c.Next > clock.Unix() {
		t.Fatal("post-apply verification delayed", c.State, c.Next)
	}
	c = correctionStep(t, e)
	if c.State != "watching" {
		t.Fatal(c.State, c.Reason)
	}
}

func TestCorrectionOtherDomainRunsDuringConfirmationWait(t *testing.T) {
	e, _, _, clock := correctionFixture(t, "auto")
	correctionStep(t, e)
	*clock = clock.Add(time.Second)
	for range 2 {
		if err := e.store.put([]Event{{ID: randomID(), Domain: "second.example.com", Source: "192.168.1.2", Route: "DIRECT", Network: "tcp", Port: 443, Error: "连接超时", Kind: "error", Time: clock.Unix()}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	c, err := e.store.correction("second.example.com")
	if err != nil || c.State != "confirming" {
		t.Fatal("unrelated domain waited for global spacing", c.State, c.Reason, err)
	}
}

func reopenCorrectionStore(t *testing.T, e *correctionEngine) {
	t.Helper()
	var seq int
	var name, path string
	if err := e.store.db.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	if err := e.store.db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	e.store = s
	t.Cleanup(func() { s.db.Close() })
}

type correctionBridgeFunc func(context.Context, routebridge.Request) (routebridge.Response, error)

func (f correctionBridgeFunc) Call(ctx context.Context, r routebridge.Request) (routebridge.Response, error) {
	return f(ctx, r)
}

func applyCorrection(t *testing.T, e *correctionEngine, clock *time.Time) Correction {
	t.Helper()
	correctionStep(t, e)
	advance(t, e, clock, 30)
	correctionStep(t, e)
	c := correctionStep(t, e)
	if c.State != "verifying" {
		t.Fatal(c.State, c.Reason)
	}
	return c
}

func TestVerificationAttemptsSurviveCrashAndEndWithoutRepeatingPublish(t *testing.T) {
	e, b, r, clock := correctionFixture(t, "auto")
	applyCorrection(t, e, clock)
	e.bridge = correctionBridgeFunc(func(context.Context, routebridge.Request) (routebridge.Response, error) {
		panic("simulated process exit")
	})
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected simulated exit")
			}
		}()
		e.Step(context.Background())
	}()
	reopenCorrectionStore(t, e)
	c, err := e.store.correction("api.example.com")
	if err != nil || c.VerificationAttempts != 1 {
		t.Fatal("verification start was not durable", c.VerificationAttempts, err)
	}
	e.bridge = b
	b.direct, b.proxy = "failed", "failed"
	c = advance(t, e, clock, 30)
	if c.State != "verifying" || c.VerificationAttempts != 2 {
		t.Fatal(c.State, c.VerificationAttempts)
	}
	reopenCorrectionStore(t, e)
	c = advance(t, e, clock, 30)
	if c.State != "attention" || c.Next != 0 || c.VerificationAttempts != 3 {
		t.Fatal("verification did not stop", c.State, c.Next, c.VerificationAttempts)
	}
	c = advance(t, e, clock, 3600)
	if c.State != "attention" || r.publishes != 1 || b.applyCalls != 1 {
		t.Fatal("restart repeated an external change", c.State, r.publishes, b.applyCalls)
	}
	if err := e.Retry(c.Fault.Domain, c.ID); err != nil {
		t.Fatal(err)
	}
	b.proxy = "response"
	c = correctionStep(t, e)
	if c.State != "watching" || c.VerificationAttempts != 1 || r.publishes != 1 || b.applyCalls != 1 {
		t.Fatal("explicit retry did not resume only verification", c.State, c.VerificationAttempts, r.publishes, b.applyCalls)
	}
}

func TestLegacyMidnightVerificationResumesOnlyOwnedWork(t *testing.T) {
	e, b, r, clock := correctionFixture(t, "auto")
	c := applyCorrection(t, e, clock)
	receiptID := c.Receipt.RequestID
	c.Reason = "daily_limit"
	c.Next = autoDay(*clock).AddDate(0, 0, 1).Unix()
	c.Failures = 1
	if err := e.store.saveCorrection(c); err != nil {
		t.Fatal(err)
	}
	ordinary := c
	ordinary.ID = randomID()
	ordinary.Fault.Domain = "waiting.example.com"
	ordinary.State = "queued"
	ordinary.Receipt = nil
	ordinary.AppliedAt = 0
	if err := e.store.saveCorrection(ordinary); err != nil {
		t.Fatal(err)
	}
	if err := e.store.setCorrectionPaused(true); err != nil {
		t.Fatal(err)
	}
	fillDiscoveryBudget(t, e, *clock, 24)
	reopenCorrectionStore(t, e)
	saved, err := e.store.correction(c.Fault.Domain)
	if err != nil || saved.Reason != "verification_resumed" || saved.Next >= c.Next || saved.VerificationAttempts != 1 || saved.Receipt.RequestID != receiptID {
		t.Fatal("legacy verification not safely resumed", saved, err)
	}
	if !e.store.correctionPaused() {
		t.Fatal("resume unpaused discovery")
	}
	other, err := e.store.correction(ordinary.Fault.Domain)
	if err != nil || other.Next != ordinary.Next || other.Reason != "daily_limit" {
		t.Fatal("unrelated queue changed", other, err)
	}
	*clock = time.Unix(saved.Next+1, 0)
	c = correctionStep(t, e)
	if c.State != "watching" || c.VerificationAttempts != 2 || r.publishes != 1 || b.applyCalls != 1 {
		t.Fatal(c.State, c.Reason, c.VerificationAttempts, r.publishes, b.applyCalls)
	}
	reopenCorrectionStore(t, e)
	c = correctionStep(t, e)
	if c.VerificationAttempts != 2 || c.State != "watching" {
		t.Fatal("resume repeated on next startup", c.State, c.VerificationAttempts)
	}
}

func TestDiscoveryLimitHasOwnReasonAndResetsAtChinaMidnight(t *testing.T) {
	e, _, _, clock := correctionFixture(t, "auto")
	*clock = autoDay(*clock).Add(12 * time.Hour)
	putCorrectionFault(t, e.store, *clock, "DIRECT")
	fillDiscoveryBudget(t, e, *clock, 24)
	c := correctionStep(t, e)
	midnight := autoDay(*clock).AddDate(0, 0, 1)
	if c.State != "queued" || c.Reason != "probe_daily_limit" || c.Next != midnight.Unix() {
		t.Fatal(c.State, c.Reason, c.Next)
	}
	*clock = midnight.Add(time.Second)
	putCorrectionFault(t, e.store, *clock, "DIRECT")
	c = correctionStep(t, e)
	if c.State != "confirming" {
		t.Fatal(c.State, c.Reason)
	}
}

func TestNegativeResolutionCoolsDownAcrossRestart(t *testing.T) {
	e, b, _, clock := correctionFixture(t, "auto")
	e.bridge = correctionBridgeFunc(func(ctx context.Context, r routebridge.Request) (routebridge.Response, error) {
		out, err := b.Call(ctx, r)
		if r.Operation == "probe" {
			for i := range out.Samples {
				s := &out.Samples[i]
				if !s.Control {
					s.Status = "failed"
					s.Stage = "dns"
					s.DNSStatus = "no_address"
					s.HTTPStatus = 0
				}
			}
		}
		return out, err
	})
	c := correctionStep(t, e)
	if c.Reason != "no_public_resolution" || c.RetryAfter != clock.Unix()+86400 {
		t.Fatal(c.State, c.Reason, c.RetryAfter)
	}
	reopenCorrectionStore(t, e)
	*clock = clock.Add(time.Hour)
	putCorrectionFault(t, e.store, *clock, "DIRECT")
	c = correctionStep(t, e)
	var n int
	if err := e.store.db.QueryRow(`SELECT COUNT(*) FROM correction_probes`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 || c.Reason != "no_public_resolution" {
		t.Fatal("negative result repeated early", n, c.Reason)
	}
}

func TestCorrectionReservationRetainsHealthAndSingleConcurrency(t *testing.T) {
	a := newTestApp(t)
	now := time.Now()
	if a.reserveProbe(now, 0) {
		t.Fatal("unhealthy probe started")
	}
	for _, k := range []string{"connections", "logs", "storage"} {
		a.states[k] = Health{Connected: true}
	}
	a.lastFrame["connections"] = now.Unix()
	a.lastProbe = now
	a.bulkRunning = true
	if a.reserveProbe(now, 0) {
		t.Fatal("overlapped bulk work")
	}
	a.bulkRunning = false
	if !a.reserveProbe(now, 0) || a.reserveProbe(now, 0) {
		t.Fatal("correction did not share the exclusive slot")
	}
	a.probing = false
	a.lastFrame["connections"] = now.Add(-time.Minute).Unix()
	if a.reserveProbe(now, 0) {
		t.Fatal("stale snapshot allowed")
	}
}

func TestCorrectionStateSeparatesLimitsAndVerificationProgress(t *testing.T) {
	e, _, _, clock := correctionFixture(t, "auto")
	c := applyCorrection(t, e, clock)
	c.VerificationAttempts = 2
	c.Reason = "verification_failed"
	c.Next = clock.Unix() + 30
	if err := e.store.saveCorrection(c); err != nil {
		t.Fatal(err)
	}
	a := &App{store: e.store, cfg: Config{Correction: e.config}}
	state := a.correctionState()
	if state["confirmDelaySeconds"] != 30 || state["verificationLimit"] != 3 {
		t.Fatal(state)
	}
	cases := state["cases"].([]map[string]any)
	if len(cases) != 1 || cases[0]["verificationAttempts"] != 2 || cases[0]["next"] != c.Next || cases[0]["observedAt"] != int64(0) {
		t.Fatal(cases)
	}
	if correctionReason("probe_daily_limit") == correctionReason("publish_daily_limit") || correctionReason("daily_limit") == correctionReason("probe_daily_limit") {
		t.Fatal("limits collapsed into one message")
	}
}

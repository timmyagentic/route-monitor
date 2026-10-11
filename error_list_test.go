package main

import (
	"fmt"
	"testing"
	"time"
)

func TestErrorListKeepsNormalObservationsOutAndPreservesErrorContext(t *testing.T) {
	a := newTestApp(t)
	now := time.Now().Unix()
	events := []Event{
		{ID: "error", Domain: "broken.example.com", Route: "HK", Kind: "error", Time: now},
		{ID: "connection", Domain: "broken.example.com", Route: "HK", Kind: "connection", Time: now},
		{ID: "healthy", Domain: "healthy.example.com", Route: "JP", Kind: "connection", Time: now},
		{ID: "old-error", Domain: "old-error.example.com", Route: "DIRECT", Kind: "error", Time: now - 86401},
		{ID: "new-connection", Domain: "old-error.example.com", Route: "DIRECT", Kind: "connection", Time: now},
	}
	if e := a.store.put(events); e != nil {
		t.Fatal(e)
	}
	// A complete failed DIRECT comparison on a healthy proxy domain must not make it an issue.
	addBatch(t, a.store, "healthy.example.com", "probe-only", 2, true)
	if _, e := a.store.db.Exec("UPDATE probes SET status='failed' WHERE batch='probe-only' AND route='DIRECT'"); e != nil {
		t.Fatal(e)
	}
	rows, _, e := a.store.summary()
	if e != nil || len(rows) != 1 || rows[0].Domain != "broken.example.com" || rows[0].Errors != 1 || rows[0].Connections != 1 {
		t.Fatal(rows, e)
	}
	all, _, e := a.store.summaryFor("all")
	if e != nil || len(all) != 3 {
		t.Fatal(all, e)
	}
	for _, r := range all {
		if r.Domain == "healthy.example.com" && (r.Priority != 0 || r.RecommendProxy || r.ProxyEvidence == nil) {
			t.Fatal(r)
		}
	}
	if e = a.store.setHandled("broken.example.com", 1, true, "节点已检查"); e != nil {
		t.Fatal(e)
	}
	rows, _, e = a.store.summary()
	if e != nil || len(rows) != 0 {
		t.Fatal(rows, e)
	}
	handled, _, e := a.store.summaryFor("handled")
	if e != nil || len(handled) != 1 {
		t.Fatal(handled, e)
	}
}

func TestErrorListFiltersNormalDomainsBeforePageLimit(t *testing.T) {
	a := newTestApp(t)
	now := time.Now().Unix()
	events := []Event{}
	for i := 0; i < 305; i++ {
		events = append(events, Event{ID: fmt.Sprint(i), Domain: fmt.Sprintf("normal-%d.example.com", i), Kind: "connection", Time: now})
	}
	events = append(events, Event{ID: "actual-error", Domain: "error.example.com", Route: "DIRECT", Kind: "error", Time: now})
	if e := a.store.put(events); e != nil {
		t.Fatal(e)
	}
	rows, _, e := a.store.summary()
	if e != nil || len(rows) != 1 || rows[0].Domain != "error.example.com" {
		t.Fatal(rows, e)
	}
	all, _, e := a.store.summaryFor("all")
	if e != nil || len(all) != 300 {
		t.Fatal(len(all), e)
	}
}

func TestBulkOnlySelectsRecentRealErrorsAndRechecksThem(t *testing.T) {
	a := newTestApp(t)
	now := time.Now().Unix()
	events := []Event{
		{ID: "healthy", Domain: "healthy.example.com", Route: "JP", Kind: "connection", Time: now},
		{ID: "old", Domain: "old.example.com", Route: "DIRECT", Kind: "error", Time: now - 86401},
		{ID: "old-conn", Domain: "old.example.com", Route: "DIRECT", Kind: "connection", Time: now},
		{ID: "error", Domain: "error.example.com", Route: "JP", Kind: "error", Time: now},
	}
	if e := a.store.put(events); e != nil {
		t.Fatal(e)
	}
	// Failed synthetic comparison evidence is not a real connection error.
	addBatch(t, a.store, "healthy.example.com", "comparison", 2, true)
	if _, e := a.store.db.Exec("UPDATE probes SET status='failed' WHERE batch='comparison'"); e != nil {
		t.Fatal(e)
	}
	if _, e := a.store.createBulk(); e != nil {
		t.Fatal(e)
	}
	if s := a.store.bulkStatus(); s.Total != 1 {
		t.Fatal(s)
	}
	for _, d := range []string{"healthy.example.com", "old.example.com"} {
		ok, e := a.bulkEligible(d)
		if e != nil || ok {
			t.Fatal(d, ok, e)
		}
	}
	ok, e := a.bulkEligible("error.example.com")
	if e != nil || !ok {
		t.Fatal(ok, e)
	}
	if _, e = a.store.db.Exec("UPDATE events SET ts=? WHERE id='error'", now-86401); e != nil {
		t.Fatal(e)
	}
	ok, e = a.bulkEligible("error.example.com")
	if e != nil || ok {
		t.Fatal(ok, e)
	}
}

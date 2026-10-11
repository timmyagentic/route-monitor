package main

// ProxyEvidence is a result from the latest complete three-route batch only.
// Reachable means a HEAD response, not proof that an app or login works.
type ProxyEvidence struct {
	Routes []string `json:"routes"`
	Time   int64    `json:"time"`
}

func proxyEvidence(probes []Probe) *ProxyEvidence {
	var latest *Probe
	for i := range probes {
		if latest == nil || probes[i].Time > latest.Time {
			latest = &probes[i]
		}
	}
	if latest == nil {
		return nil
	}
	groups := map[string][]Probe{}
	var testedAt int64
	for _, p := range probes {
		if p.Batch == latest.Batch {
			groups[p.Route] = append(groups[p.Route], p)
			testedAt = max(testedAt, p.Time)
		}
	}
	for _, route := range []string{"DIRECT", "JP", "HK"} {
		if len(groups[route]) != 3 {
			return nil
		}
	}
	for _, p := range groups["DIRECT"] {
		if p.Status != "failed" {
			return nil
		}
	}
	evidence := &ProxyEvidence{Time: testedAt}
	for _, route := range []string{"JP", "HK"} {
		ps := groups[route]
		stable := ps[0].Node != ""
		for _, p := range ps {
			stable = stable && p.Status == "reachable" && p.Node == ps[0].Node
		}
		if stable {
			evidence.Routes = append(evidence.Routes, route)
		}
	}
	if len(evidence.Routes) == 0 {
		return nil
	}
	return evidence
}

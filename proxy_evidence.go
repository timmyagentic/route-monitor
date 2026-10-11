package main

// ProxyEvidence is a result from the latest complete three-route batch only.
// Reachable means a HEAD response, not proof that an app or login works.
type ProxyEvidence struct {
	Samples int      `json:"samples"`
	Routes  []string `json:"routes"`
	Time    int64    `json:"time"`
}

func proxyEvidence(probes []Probe) *ProxyEvidence {
	groups, n, complete, testedAt := latestProbeBatch(probes)
	if !complete {
		return nil
	}
	for _, p := range groups["DIRECT"] {
		if p.Status != "failed" {
			return nil
		}
	}
	evidence := &ProxyEvidence{Time: testedAt, Samples: n}
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

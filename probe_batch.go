package main

// Old rows have no batch metadata and always used three samples per route.
const probeSamples = 2

func latestProbeBatch(probes []Probe) (map[string][]Probe, int, bool, int64) {
	var latest *Probe
	for i := range probes {
		if latest == nil || probes[i].Time > latest.Time {
			latest = &probes[i]
		}
	}
	groups := map[string][]Probe{}
	if latest == nil {
		return groups, probeSamples, false, 0
	}
	n := latest.Samples
	if n == 0 {
		n = 3
	}
	var ts int64
	for _, p := range probes {
		if p.Batch == latest.Batch {
			groups[p.Route] = append(groups[p.Route], p)
			ts = max(ts, p.Time)
		}
	}
	if latest.BatchState != "" && latest.BatchState != "completed" {
		return groups, n, false, ts
	}
	if n != 2 && n != 3 {
		return groups, n, false, ts
	}
	for _, r := range []string{"DIRECT", "JP", "HK"} {
		if len(groups[r]) != n {
			return groups, n, false, ts
		}
	}
	return groups, n, true, ts
}

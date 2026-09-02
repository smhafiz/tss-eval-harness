package internal

import "math"

// Stats is the {mean, min, max, stddev} object the schema's timing_ms entries
// carry, in milliseconds.
type Stats struct {
	Mean   float64 `json:"mean"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	StdDev float64 `json:"stddev"`
}

// ComputeStats takes durations in *seconds* (what time.Since(...).Seconds()
// returns at every call site) and returns them in *milliseconds*, which is what
// the schema stores. The unit change happens here, once, rather than being
// sprinkled over the callers.
//
// StdDev is the population standard deviation (divisor N, not N-1): several
// phases legitimately have a single sample — tss-lib's interactive keygen runs
// exactly once per cell — and reporting 0 for those is honest, whereas a sample
// stddev would divide by zero. SCHEMA.md documents the choice so nobody reads a
// 0 as suspiciously low variance.
func ComputeStats(seconds []float64) Stats {
	if len(seconds) == 0 {
		return Stats{}
	}
	ms := make([]float64, len(seconds))
	for i, s := range seconds {
		ms[i] = s * 1000
	}

	minV, maxV, sum := ms[0], ms[0], 0.0
	for _, v := range ms {
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
		sum += v
	}
	mean := sum / float64(len(ms))

	var sqDev float64
	for _, v := range ms {
		d := v - mean
		sqDev += d * d
	}

	return Stats{
		Mean:   mean,
		Min:    minV,
		Max:    maxV,
		StdDev: math.Sqrt(sqDev / float64(len(ms))),
	}
}

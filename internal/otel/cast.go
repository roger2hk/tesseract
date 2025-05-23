// Copyright 2025 The Tessera authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package otel

import "math"

var (
	// SubSecondLatencyHistogramBuckets is a range of millisecond scale bucket boundaries which remain useful at around 1-2 seconds timescale in addition to smaller latencies.
	// We use seconds as units, Open Telemetry's default unit for time.
	SubSecondLatencyHistogramBuckets = []float64{0, 10e-3, 50e-3, 100e-3, 200e-3, 300e-3, 400e-3, 500e-3, 600e-3, 700e-3, 800e-3, 900e-3, 1000e-3, 1200e-3, 1400e-3, 1600e-3, 1800e-3, 2000e-3, 2500e-3, 3000e-3, 4000e-3, 5000e-3, 6000e-3, 8000e-3, 10000e-3}
)

// Clamp64 casts a uint64 to an int64, clamping it at MaxInt64 if the value is above.
//
// Intended only for converting Tessera uint64 internal values to int64 for use with
// open telemetry metrics.
func Clamp64(u uint64) int64 {
	if u > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(u)
}

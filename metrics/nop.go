// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package metrics

// NopMetrics is a Metrics implementation that discards all increments. It is the
// default when no Metrics is injected, so the library can call its metrics sink
// unconditionally without a nil guard:
//
//	cfg.Metrics = metrics.NopMetrics{}
//
// The library also tolerates a nil Metrics (increments are skipped), so NopMetrics
// is only a convenience for callers that prefer a non-nil value.
type NopMetrics struct{}

// IncCounter implements Metrics and discards the increment.
func (NopMetrics) IncCounter(name string, labels ...string) {}

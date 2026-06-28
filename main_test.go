package main

import (
	"testing"
	"time"
)

// TestBillingRangeSeconds pins the rate-multiplier that cpu/disk/replica usage
// is scaled by. The key billing-correctness property for backfill: a completed
// day must bill exactly one day (86400s). A naive wall-clock `now` for an
// already-finished day inflates the window to multiple days — the bug Backfill
// avoids by passing now == et.
func TestBillingRangeSeconds(t *testing.T) {
	const day = 86400
	d := time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)
	et := d.AddDate(0, 0, 1)

	tests := []struct {
		name string
		now  time.Time
		want int64
	}{
		{
			name: "completed day with now=et bills exactly one day (backfill)",
			now:  et,
			want: day,
		},
		{
			name: "in-progress current day projects to a full day",
			now:  d.Add(7 * time.Hour),
			want: day,
		},
		{
			name: "past day with real wall-clock now over-counts (why backfill pins now=et)",
			now:  d.AddDate(0, 0, 4), // 4 days later
			want: 4 * day,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := billingRangeSeconds(d, tc.now, et)
			if got != tc.want {
				t.Errorf("billingRangeSeconds(%s, now=%s, %s) = %d, want %d",
					d.Format(time.RFC3339), tc.now.Format(time.RFC3339), et.Format(time.RFC3339), got, tc.want)
			}
		})
	}
}

// TestNormalizeCacheResult pins the canonical edge cache-result set that the
// cache-result usage sync attributes to projects. The mapping is billing-
// relevant: a result that maps to "" is dropped (not counted), so STALE_ERROR
// MUST fold into STALE rather than vanish, and only these exact labels count.
func TestNormalizeCacheResult(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		// Canonical results pass through unchanged.
		{"HIT", "HIT"},
		{"MISS", "MISS"},
		{"STALE", "STALE"},
		{"BYPASS", "BYPASS"},
		// STALE_ERROR is counted, folded into STALE (must not be dropped).
		{"STALE_ERROR", "STALE"},
		// Anything else maps to "" and is dropped by the caller — including
		// wrong case and empty, so a new/unexpected label is never mis-bucketed.
		{"hit", ""},
		{"EXPIRED", ""},
		{"REVALIDATED", ""},
		{"", ""},
	}
	for _, tc := range tests {
		if got := normalizeCacheResult(tc.in); got != tc.want {
			t.Errorf("normalizeCacheResult(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

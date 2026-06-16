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

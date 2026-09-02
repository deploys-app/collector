package main

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/deploys-app/api"
)

func TestParsePromMetrics(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		maxSeries int
		want      []scrapedSample
		truncated bool
		wantErr   bool
	}{
		{
			name: "gauge + counter + untyped kept",
			body: `
# TYPE queue_depth gauge
queue_depth{queue="email"} 3
# TYPE requests_total counter
requests_total 10
jobs_in_flight 4
`,
			maxSeries: api.MetricSourceMaxSeries,
			want: []scrapedSample{
				{Series: "jobs_in_flight", Type: api.MetricSourceSeriesTypeUntyped, Value: 4},
				{Series: `queue_depth{queue="email"}`, Type: api.MetricSourceSeriesTypeGauge, Value: 3},
				{Series: "requests_total", Type: api.MetricSourceSeriesTypeCounter, Value: 10},
			},
		},
		{
			name: "no labels uses name without braces",
			body: `
# TYPE up gauge
up 1
`,
			maxSeries: api.MetricSourceMaxSeries,
			want: []scrapedSample{
				{Series: "up", Type: api.MetricSourceSeriesTypeGauge, Value: 1},
			},
		},
		{
			name: "label names are sorted in the series key",
			body: `
# TYPE queue_depth gauge
queue_depth{b="1",a="2"} 7
`,
			maxSeries: api.MetricSourceMaxSeries,
			want: []scrapedSample{
				{Series: `queue_depth{a="2",b="1"}`, Type: api.MetricSourceSeriesTypeGauge, Value: 7},
			},
		},
		{
			name: "histogram family dropped including _bucket _sum _count",
			body: `
# TYPE queue_depth gauge
queue_depth 1
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{le="0.1"} 1
http_request_duration_seconds_bucket{le="+Inf"} 2
http_request_duration_seconds_sum 0.15
http_request_duration_seconds_count 2
`,
			maxSeries: api.MetricSourceMaxSeries,
			want: []scrapedSample{
				{Series: "queue_depth", Type: api.MetricSourceSeriesTypeGauge, Value: 1},
			},
		},
		{
			name: "summary family dropped",
			body: `
# TYPE up gauge
up 1
# TYPE rpc_duration_seconds summary
rpc_duration_seconds{quantile="0.5"} 0.2
rpc_duration_seconds_sum 1.5
rpc_duration_seconds_count 10
`,
			maxSeries: api.MetricSourceMaxSeries,
			want: []scrapedSample{
				{Series: "up", Type: api.MetricSourceSeriesTypeGauge, Value: 1},
			},
		},
		{
			name:      "empty body errors",
			body:      "",
			maxSeries: api.MetricSourceMaxSeries,
			wantErr:   true,
		},
		{
			name:      "invalid body errors",
			body:      "this is not prometheus",
			maxSeries: api.MetricSourceMaxSeries,
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parsePromMetrics([]byte(tc.body), tc.maxSeries)
			if tc.wantErr {
				if got.Err == nil {
					t.Fatalf("expected error, got samples %#v", got.Samples)
				}
				if got.Samples != nil {
					t.Fatalf("Samples = %#v, want nil", got.Samples)
				}
				return
			}
			if got.Err != nil {
				t.Fatalf("parsePromMetrics: %v", got.Err)
			}
			if got.Truncated != tc.truncated {
				t.Errorf("Truncated = %v, want %v", got.Truncated, tc.truncated)
			}
			if !slices.Equal(got.Samples, tc.want) {
				t.Errorf("Samples = %#v, want %#v", got.Samples, tc.want)
			}
		})
	}

	t.Run("nil body errors", func(t *testing.T) {
		got := parsePromMetrics(nil, api.MetricSourceMaxSeries)
		if got.Err == nil {
			t.Fatal("expected error")
		}
		if got.Samples != nil {
			t.Fatalf("Samples = %#v, want nil", got.Samples)
		}
	})
}

func TestSamplesToUsageItemsCopiesType(t *testing.T) {
	samples := []scrapedSample{
		{Series: "up", Type: api.MetricSourceSeriesTypeGauge, Value: 1},
		{Series: "jobs_total", Type: api.MetricSourceSeriesTypeCounter, Value: 9},
	}
	got := samplesToUsageItems(7, 11, samples, 1000)
	if len(got) != 2 {
		t.Fatalf("len = %d", len(got))
	}
	if got[0].Type != api.MetricSourceSeriesTypeGauge || got[0].Series != "up" || got[0].Value != 1 {
		t.Fatalf("gauge item = %+v", got[0])
	}
	if got[1].Type != api.MetricSourceSeriesTypeCounter || got[1].Series != "jobs_total" {
		t.Fatalf("counter item = %+v", got[1])
	}
	if got[1].ProjectID != 7 || got[1].SourceID != 11 || got[1].At != 1000 {
		t.Fatalf("ids = %+v", got[1])
	}
}

func TestParsePromMetricsSeriesCap(t *testing.T) {
	var b strings.Builder
	for i := range api.MetricSourceMaxSeries + 1 {
		fmt.Fprintf(&b, "# TYPE s%03d gauge\ns%03d %d\n", i, i, i)
	}

	got := parsePromMetrics([]byte(b.String()), api.MetricSourceMaxSeries)
	if got.Err != nil {
		t.Fatalf("parsePromMetrics: %v", got.Err)
	}
	if !got.Truncated {
		t.Fatal("Truncated = false, want true")
	}
	if len(got.Samples) != api.MetricSourceMaxSeries {
		t.Fatalf("len(Samples) = %d, want %d", len(got.Samples), api.MetricSourceMaxSeries)
	}

	wantLast := fmt.Sprintf("s%03d", api.MetricSourceMaxSeries-1)
	if got.Samples[api.MetricSourceMaxSeries-1].Series != wantLast {
		t.Errorf("100th series = %q, want %q", got.Samples[api.MetricSourceMaxSeries-1].Series, wantLast)
	}
	dropped := fmt.Sprintf("s%03d", api.MetricSourceMaxSeries)
	if slices.ContainsFunc(got.Samples, func(s scrapedSample) bool { return s.Series == dropped }) {
		t.Errorf("Samples still contain truncated series %q", dropped)
	}

	// Exactly maxSeries must not set Truncated.
	exact := parsePromMetrics([]byte(b.String()), api.MetricSourceMaxSeries+1)
	if exact.Err != nil {
		t.Fatalf("parsePromMetrics exact: %v", exact.Err)
	}
	if exact.Truncated {
		t.Fatal("Truncated = true for exactly 101 requested, want false")
	}
	if len(exact.Samples) != api.MetricSourceMaxSeries+1 {
		t.Fatalf("len(Samples) = %d, want %d", len(exact.Samples), api.MetricSourceMaxSeries+1)
	}
}

func TestCapBody(t *testing.T) {
	const max = api.MetricSourceMaxBodyBytes

	t.Run("1 MiB ok", func(t *testing.T) {
		in := bytes.Repeat([]byte("a"), max)
		got, err := capBody(bytes.NewReader(in), max)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != max {
			t.Fatalf("len = %d, want %d", len(got), max)
		}
	})

	t.Run("1 MiB+1 fails", func(t *testing.T) {
		in := bytes.Repeat([]byte("a"), max+1)
		_, err := capBody(bytes.NewReader(in), max)
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, errBodyTooLarge) {
			t.Fatalf("err = %v, want %v", err, errBodyTooLarge)
		}
	})
}

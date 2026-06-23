package prom

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHostPattern(t *testing.T) {
	tests := []struct {
		name    string
		domains []string
		want    string
	}{
		{
			name:    "plain domain escapes dots",
			domains: []string{"example.com"},
			want:    `example\.com`,
		},
		{
			name:    "wildcard-only list produces empty pattern (wildcards are unbillable)",
			domains: []string{"*.example.com"},
			want:    ``,
		},
		{
			name:    "mixed list keeps only the exact domain, wildcard skipped",
			domains: []string{"foo.example.com", "*.bar.example.com"},
			want:    `foo\.example\.com`,
		},
		{
			name:    "empty list produces empty string",
			domains: []string{},
			want:    ``,
		},
		{
			name:    "plain domain with multiple dots",
			domains: []string{"a.b.c.deploys.app"},
			want:    `a\.b\.c\.deploys\.app`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := hostPattern(tc.domains)
			if got != tc.want {
				t.Errorf("hostPattern(%v) = %q, want %q", tc.domains, got, tc.want)
			}
		})
	}
}

// TestSummaryCacheEgressEscapesHostRegex is the regression guard for the bug
// where the host regex (regexp.QuoteMeta output, e.g. `example\.com`) was
// embedded raw into a PromQL double-quoted string. A bare `\.` is an invalid
// PromQL escape, so Prometheus rejected the query with status "error" and the
// collector logged the opaque "status not success". The backslash must be
// doubled so the string literal decodes back to the intended regex.
func TestSummaryCacheEgressEscapesHostRegex(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[{"value":[1700000000,"42"]}]}}`)
	}))
	defer srv.Close()

	c := &Client{Endpoint: srv.URL}
	got, err := c.SummaryCacheEgress([]string{"foo.example.com"}, 1700000000, "1d")
	if err != nil {
		t.Fatalf("SummaryCacheEgress error: %v", err)
	}
	if got != "42" {
		t.Fatalf("value = %q, want %q", got, "42")
	}

	// The dots must reach Prometheus as a doubled-backslash escape so the
	// double-quoted string literal yields the regex `foo\.example\.com`.
	if !strings.Contains(gotQuery, `host=~"foo\\.example\\.com"`) {
		t.Fatalf("host matcher not escaped for PromQL string literal: %s", gotQuery)
	}
}

// TestSummaryStaticEgressQuery verifies the static-egress query is a daily
// counter total (increase over the range) summed across a project's sites and
// gateway replicas, keyed by the project SID as an exact-match label, evaluated
// at the day boundary.
func TestSummaryStaticEgressQuery(t *testing.T) {
	var gotQuery, gotTime string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		gotTime = r.URL.Query().Get("time")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[{"value":[1700000000,"123"]}]}}`)
	}))
	defer srv.Close()

	c := &Client{Endpoint: srv.URL}
	got, err := c.SummaryStaticEgress("acme", 1700000000, "1d")
	if err != nil {
		t.Fatalf("SummaryStaticEgress error: %v", err)
	}
	if got != "123" {
		t.Fatalf("value = %q, want %q", got, "123")
	}
	if !strings.Contains(gotQuery, `sum(increase(static_gateway_response_bytes_total{project="acme"}[1d]))`) {
		t.Fatalf("unexpected query: %s", gotQuery)
	}
	if gotTime != "1700000000" {
		t.Fatalf("time = %q, want evaluation at the day boundary 1700000000", gotTime)
	}
}

// TestQueryVectorValueSurfacesPromError verifies a non-success Prometheus
// response carries its errorType/error into the returned error rather than the
// old opaque "status not success".
func TestQueryVectorValueSurfacesPromError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"status":"error","errorType":"bad_data","error":"invalid parameter \"query\": unknown escape sequence"}`)
	}))
	defer srv.Close()

	c := &Client{Endpoint: srv.URL}
	_, err := c.SummaryCacheEgress([]string{"foo.example.com"}, 1700000000, "1d")
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	for _, want := range []string{"bad_data", "unknown escape sequence"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err.Error(), want)
		}
	}
}

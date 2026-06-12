package prom

import (
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

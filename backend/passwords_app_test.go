//go:build darwin

package backend

import (
	"reflect"
	"testing"
)

func TestDedupeSortedServices(t *testing.T) {
	cases := []struct {
		name   string
		joined string
		want   []string
	}{
		{
			name:   "sorts and dedupes",
			joined: "github.com\nexample.com\ngithub.com",
			want:   []string{"example.com", "github.com"},
		},
		{
			name:   "drops empty entries",
			joined: "github.com\n\nexample.com",
			want:   []string{"example.com", "github.com"},
		},
		{
			name:   "empty input",
			joined: "",
			want:   []string{},
		},
		{
			name:   "single entry",
			joined: "github.com",
			want:   []string{"github.com"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dedupeSortedServices(tc.joined)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("dedupeSortedServices(%q) = %v, want %v", tc.joined, got, tc.want)
			}
		})
	}
}

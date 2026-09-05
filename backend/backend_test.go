package backend

import (
	"reflect"
	"testing"
)

func TestDedupeSortServices(t *testing.T) {
	cases := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "sorts and dedupes",
			input: []string{"github.com", "example.com", "github.com"},
			want:  []string{"example.com", "github.com"},
		},
		{
			name:  "drops empty entries",
			input: []string{"github.com", "", "example.com"},
			want:  []string{"example.com", "github.com"},
		},
		{
			name:  "empty input",
			input: []string{},
			want:  []string{},
		},
		{
			name:  "nil input",
			input: nil,
			want:  []string{},
		},
		{
			name:  "single entry",
			input: []string{"github.com"},
			want:  []string{"github.com"},
		},
		{
			name:  "ordinal byte-wise ordering, not locale-aware",
			input: []string{"b", "A", "a", "B"},
			want:  []string{"A", "B", "a", "b"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DedupeSortServices(tc.input)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("DedupeSortServices(%v) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

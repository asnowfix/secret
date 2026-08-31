//go:build darwin

package backend

import "testing"

// errSecInteractionNotAllowed's numeric value (-25308), used here as "some
// real Security framework failure other than success/not-found". It is not
// imported from the cgo preamble because cgo is not supported in _test.go
// files; secSuccessStatus/secItemNotFoundStatus (defined in passwords_app.go)
// are, so this is the one status value in the test that needs its own
// literal.
const errSecInteractionNotAllowed = -25308

func TestIsRealFailure(t *testing.T) {
	cases := []struct {
		name string
		st   int32
		want bool
	}{
		{name: "success is not a failure", st: secSuccessStatus, want: false},
		{name: "item not found is not a failure", st: secItemNotFoundStatus, want: false},
		{name: "interaction not allowed is a failure", st: errSecInteractionNotAllowed, want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRealFailure(tc.st); got != tc.want {
				t.Errorf("isRealFailure(%d) = %v, want %v", tc.st, got, tc.want)
			}
		})
	}
}

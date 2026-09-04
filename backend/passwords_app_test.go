//go:build darwin

package backend

import (
	"errors"
	"testing"
)

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

// TestNotFoundInBothQueries exercises the classification logic that decides
// whether a NULL result from sec_copy_password/sec_copy_username is a
// definitive "not found" or a real failure that must not be reported as
// such. The two queries' statuses are independent (see the comment on
// notFoundInBothQueries): a real failure on either one must not be masked
// by the other query genuinely finding nothing.
func TestNotFoundInBothQueries(t *testing.T) {
	const errSecInteractionNotAllowed = int32(-25308) // locked keychain, non-interactive
	const errSecSuccess = int32(0)

	cases := []struct {
		name                  string
		stGeneric, stInternet int32
		want                  bool
	}{
		{"both not found", osStatusItemNotFound, osStatusItemNotFound, true},
		{"generic real failure, internet not found", errSecInteractionNotAllowed, osStatusItemNotFound, false},
		{"generic not found, internet real failure", osStatusItemNotFound, errSecInteractionNotAllowed, false},
		{"both real failure", errSecInteractionNotAllowed, errSecInteractionNotAllowed, false},
		{"generic success sentinel leaked through, internet not found", errSecSuccess, osStatusItemNotFound, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := notFoundInBothQueries(tc.stGeneric, tc.stInternet); got != tc.want {
				t.Errorf("notFoundInBothQueries(%d, %d) = %v, want %v", tc.stGeneric, tc.stInternet, got, tc.want)
			}
		})
	}
}

// TestPasswordsApp_GetPassword_NotFound checks that a service which is
// genuinely absent is reported as *ErrNotFound. This does not exercise the
// entitlement-restricted ambiguity from #20/#27 (this process has no
// keychain-access entitlements at all, so it cannot distinguish "absent"
// from "present but denied" for *any* item on this backend) — it only
// confirms the plain not-found path still works after the refactor.
func TestPasswordsApp_GetPassword_NotFound(t *testing.T) {
	p := NewPasswordsApp()
	_, err := p.GetPassword("secret-issue30-does-not-exist-passwordsapp")
	var notFound *ErrNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("GetPassword() error = %v (%T), want *ErrNotFound", err, err)
	}
}

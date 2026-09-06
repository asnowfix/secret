//go:build darwin

package backend

import (
	"errors"
	"os"
	"testing"
)

// The OSStatus values this file needs as literals. secSuccessStatus and
// secItemNotFoundStatus (defined in passwords_app.go) mirror the cgo
// constants, so a test that used them on both sides of a comparison would
// only prove that a variable equals itself. These literals are the
// independent side: they are what Security.h actually documents, so a change
// to the mirrors is caught rather than followed.
const (
	errSecSuccessValue              = 0
	errSecItemNotFoundValue         = -25300
	errSecInteractionNotAllowed     = -25308 // locked keychain, non-interactive
	errSecInteractionNotAllowedName = "errSecInteractionNotAllowed"
)

// TestOSStatusMirrors checks the plain-int32 mirrors of the cgo constants
// against the documented Security.h values. Everything else in this file
// depends on them being right.
func TestOSStatusMirrors(t *testing.T) {
	t.Parallel()
	if secSuccessStatus != errSecSuccessValue {
		t.Errorf("secSuccessStatus = %d, want errSecSuccess (%d)", secSuccessStatus, errSecSuccessValue)
	}
	if secItemNotFoundStatus != errSecItemNotFoundValue {
		t.Errorf("secItemNotFoundStatus = %d, want errSecItemNotFound (%d)", secItemNotFoundStatus, errSecItemNotFoundValue)
	}
}

func TestIsRealFailure(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		st   int32
		want bool
	}{
		{name: "success is not a failure", st: errSecSuccessValue, want: false},
		{name: "item not found is not a failure", st: errSecItemNotFoundValue, want: false},
		{name: errSecInteractionNotAllowedName + " is a failure", st: errSecInteractionNotAllowed, want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
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
	t.Parallel()
	cases := []struct {
		name                  string
		stGeneric, stInternet int32
		want                  bool
	}{
		{"both not found", errSecItemNotFoundValue, errSecItemNotFoundValue, true},
		{"generic real failure, internet not found", errSecInteractionNotAllowed, errSecItemNotFoundValue, false},
		{"generic not found, internet real failure", errSecItemNotFoundValue, errSecInteractionNotAllowed, false},
		{"both real failure", errSecInteractionNotAllowed, errSecInteractionNotAllowed, false},
		{"generic success sentinel leaked through, internet not found", errSecSuccessValue, errSecItemNotFoundValue, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := notFoundInBothQueries(tc.stGeneric, tc.stInternet); got != tc.want {
				t.Errorf("notFoundInBothQueries(%d, %d) = %v, want %v", tc.stGeneric, tc.stInternet, got, tc.want)
			}
		})
	}
}

// TestClassifyPasswordsAppLookup pins the mapping onto the Backend error
// types the callers act on: only a definitive miss in both classes may be
// *ErrNotFound, because cmd/set.go reads that as "safe to overwrite".
func TestClassifyPasswordsAppLookup(t *testing.T) {
	t.Parallel()
	t.Run("both not found is ErrNotFound", func(t *testing.T) {
		t.Parallel()
		err := classifyPasswordsAppLookup("svc", errSecItemNotFoundValue, errSecItemNotFoundValue)
		var notFound *ErrNotFound
		if !errors.As(err, &notFound) {
			t.Fatalf("classifyPasswordsAppLookup() = %v (%T), want *ErrNotFound", err, err)
		}
	})

	t.Run("a real failure is ErrUnavailable", func(t *testing.T) {
		t.Parallel()
		err := classifyPasswordsAppLookup("svc", errSecInteractionNotAllowed, errSecItemNotFoundValue)
		var notFound *ErrNotFound
		if errors.As(err, &notFound) {
			t.Fatalf("classifyPasswordsAppLookup() = *ErrNotFound (%v); an unreadable credential must not look absent", err)
		}
		var unavailable *ErrUnavailable
		if !errors.As(err, &unavailable) {
			t.Fatalf("classifyPasswordsAppLookup() = %v (%T), want *ErrUnavailable", err, err)
		}
	})
}

// TestPasswordsApp_GetPassword_NotFound checks that a service which is
// genuinely absent is reported as *ErrNotFound.
//
// It is opt-in because it queries the *runner's own* default keychain list —
// real, uncontrolled I/O whose result depends on that keychain's state, and
// which would fail with errSecInteractionNotAllowed if it happened to be
// locked. Gating it matches the posture the far more controlled
// locked-keychain tests in keychain_test.go already use. The always-on
// coverage of the same logic is TestClassifyPasswordsAppLookup above.
//
// Note that this does not exercise the entitlement-restricted ambiguity from
// #20/#27 either: this process has no keychain-access entitlements at all, so
// it cannot distinguish "absent" from "present but denied" for any item on
// this backend.
func TestPasswordsApp_GetPassword_NotFound(t *testing.T) {
	if os.Getenv("SECRET_LIVE_KEYCHAIN_TEST") != "1" {
		t.Skip("set SECRET_LIVE_KEYCHAIN_TEST=1 to query the runner's real default keychain")
	}
	p := NewPasswordsApp()
	_, err := p.GetPassword("secret-issue30-does-not-exist-passwordsapp")
	var notFound *ErrNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("GetPassword() error = %v (%T), want *ErrNotFound", err, err)
	}
}

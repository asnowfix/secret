//go:build windows

package backend

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func mustUTF16Ptr(t *testing.T, s string) *uint16 {
	t.Helper()
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		t.Fatalf("UTF16PtrFromString(%q): %v", s, err)
	}
	return p
}

func TestFilterGenericTargetNames(t *testing.T) {
	creds := []*nativeCredential{
		{Type: credTypeGeneric, TargetName: mustUTF16Ptr(t, "github.com")},
		{Type: 2 /* CRED_TYPE_DOMAIN_PASSWORD */, TargetName: mustUTF16Ptr(t, "corp.local")},
		{Type: credTypeGeneric, TargetName: mustUTF16Ptr(t, "example.com")},
		{Type: credTypeGeneric, TargetName: nil},
	}

	got := filterGenericTargetNames(creds)
	want := []string{"example.com", "github.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("filterGenericTargetNames() = %v, want %v", got, want)
	}
}

// TestFilterGenericTargetNames_Dedup guards the assumption the review
// flagged as untested: CredEnumerateW is not documented to guarantee unique
// TargetName values per credential type, so filterGenericTargetNames must
// dedupe like the other backends' List() implementations do.
func TestFilterGenericTargetNames_Dedup(t *testing.T) {
	creds := []*nativeCredential{
		{Type: credTypeGeneric, TargetName: mustUTF16Ptr(t, "github.com")},
		{Type: credTypeGeneric, TargetName: mustUTF16Ptr(t, "github.com")},
		{Type: credTypeGeneric, TargetName: mustUTF16Ptr(t, "example.com")},
	}

	got := filterGenericTargetNames(creds)
	want := []string{"example.com", "github.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("filterGenericTargetNames() = %v, want %v", got, want)
	}
}

func TestFilterGenericTargetNames_Empty(t *testing.T) {
	got := filterGenericTargetNames(nil)
	if len(got) != 0 {
		t.Errorf("filterGenericTargetNames(nil) = %v, want empty", got)
	}
}

// TestClassifyCredError_NotFound guards the "genuinely absent" path:
// ERROR_NOT_FOUND — and only ERROR_NOT_FOUND — must map to *ErrNotFound, the
// type classifySetTarget (cmd/set.go) trusts as "safe to create new".
func TestClassifyCredError_NotFound(t *testing.T) {
	err := classifyCredError("svc", "read", windows.ERROR_NOT_FOUND)
	var notFound *ErrNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("classifyCredError(ERROR_NOT_FOUND) = %v (%T), want *ErrNotFound", err, err)
	}
	if notFound.Service != "svc" {
		t.Errorf("ErrNotFound.Service = %q, want %q", notFound.Service, "svc")
	}
}

// TestClassifyCredError_OtherFailure guards the bug this fixes (#32): any
// Win32 error other than the confirmed ERROR_NOT_FOUND sentinel must surface
// as *ErrUnavailable, not be collapsed into *ErrNotFound — otherwise
// classifySetTarget concludes "safe to create new" on a real failure (e.g.
// access denied, an invalid logon session) instead of refusing.
func TestClassifyCredError_OtherFailure(t *testing.T) {
	cases := []error{
		windows.ERROR_ACCESS_DENIED,
		windows.ERROR_NO_SUCH_LOGON_SESSION,
		windows.ERROR_INVALID_PARAMETER,
		windows.ERROR_INVALID_FLAGS,
	}
	for _, e := range cases {
		err := classifyCredError("svc", "read", e)
		var unavailable *ErrUnavailable
		if !errors.As(err, &unavailable) {
			t.Errorf("classifyCredError(%v) = %v (%T), want *ErrUnavailable", e, err, err)
			continue
		}
		if !strings.Contains(unavailable.Reason, "svc") {
			t.Errorf("ErrUnavailable.Reason = %q, want it to mention service %q", unavailable.Reason, "svc")
		}
	}
}

// TestClassifyCredError_OpInMessage guards that the operation name (read vs.
// delete) makes it into the error, since Delete and credReadW share this
// classifier but fail on different Win32 calls.
func TestClassifyCredError_OpInMessage(t *testing.T) {
	err := classifyCredError("svc", "delete", windows.ERROR_ACCESS_DENIED)
	var unavailable *ErrUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("classifyCredError(delete, ERROR_ACCESS_DENIED) = %v (%T), want *ErrUnavailable", err, err)
	}
	if !strings.Contains(unavailable.Reason, "delete") {
		t.Errorf("ErrUnavailable.Reason = %q, want it to mention op %q", unavailable.Reason, "delete")
	}
}

//go:build windows

package backend

import (
	"reflect"
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

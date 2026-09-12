//go:build windows

package cmd

import (
	"strings"
	"testing"

	"github.com/asnowfix/secret/backend"
)

func TestSelectBackend_Windows_DefaultsToCredentialManager(t *testing.T) {
	t.Setenv("SECRET_BACKEND", "")

	b, err := selectBackend()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := b.(*backend.CredentialManager); !ok {
		t.Fatalf("got %T, want *backend.CredentialManager", b)
	}
}

func TestSelectBackend_Windows_EnvSelectsCredentialManagerExplicitly(t *testing.T) {
	t.Setenv("SECRET_BACKEND", "credential-manager")

	b, err := selectBackend()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := b.(*backend.CredentialManager); !ok {
		t.Fatalf("got %T, want *backend.CredentialManager", b)
	}
}

func TestSelectBackend_Windows_UnrecognisedEnvValueErrors(t *testing.T) {
	t.Setenv("SECRET_BACKEND", "typo")

	b, err := selectBackend()
	if err == nil {
		t.Fatalf("expected an error, got backend %T", b)
	}
	if b != nil {
		t.Fatalf("expected a nil backend alongside the error, got %T", b)
	}
	if !strings.Contains(err.Error(), "typo") {
		t.Errorf("error %q does not name the offending value", err.Error())
	}
}

// TestSelectBackend_Windows_ValueValidOnlyOnAnotherPlatform documents that
// a value which is a real backend name, just not one Windows accepts,
// still gets a hard error here — see issue #7's design question 1 — while
// the message distinguishes it from a plain typo (design question 2).
func TestSelectBackend_Windows_ValueValidOnlyOnAnotherPlatform(t *testing.T) {
	t.Setenv("SECRET_BACKEND", "keychain")

	_, err := selectBackend()
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "only available on darwin") {
		t.Errorf("error %q does not explain that this name is valid on a different platform", err.Error())
	}
}

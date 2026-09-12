//go:build darwin

package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/asnowfix/secret/backend"
)

// resetDarwinBackendOverrides clears the flag-backed override before and
// after a test, since forcePasswordsApp is a package-level var shared with
// the real -k/--passwords-app flags.
func resetDarwinBackendOverrides(t *testing.T) {
	t.Helper()
	old := forcePasswordsApp
	forcePasswordsApp = false
	t.Cleanup(func() { forcePasswordsApp = old })
}

func TestSelectBackend_Darwin_DefaultsToKeychain(t *testing.T) {
	resetDarwinBackendOverrides(t)
	t.Setenv("SECRET_BACKEND", "")

	b, err := selectBackend()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := b.(*backend.Keychain); !ok {
		t.Fatalf("got %T, want *backend.Keychain", b)
	}
}

func TestSelectBackend_Darwin_EnvSelectsPasswordsApp(t *testing.T) {
	resetDarwinBackendOverrides(t)
	t.Setenv("SECRET_BACKEND", "passwords-app")

	b, err := selectBackend()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := b.(*backend.PasswordsApp); !ok {
		t.Fatalf("got %T, want *backend.PasswordsApp", b)
	}
}

func TestSelectBackend_Darwin_EnvSelectsKeychainExplicitly(t *testing.T) {
	resetDarwinBackendOverrides(t)
	t.Setenv("SECRET_BACKEND", "keychain")

	b, err := selectBackend()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := b.(*backend.Keychain); !ok {
		t.Fatalf("got %T, want *backend.Keychain", b)
	}
}

func TestSelectBackend_Darwin_UnrecognisedEnvValueErrors(t *testing.T) {
	resetDarwinBackendOverrides(t)
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

func TestSelectBackend_Darwin_FlagWinsOverEnv(t *testing.T) {
	resetDarwinBackendOverrides(t)
	forcePasswordsApp = true
	// A SECRET_BACKEND value that would itself be a hard error is set
	// deliberately: design question 3 says the flag must fully determine
	// the outcome, without even consulting (let alone validating) the env
	// var, so this must not error.
	t.Setenv("SECRET_BACKEND", "typo")

	b, err := selectBackend()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := b.(*backend.PasswordsApp); !ok {
		t.Fatalf("got %T, want *backend.PasswordsApp (flag must win over SECRET_BACKEND)", b)
	}
}

// TestRunGitCredentialHelper_UnrecognisedBackendEnv exercises the exported
// RunGitCredentialHelper (rather than the fake-backend-injected
// runGitCredentialHelper covered elsewhere), confirming git-credential-secret
// honours SECRET_BACKEND (issue #7's design question 5) via the same
// selectBackend() the secret binary uses, and that an invalid value is
// reported on stderr without a non-zero exit — git must still fall through
// to another helper or an interactive prompt rather than see a hard
// failure, per gitcredentials(7) and this file's existing IsAvailable-error
// handling.
func TestRunGitCredentialHelper_UnrecognisedBackendEnv(t *testing.T) {
	resetDarwinBackendOverrides(t)
	t.Setenv("SECRET_BACKEND", "typo")

	var stdout, stderr bytes.Buffer
	code := RunGitCredentialHelper("get", strings.NewReader("protocol=https\nhost=example.com\n\n"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("got exit code %d, want 0", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("expected no stdout output, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "typo") {
		t.Errorf("expected stderr to mention the offending value, got %q", stderr.String())
	}
}

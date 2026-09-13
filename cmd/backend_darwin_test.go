//go:build darwin

package cmd

import (
	"bytes"
	"io"
	"os"
	"runtime"
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

// TestSelectBackend_Darwin_AllOwnNamesAccepted is the intra-platform
// consistency check for "must fix 1" in the PR #63 review: darwinBackendNames
// and resolveBackendName's switch cases are two hand-written lists in the
// same file that must agree, and nothing previously checked that they did.
// This catches the direction that is fully verifiable in a single build: a
// name present in darwinBackendNames (so errUnrecognisedBackend would
// advertise it as valid) but missing, misspelled, or removed from the
// switch (so selectBackend() would actually reject it). It cannot catch the
// reverse — a switch case with no matching slice entry — because that isn't
// harmful in the same way: it means the error message under-advertises a
// name selectBackend() actually accepts, not that it wrongly claims one
// works.
func TestSelectBackend_Darwin_AllOwnNamesAccepted(t *testing.T) {
	for _, name := range darwinBackendNames {
		t.Run(name, func(t *testing.T) {
			resetDarwinBackendOverrides(t)
			t.Setenv("SECRET_BACKEND", name)

			if _, err := selectBackend(); err != nil {
				t.Fatalf("selectBackend() rejected %q, which darwinBackendNames claims is valid on darwin: %v", name, err)
			}
		})
	}
}

// TestSelectBackend_Darwin_UnrecognisedEnvValueNamesThisPlatform closes the
// other test-coverage gap the review flagged alongside "must fix 1": nothing
// asserted that selectBackend()'s call to errUnrecognisedBackend passes its
// own darwinBackendNames slice, rather than some other platform's copy-pasted
// by mistake at the call site. A plain typo (one errUnrecognisedBackend does
// not recognise as valid on any platform) is used here rather than a value
// valid elsewhere, because the ", not <goos>" half of the message only
// appears on the "valid elsewhere" branch — see
// TestSelectBackend_Darwin_ValueValidOnlyOnAnotherPlatform below for that.
func TestSelectBackend_Darwin_UnrecognisedEnvValueNamesThisPlatform(t *testing.T) {
	resetDarwinBackendOverrides(t)
	t.Setenv("SECRET_BACKEND", "typo")

	_, err := selectBackend()
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, strings.Join(darwinBackendNames, ", ")) {
		t.Errorf("error %q does not list darwinBackendNames verbatim — selectBackend() may be threading the wrong names slice into errUnrecognisedBackend", msg)
	}
}

// TestSelectBackend_Darwin_ValueValidOnlyOnAnotherPlatform mirrors
// TestSelectBackend_Windows_ValueValidOnlyOnAnotherPlatform, which was the
// only platform with this end-to-end case before the PR #63 review pointed
// out darwin and linux lacked it. It also covers the ", not <goos>" half of
// the message, which only appears on this "valid elsewhere" branch (see
// errUnrecognisedBackend): comparing against runtime.GOOS, rather than a
// hardcoded "darwin" string, means a call site that accidentally hardcodes
// the wrong GOOS literal — e.g. "linux" pasted into cmd/backend_darwin.go —
// fails this test when it runs on darwin, which is the only platform this
// file builds on.
func TestSelectBackend_Darwin_ValueValidOnlyOnAnotherPlatform(t *testing.T) {
	resetDarwinBackendOverrides(t)
	t.Setenv("SECRET_BACKEND", "secret-service")

	_, err := selectBackend()
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "only available on linux") {
		t.Errorf("error %q does not explain that this name is valid on a different platform", msg)
	}
	if !strings.Contains(msg, ", not "+runtime.GOOS) {
		t.Errorf("error %q does not say \", not %s\" — selectBackend() may be passing the wrong GOOS literal to errUnrecognisedBackend", msg, runtime.GOOS)
	}
}

func TestSelectBackend_Darwin_FlagWinsOverEnv(t *testing.T) {
	resetDarwinBackendOverrides(t)
	forcePasswordsApp = true
	// A SECRET_BACKEND value that would itself be a hard error is set
	// deliberately: design question 3 says the flag must fully determine
	// the *outcome* regardless of the env var, so this must not error (it
	// is, however, still validated and reported on stderr as a warning —
	// see TestSelectBackend_Darwin_FlagStillReportsBadEnvAsWarning below).
	t.Setenv("SECRET_BACKEND", "typo")

	var b backend.Backend
	captureStderr(t, func() {
		var err error
		b, err = selectBackend()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if _, ok := b.(*backend.PasswordsApp); !ok {
		t.Fatalf("got %T, want *backend.PasswordsApp (flag must win over SECRET_BACKEND)", b)
	}
}

// captureStderr redirects os.Stderr for the duration of fn and returns
// everything written to it. validateBackendEnvIgnoredByFlag (called from
// selectBackend when forcePasswordsApp is set) writes straight to
// os.Stderr rather than taking an io.Writer parameter, matching the
// existing pattern in cmd/backend_linux.go's trampolineToWindows — both are
// rare, non-protocol diagnostics with no caller that needs to capture them
// outside a test.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	old := os.Stderr
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = old })

	fn()

	w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("reading captured stderr: %v", err)
	}
	return buf.String()
}

// TestSelectBackend_Darwin_FlagStillReportsBadEnvAsWarning is the "would
// like" item from the PR #63 review: --passwords-app must keep winning
// unconditionally (TestSelectBackend_Darwin_FlagWinsOverEnv above), but a
// SECRET_BACKEND value that would otherwise be a hard error should not go
// completely unreported, or a user relying on --passwords-app (e.g. via a
// shell alias) never learns their environment is broken until
// git-credential-secret — which cannot take the flag — hits the same value
// cold as a hard error instead of a warning.
func TestSelectBackend_Darwin_FlagStillReportsBadEnvAsWarning(t *testing.T) {
	resetDarwinBackendOverrides(t)
	forcePasswordsApp = true
	t.Setenv("SECRET_BACKEND", "typo")

	var b backend.Backend
	stderr := captureStderr(t, func() {
		var err error
		b, err = selectBackend()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	if _, ok := b.(*backend.PasswordsApp); !ok {
		t.Fatalf("got %T, want *backend.PasswordsApp (flag must still win despite the warning)", b)
	}
	if !strings.Contains(stderr, "typo") {
		t.Errorf("expected stderr to warn about the ignored SECRET_BACKEND value, got %q", stderr)
	}
}

// TestSelectBackend_Darwin_FlagSuppressesWarningForValidEnv confirms the
// warning is specific to a value selectBackend would otherwise reject: a
// SECRET_BACKEND value that is simply a different, valid choice than the
// flag's (the ordinary, working precedence case) must stay silent.
func TestSelectBackend_Darwin_FlagSuppressesWarningForValidEnv(t *testing.T) {
	resetDarwinBackendOverrides(t)
	forcePasswordsApp = true
	t.Setenv("SECRET_BACKEND", "keychain")

	stderr := captureStderr(t, func() {
		if _, err := selectBackend(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	if stderr != "" {
		t.Errorf("expected no warning for a validly-named SECRET_BACKEND value, got %q", stderr)
	}
}

// TestSelectBackend_Darwin_FlagPathSilentForAllOwnNames is the mirror of
// TestSelectBackend_Darwin_AllOwnNamesAccepted for the flag-validation path:
// it is the test that would have caught validateBackendEnvIgnoredByFlag
// originally carrying its own hand-written copy of darwinBackendNames'
// cases, a fourth hand-synchronised list this file no longer has now that
// validateBackendEnvIgnoredByFlag calls resolveBackendName instead of
// re-deciding validity itself. Every name darwinBackendNames advertises as
// valid must produce no warning on the --passwords-app path, exactly as it
// produces no error on the plain path.
func TestSelectBackend_Darwin_FlagPathSilentForAllOwnNames(t *testing.T) {
	for _, name := range darwinBackendNames {
		t.Run(name, func(t *testing.T) {
			resetDarwinBackendOverrides(t)
			forcePasswordsApp = true
			t.Setenv("SECRET_BACKEND", name)

			var b backend.Backend
			stderr := captureStderr(t, func() {
				var err error
				b, err = selectBackend()
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			})

			if _, ok := b.(*backend.PasswordsApp); !ok {
				t.Fatalf("got %T, want *backend.PasswordsApp (flag must still win)", b)
			}
			if stderr != "" {
				t.Errorf("selectBackend() warned about %q, which darwinBackendNames claims is valid on darwin: %q", name, stderr)
			}
		})
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
